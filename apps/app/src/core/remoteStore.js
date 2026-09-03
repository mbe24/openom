// RemoteStore: the DocStore contract (see store.js) over HTTP to the openom server.
// It moves OPAQUE bytes — it knows nothing about encryption (that's SealedStore, one
// layer up) and nothing about offline queueing (that's SyncStore). V1 is snapshot-only:
// readSnapshot / putSnapshot map onto GET / PUT /trees/{id} with the server's
// ETag / If-Match compare-and-swap; the delta-log methods are V2 and report so.
//
// The local DocStore version token ('v'+counter) and the server's ETag (a random UUID
// per write) are DIFFERENT namespaces — this store's `version` is always the server
// ETag. SyncStore owns the mapping between the two.

import { ConflictError, AuthError } from './store.js';

const unquote = (etag) => (etag ? etag.replace(/^"|"$/g, '') : null);
const b64decode = (s) => (s ? Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) : new Uint8Array(0));

/**
 * The requested log tail is below the server's retained window (HTTP 410): the client can't catch up
 * from deltas and must bootstrap from a snapshot. Carries the retained bounds so the caller can decide.
 */
export class BootstrapRequiredError extends Error {
  constructor(oldestRetainedSeq, headSeq) {
    super('log tail no longer retained — bootstrap from a snapshot');
    this.name = 'BootstrapRequiredError';
    this.oldestRetainedSeq = oldestRetainedSeq;
    this.headSeq = headSeq;
  }
}

export class RemoteStore {
  #baseUrl;
  #fetch;
  #getAccessToken;

  /**
   * @param {object} opts
   * @param {string} opts.baseUrl   e.g. "http://localhost:6060"
   * @param {typeof fetch} [opts.fetch]  injectable for tests
   * @param {object|Function|null} [opts.auth]  the AuthSession seam (an object with
   *   `getAccessToken({forceRefresh})`) or a bare `getAccessToken` fn. Omit → no bearer (a
   *   server running fake-auth). The token is fetched PER REQUEST (never captured at
   *   construction) so the long-lived publishKeyring / summary closures that hold this store
   *   keep working across token expiry — caching + refresh live BEHIND the seam.
   */
  constructor({ baseUrl, fetch = globalThis.fetch, auth = null }) {
    if (!baseUrl) throw new Error('RemoteStore needs a baseUrl');
    this.#baseUrl = baseUrl.replace(/\/$/, '');
    this.#fetch = fetch;
    // Normalize the seam to a `getAccessToken(opts) => Promise<string>` (or null for no-auth).
    if (typeof auth === 'function') this.#getAccessToken = auth;
    else if (auth && typeof auth.getAccessToken === 'function') this.#getAccessToken = (o) => auth.getAccessToken(o);
    else this.#getAccessToken = null;
  }

  caps() {
    return { remote: true, conditionalWrites: true, durable: true };
  }

  async #headers(extra = {}, { forceRefresh = false } = {}) {
    const h = { ...extra };
    if (this.#getAccessToken) {
      const token = await this.#getAccessToken({ forceRefresh });
      if (token) h.authorization = `Bearer ${token}`;
    }
    return h;
  }

  #tree(id) {
    return `${this.#baseUrl}/trees/${encodeURIComponent(id)}`;
  }

  // Every request routes through here so auth is applied uniformly and a 401 gets EXACTLY ONE
  // forced-refresh retry (the token may just be stale). If the retry still 401s, surface an
  // AuthError so the composition root re-gates / signs out. Never loops. Non-401 statuses are
  // handed back untouched for each method to interpret (404/409/410/etc.).
  async #send(url, { method, extraHeaders = {}, body } = {}) {
    const attempt = async (forceRefresh) => {
      const headers = await this.#headers(extraHeaders, { forceRefresh });
      return this.#fetch(url, { method, headers, body });
    };
    let res = await attempt(false);
    if (res.status === 401) {
      if (this.#getAccessToken) res = await attempt(true); // one forced-refresh retry
      if (res.status === 401) {
        let detail = '';
        try { detail = (await res.text?.()) ?? ''; } catch { detail = ''; }
        throw new AuthError(detail);
      }
    }
    return res;
  }

  async readSnapshot(id) {
    const res = await this.#send(this.#tree(id), { method: 'GET' });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`readSnapshot ${id}: HTTP ${res.status}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    return { bytes, version: unquote(res.headers.get('etag')) };
  }

  // `expected` is the server ETag the edit was based on (null → create, must not exist).
  // A 409 means someone else advanced the snapshot: surface it as ConflictError so the
  // caller pulls + reapplies, distinct from a network error (retry with the same body).
  async putSnapshot(id, bytes, expected = null) {
    const extraHeaders = { 'content-type': 'application/octet-stream' };
    if (expected != null) extraHeaders['if-match'] = expected; // server trims any quotes
    const res = await this.#send(this.#tree(id), { method: 'PUT', extraHeaders, body: bytes });
    if (res.status === 409) throw new ConflictError(expected, null);
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`putSnapshot ${id}: HTTP ${res.status}${detail ? ` — ${detail}` : ''}`);
    }
    return unquote(res.headers.get('etag'));
  }

  // ---- delta-log surface (POST/GET /trees/{id}/log) ----

  /** Append one sealed delta envelope; returns its server-assigned `seq` (idempotent on the dot). */
  async appendLog(id, sealedDelta) {
    const res = await this.#send(`${this.#tree(id)}/log`, {
      method: 'POST',
      extraHeaders: { 'content-type': 'application/octet-stream' },
      body: sealedDelta,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`appendLog ${id}: HTTP ${res.status}${detail ? ` — ${detail}` : ''}`);
    }
    return (await res.json()).seq;
  }

  /**
   * The ordered tail after `since` (default from the start). Returns `{ entries, nextCursor,
   * oldestRetainedSeq, headSeq }`; each entry is `{ seq, member, replica, counter, time, payload }`
   * with `payload` the sealed delta bytes. Throws BootstrapRequiredError on a 410 (cursor below the
   * retained window).
   */
  async readLog(id, since = -1) {
    const res = await this.#send(`${this.#tree(id)}/log?since=${since}`, { method: 'GET' });
    if (res.status === 404) return { entries: [], nextCursor: since, oldestRetainedSeq: 0, headSeq: -1 };
    if (res.status === 410) {
      const j = await res.json().catch(() => ({}));
      throw new BootstrapRequiredError(j.oldest_retained_seq ?? 0, j.head_seq ?? -1);
    }
    if (!res.ok) throw new Error(`readLog ${id}: HTTP ${res.status}`);
    const tail = await res.json();
    return {
      entries: (tail.entries ?? []).map((e) => ({
        seq: e.seq,
        member: e.member ?? null,
        replica: e.replica,
        counter: e.counter,
        time: e.time ?? null,
        payload: b64decode(e.payload),
      })),
      nextCursor: tail.next_cursor,
      oldestRetainedSeq: tail.oldest_retained_seq,
      headSeq: tail.head_seq,
    };
  }

  /**
   * The change-history / activity feed: log metadata (who/when/where in the sequence) without paying
   * for the payload bytes. Same endpoint; the caller ignores `payload`. (A payload-free server mode is
   * a later optimization.)
   */
  async activity(id, since = -1) {
    const { entries, nextCursor, headSeq } = await this.readLog(id, since);
    return {
      changes: entries.map(({ seq, member, replica, counter, time }) => ({ seq, member, replica, counter, time })),
      nextCursor,
      headSeq,
    };
  }

  // ---- keyring surface (GET /trees/{id}/keyring) ----

  /**
   * The keyring revision chain from `from` (inclusive) to head, for the client to verify + adopt via
   * the sealer's `acceptRemoteKeyring` and RETAIN per revision. Returns `{ revisions, head }` where
   * `revisions` is `[{ revision, bytes }]` ascending (bytes = the opaque signed keyring). A 404 (no
   * keyring yet) → empty.
   */
  async readKeyring(id, from = 1) {
    const res = await this.#send(`${this.#tree(id)}/keyring?from=${from}`, { method: 'GET' });
    if (res.status === 404) return { revisions: [], head: 0 };
    if (!res.ok) throw new Error(`readKeyring ${id}: HTTP ${res.status}`);
    const body = await res.json();
    return {
      revisions: (body.revisions ?? []).map((r) => ({ revision: r.revision, bytes: b64decode(r.payload) })),
      head: body.head ?? 0,
    };
  }

  /**
   * Publish a produced keyring revision so peers can pull + verify it. `updateBytes` is the RAW
   * `KeyringUpdate` protobuf (from the vault's `wrapChainKeyringUpdate`) — sent as opaque binary; the
   * server `KeyringUpdate::decode`s it, dispatches to the engine verifier, and admits. The server keys
   * storage on the VERIFIED position, so this needs no CAS token: a stale/forked candidate is rejected as
   * a 409 (ConflictError → the caller pulls the newer head, re-produces, retries). Returns the server's
   * accepted `{ revision }`.
   */
  async putKeyring(id, updateBytes) {
    const res = await this.#send(`${this.#tree(id)}/keyring`, {
      method: 'PUT',
      extraHeaders: { 'content-type': 'application/octet-stream' },
      body: updateBytes,
    });
    if (res.status === 409) throw new ConflictError(null, null);
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`putKeyring ${id}: HTTP ${res.status}${detail ? ` — ${detail}` : ''}`);
    }
    const b = await res.json().catch(() => ({}));
    return { revision: b.revision ?? null };
  }

  // ---- advisory membership summary surface (GET/PUT /trees/{id}/access) ----

  /**
   * The current advisory member list + the summary's CAS `generation` and opaque `basis` (the client's
   * keyring frontier). 404 (no tree) → null. Returns `{ members: [{memberId, role}], generation, basis }`
   * where `generation` is `null` (and `basis` empty) for a tree whose ACL was derived in-tx by the chain
   * keyring PUT and never summary-pushed.
   */
  async getAccess(id) {
    const res = await this.#send(`${this.#tree(id)}/access`, { method: 'GET' });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`getAccess ${id}: HTTP ${res.status}`);
    const b = await res.json();
    return {
      members: (b.members ?? []).map((m) => ({ memberId: m.member_id, role: m.role })),
      generation: b.generation ?? null,
      basis: b.basis ?? [],
    };
  }

  /**
   * Push a client-asserted advisory membership summary (OPE-278): the resolved `{memberId, role}` view +
   * the engine-opaque `basis` frontier, CAS'd on `expectedGeneration` (from a prior getAccess; null = expect
   * no summary yet). Throws ConflictError on 409 (stale generation — re-GET + retry). Returns
   * `{ generation, unchanged }` (`unchanged` = an identical re-assert the server did not bump).
   */
  async putAccess(id, { basis, expectedGeneration = null, members }) {
    const body = {
      basis,
      expected_generation: expectedGeneration,
      members: members.map((m) => ({ member_id: m.memberId, role: m.role })),
    };
    const res = await this.#send(`${this.#tree(id)}/access`, {
      method: 'PUT',
      extraHeaders: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 409) throw new ConflictError(expectedGeneration, null);
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`putAccess ${id}: HTTP ${res.status}${detail ? ` — ${detail}` : ''}`);
    }
    const b = await res.json();
    return { generation: b.generation ?? null, unchanged: !!b.unchanged };
  }

  async list() {
    throw new Error('remote list is not supported');
  }
  async delete() {
    throw new Error('remote tree delete is not supported yet');
  }
}
