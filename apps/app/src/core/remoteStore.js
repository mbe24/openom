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

// A thrown HTTP error carrying its `status`, so syncOutcome.classifyError can tell a PERMANENT refusal
// (403 quota/forbidden, 400) from a transient one (5xx/429) — a bare Error("HTTP 403") is
// indistinguishable from offline, which is exactly how a permanent failure used to hide behind an
// infinite silent backoff.
function httpError(label, status, detail = '') {
  const e = new Error(`${label}: HTTP ${status}${detail ? ` — ${detail}` : ''}`);
  e.status = status;
  return e;
}

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
    return `${this.#baseUrl}/v1/trees/${encodeURIComponent(id)}`;
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

  /**
   * Explicit create-tree (OPE-407): POST the tree id to mint its `trees` row (entitlement-gated on
   * `max_trees`) so the caller becomes owner, BEFORE any blob write reaches the server — `put_blob` no
   * longer mints and `404`s on a missing tree. Idempotent for the owner (a returning device re-POSTs and
   * gets `2xx`, not an error); a tree owned by someone else is refused (`403`, surfaced as an httpError so
   * `runTick` can tell a permanent refusal from offline). `id` is the tree UUID (the same id `#tree` routes on).
   */
  async createTree(id) {
    const res = await this.#send(this.#tree(id), { method: 'POST' });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw httpError(`createTree ${id}`, res.status, detail);
    }
  }

  async readSnapshot(id) {
    const res = await this.#send(this.#tree(id), { method: 'GET' });
    if (res.status === 404) return null;
    if (!res.ok) throw httpError(`readSnapshot ${id}`, res.status);
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
      throw httpError(`putSnapshot ${id}`, res.status, detail);
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
      throw httpError(`appendLog ${id}`, res.status, detail);
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
    if (!res.ok) throw httpError(`readLog ${id}`, res.status);
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

  // ---- data blob surface (the OPE-397 BlobStore-over-HTTP; the managed server is OPE-398) ----
  //
  // The data channel is a content-addressable blob store keyed by the core's OPAQUE object keys —
  // `{treeKey}/log/{replica}/{counter}` (immutable) | `{treeKey}/heads/{replica}` | `{treeKey}/snapshot`
  // (pointers). The tree (for routing + authz) is the key's leading segment; the rest is the object path.

  #blobUrl(key) {
    const slash = key.indexOf('/');
    const tree = key.slice(0, slash);
    const sub = key.slice(slash + 1).split('/').map(encodeURIComponent).join('/');
    return `${this.#tree(tree)}/blobs/${sub}`;
  }

  /** The keys under `prefix` (a `{treeKey}/` prefix) as `[{ key, etag }]`, re-prefixed to the caller's namespace. */
  async blobList(prefix) {
    const slash = prefix.indexOf('/');
    const tree = slash === -1 ? prefix : prefix.slice(0, slash);
    // Forward the sub-prefix (everything after `{tree}/`) as `?prefix=` so the server scopes the LIST
    // itself (OPE-398 §2/§5.1) — additive and backward-compatible: an empty sub-prefix (bare `{tree}/` or
    // no prefix at all) omits the query param, which is today's whole-tree behavior unchanged.
    const sub = slash === -1 ? '' : prefix.slice(slash + 1).replace(/\/$/, '');
    const qs = sub ? `?prefix=${encodeURIComponent(sub)}` : '';
    const res = await this.#send(`${this.#tree(tree)}/blobs${qs}`, { method: 'GET' });
    if (res.status === 404) return [];
    if (!res.ok) throw httpError(`blobList ${tree}`, res.status);
    const j = await res.json();
    return (j.keys ?? []).map((k) => ({ key: `${tree}/${k.key}`, etag: k.etag }));
  }

  /** Fetch one object's bytes, or `null` if absent. */
  async blobGet(key) {
    const res = await this.#send(this.#blobUrl(key), { method: 'GET' });
    if (res.status === 404) return null;
    if (!res.ok) throw httpError(`blobGet ${key}`, res.status);
    return new Uint8Array(await res.arrayBuffer());
  }

  /** Write one object. A `pointer` overwrites; an immutable object writes `If-None-Match: *` (a 412 = the
   *  object already exists → idempotent success, since immutable objects are content-stable). `covered` (the
   *  snapshot PUT only) is the SUBSUMED covered frontier as a JSON `{replica:counter}` string — sent base64 as
   *  the mandatory `x-openom-covered` header so the server's GC gate 1 can trust + etag-bind it (OPE-409). */
  async blobPut(key, bytes, pointer, covered) {
    const extraHeaders = { 'content-type': 'application/octet-stream', ...(pointer ? {} : { 'if-none-match': '*' }) };
    if (covered) extraHeaders['x-openom-covered'] = btoa(covered); // ASCII JSON (hex keys + numbers) → btoa is safe
    const res = await this.#send(this.#blobUrl(key), { method: 'PUT', extraHeaders, body: bytes });
    if (res.status === 412) return; // immutable object already present — idempotent
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw httpError(`blobPut ${key}`, res.status, detail);
    }
  }

  /**
   * Report this member's own PULL frontier — `{replica: counter}`, how far it has fetched each replica's log.
   * Advisory gate-2 liveness telemetry for the server's log-GC floor: the server pins reclamation down to the
   * slowest in-window member so an un-pulled tail is never reaped from under a member (OPE-409 gate 2). `id`
   * is the tree UUID (the same id `#tree` routes on); rows are keyed by `(member, replica)` from the auth
   * identity. PUT /v1/trees/{id}/frontier. A failure is non-fatal to sync — the worker swallows it.
   */
  async putFrontier(id, frontier) {
    const res = await this.#send(`${this.#tree(id)}/frontier`, {
      method: 'PUT',
      extraHeaders: { 'content-type': 'application/json' },
      body: JSON.stringify({ frontier }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw httpError(`putFrontier ${id}`, res.status, detail);
    }
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
    if (!res.ok) throw httpError(`readKeyring ${id}`, res.status);
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
      throw httpError(`putKeyring ${id}`, res.status, detail);
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
    if (!res.ok) throw httpError(`getAccess ${id}`, res.status);
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
      throw httpError(`putAccess ${id}`, res.status, detail);
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
