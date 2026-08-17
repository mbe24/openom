// RemoteStore: the DocStore contract (see store.js) over HTTP to the openom server.
// It moves OPAQUE bytes — it knows nothing about encryption (that's SealedStore, one
// layer up) and nothing about offline queueing (that's SyncStore). V1 is snapshot-only:
// readSnapshot / putSnapshot map onto GET / PUT /trees/{id} with the server's
// ETag / If-Match compare-and-swap; the delta-log methods are V2 and report so.
//
// The local DocStore version token ('v'+counter) and the server's ETag (a random UUID
// per write) are DIFFERENT namespaces — this store's `version` is always the server
// ETag. SyncStore owns the mapping between the two.

import { ConflictError } from './store.js';

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
  #token;

  /**
   * @param {object} opts
   * @param {string} opts.baseUrl   e.g. "http://localhost:6060"
   * @param {typeof fetch} [opts.fetch]  injectable for tests
   * @param {string|null} [opts.token]   Supabase JWT (prod); omit locally (fake auth)
   */
  constructor({ baseUrl, fetch = globalThis.fetch, token = null }) {
    if (!baseUrl) throw new Error('RemoteStore needs a baseUrl');
    this.#baseUrl = baseUrl.replace(/\/$/, '');
    this.#fetch = fetch;
    this.#token = token;
  }

  caps() {
    return { remote: true, conditionalWrites: true, durable: true };
  }

  #headers(extra = {}) {
    const h = { ...extra };
    if (this.#token) h.authorization = `Bearer ${this.#token}`;
    return h;
  }

  #tree(id) {
    return `${this.#baseUrl}/trees/${encodeURIComponent(id)}`;
  }

  async readSnapshot(id) {
    const res = await this.#fetch(this.#tree(id), { headers: this.#headers() });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`readSnapshot ${id}: HTTP ${res.status}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    return { bytes, version: unquote(res.headers.get('etag')) };
  }

  // `expected` is the server ETag the edit was based on (null → create, must not exist).
  // A 409 means someone else advanced the snapshot: surface it as ConflictError so the
  // caller pulls + reapplies, distinct from a network error (retry with the same body).
  async putSnapshot(id, bytes, expected = null) {
    const headers = this.#headers({ 'content-type': 'application/octet-stream' });
    if (expected != null) headers['if-match'] = expected; // server trims any quotes
    const res = await this.#fetch(this.#tree(id), { method: 'PUT', headers, body: bytes });
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
    const res = await this.#fetch(`${this.#tree(id)}/log`, {
      method: 'POST',
      headers: this.#headers({ 'content-type': 'application/octet-stream' }),
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
    const res = await this.#fetch(`${this.#tree(id)}/log?since=${since}`, { headers: this.#headers() });
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
    const res = await this.#fetch(`${this.#tree(id)}/keyring?from=${from}`, { headers: this.#headers() });
    if (res.status === 404) return { revisions: [], head: 0 };
    if (!res.ok) throw new Error(`readKeyring ${id}: HTTP ${res.status}`);
    const body = await res.json();
    return {
      revisions: (body.revisions ?? []).map((r) => ({ revision: r.revision, bytes: b64decode(r.payload) })),
      head: body.head ?? 0,
    };
  }

  async list() {
    throw new Error('remote list is not supported');
  }
  async delete() {
    throw new Error('remote tree delete is not supported yet');
  }
}
