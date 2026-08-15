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

  // Delta-log surface — V2 (the server is snapshot-only in V1).
  async readUpdates(_id, _since) {
    return { updates: [], cursor: 0 };
  }
  async append() {
    throw new Error('remote delta append is a V2 feature (server is snapshot-only in V1)');
  }
  async list() {
    throw new Error('remote list is not supported');
  }
  async delete() {
    throw new Error('remote tree delete is not supported yet');
  }
}
