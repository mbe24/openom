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
import { makeError, isAppError } from './errorModel.js';
import { ERROR_CODES } from './errorCodes.generated.js';

const unquote = (etag) => (etag ? etag.replace(/^"|"$/g, '') : null);
const b64decode = (s) => (s ? Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) : new Uint8Array(0));

// Per-request deadline: a hung Lambda cold-start / half-open socket must fail, not hang the sync driver
// forever (design C2). #send aborts the fetch after this; the abort surfaces as the `timeout` code.
const REQUEST_TIMEOUT_MS = 20_000;

// A thrown HTTP error carrying its `status`, so callers (the sync driver's retry/backoff classification) can
// tell a permanent refusal from a transient one. The NEW blob channel (below) throws AppErrors instead.
function httpError(label, status, detail = '') {
  const e = new Error(`${label}: HTTP ${status}${detail ? ` — ${detail}` : ''}`);
  e.status = status;
  return e;
}

// ---- blob-channel error normalization (OPE-418 client adapter) ----
// The data channel crosses the Comlink worker↔main boundary, so its failures must be PLAIN AppErrors
// (a custom Error subclass loses its props in transit). Parse the server's RFC 9457 body into a code; a
// bodyless/infra failure synthesizes one from the status or the network condition.

/** An HTTP error RESPONSE (`!res.ok`) → AppError, reading the 9457 `code`/`args`/`detail` when present. */
async function httpAppError(res) {
  let body = null;
  try { body = await res.json(); } catch { /* not a JSON/problem+json body (infra error) */ }
  const retryAfter = Number(res.headers.get('retry-after')) || undefined;
  const code = body?.code;
  if (code && Object.prototype.hasOwnProperty.call(ERROR_CODES, code)) {
    return makeError(code, { args: body.args, retryAfter, httpStatus: res.status, cause: body.detail });
  }
  return makeError(statusFallbackCode(res.status), { retryAfter, httpStatus: res.status });
}

/** A fetch REJECTION (network throw / timeout / a bubbled AuthError) → AppError. */
function netAppError(e) {
  if (isAppError(e)) return e; // already normalized
  if (e instanceof AuthError) return makeError('auth_required', { httpStatus: 401 });
  if (e?.name === 'AbortError' || e?.name === 'TimeoutError') return makeError('timeout', { cause: 'request timed out' });
  const offline = typeof navigator !== 'undefined' && navigator.onLine === false;
  return makeError(offline ? 'offline' : 'request_failed', { cause: String(e?.message ?? e) });
}

/** A code for a status with no usable 9457 body (an infra 5xx, a gateway error, etc.). */
function statusFallbackCode(status) {
  if (status === 401) return 'auth_required';
  if (status === 403) return 'access_denied';
  if (status === 404) return 'not_found';
  if (status === 409) return 'version_conflict';
  if (status === 410) return 'below_gc_floor';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'unavailable';
  return 'invalid_request';
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
      // Per-request deadline (C2): abort the fetch if it hasn't resolved in time, so a hung backend surfaces
      // as an error (blob channel → the `timeout` code) instead of hanging the driver. The abort reason is a
      // TimeoutError; the only abort source on this path is this timer, so netAppError reads any abort as a timeout.
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(new DOMException('request timed out', 'TimeoutError')), REQUEST_TIMEOUT_MS);
      try {
        return await this.#fetch(url, { method, headers, body, signal: ctl.signal });
      } finally {
        clearTimeout(timer);
      }
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
    let res;
    try {
      res = await this.#send(this.#tree(id), { method: 'POST' });
    } catch (e) {
      throw netAppError(e);
    }
    if (!res.ok) throw await httpAppError(res);
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
    let res;
    try {
      res = await this.#send(`${this.#tree(tree)}/blobs${qs}`, { method: 'GET' });
    } catch (e) {
      throw netAppError(e);
    }
    if (res.status === 404) return [];
    if (!res.ok) throw await httpAppError(res);
    const j = await res.json();
    return (j.keys ?? []).map((k) => ({ key: `${tree}/${k.key}`, etag: k.etag }));
  }

  /** Fetch one object's bytes, or `null` if absent. */
  async blobGet(key) {
    let res;
    try {
      res = await this.#send(this.#blobUrl(key), { method: 'GET' });
    } catch (e) {
      throw netAppError(e);
    }
    if (res.status === 404) return null;
    if (!res.ok) throw await httpAppError(res);
    return new Uint8Array(await res.arrayBuffer());
  }

  /** Write one object. A `pointer` overwrites; an immutable object writes `If-None-Match: *` (a 412 = the
   *  object already exists → idempotent success, since immutable objects are content-stable). `covered` (the
   *  snapshot PUT only) is the SUBSUMED covered frontier as a JSON `{replica:counter}` string — sent base64 as
   *  the mandatory `x-openom-covered` header so the server's GC gate 1 can trust + etag-bind it (OPE-409). */
  async blobPut(key, bytes, pointer, covered) {
    const extraHeaders = { 'content-type': 'application/octet-stream', ...(pointer ? {} : { 'if-none-match': '*' }) };
    if (covered) extraHeaders['x-openom-covered'] = btoa(covered); // ASCII JSON (hex keys + numbers) → btoa is safe
    let res;
    try {
      res = await this.#send(this.#blobUrl(key), { method: 'PUT', extraHeaders, body: bytes });
    } catch (e) {
      throw netAppError(e);
    }
    if (res.status === 412) return; // immutable object already present — idempotent
    if (!res.ok) throw await httpAppError(res);
  }

  /**
   * Report this member's own PULL frontier — `{replica: counter}`, how far it has fetched each replica's log.
   * Advisory gate-2 liveness telemetry for the server's log-GC floor: the server pins reclamation down to the
   * slowest in-window member so an un-pulled tail is never reaped from under a member (OPE-409 gate 2). `id`
   * is the tree UUID (the same id `#tree` routes on); rows are keyed by `(member, replica)` from the auth
   * identity. PUT /v1/trees/{id}/frontier. A failure is non-fatal to sync — the worker swallows it.
   */
  async putFrontier(id, frontier) {
    let res;
    try {
      res = await this.#send(`${this.#tree(id)}/frontier`, {
        method: 'PUT',
        extraHeaders: { 'content-type': 'application/json' },
        body: JSON.stringify({ frontier }),
      });
    } catch (e) {
      throw netAppError(e);
    }
    if (!res.ok) throw await httpAppError(res);
  }

  // ---- keyring surface (GET /trees/{id}/keyring) ----

  /**
   * The keyring revision chain from `from` (inclusive) to head, for the client to verify + adopt via
   * the sealer's `acceptRemoteKeyring` and RETAIN per revision. Returns `{ revisions, head }` where
   * `revisions` is `[{ revision, bytes }]` ascending (bytes = the opaque signed keyring). A 404 (no
   * keyring yet) → empty.
   */
  async readKeyring(id, from = 1) {
    let res;
    try {
      res = await this.#send(`${this.#tree(id)}/keyring?from=${from}`, { method: 'GET' });
    } catch (e) {
      throw netAppError(e);
    }
    if (res.status === 404) return { revisions: [], head: 0 };
    if (!res.ok) throw await httpAppError(res);
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
    let res;
    try {
      res = await this.#send(`${this.#tree(id)}/keyring`, {
        method: 'PUT',
        extraHeaders: { 'content-type': 'application/octet-stream' },
        body: updateBytes,
      });
    } catch (e) {
      throw netAppError(e);
    }
    // A 409 stays a ConflictError — it is INTERNAL retry control-flow (the caller pulls the newer head +
    // re-produces), not a user-facing error; sharing.js branches on its `.name`. Everything else is an
    // AppError so an offline/5xx/timeout keyring publish surfaces properly through the driver.
    if (res.status === 409) throw new ConflictError(null, null);
    if (!res.ok) throw await httpAppError(res);
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
    let res;
    try {
      res = await this.#send(`${this.#tree(id)}/access`, { method: 'GET' });
    } catch (e) {
      throw netAppError(e);
    }
    if (res.status === 404) return null;
    if (!res.ok) throw await httpAppError(res);
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
    let res;
    try {
      res = await this.#send(`${this.#tree(id)}/access`, {
        method: 'PUT',
        extraHeaders: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw netAppError(e);
    }
    // 409 stays a ConflictError — stale-generation retry control-flow (membershipSummary branches on
    // `.name`); other failures are AppErrors for the display path.
    if (res.status === 409) throw new ConflictError(expectedGeneration, null);
    if (!res.ok) throw await httpAppError(res);
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
