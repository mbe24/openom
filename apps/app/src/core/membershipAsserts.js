// Durable pending-assert record for the advisory membership summary (OPE-296).
//
// The membership summary a device asserts to the server (PUT /trees/{id}/access) is DERIVED from the
// verified head keyring, which is itself durably persisted (keyringStore). So the real crash-safety comes
// for free: after any keyring change, the sync tick recomputes {view, basis} from the durable keyring and
// re-asserts it (idempotent — the server's unchanged-check doesn't bump the generation). This store adds the
// two things a pure recompute can't give:
//   - "persist the intent BEFORE the network call" — `mark()` writes the desired {view, basis} durably so a
//     crash strictly between the keyring write and the push still has a recorded intent to flush on restart.
//   - de-dup — `confirmed` is the last view the server acknowledged, so the reconciler skips the GET+PUT when
//     nothing changed (the common steady-state tick), instead of re-asserting every tick.
//
// Client-only, advisory (never the security boundary). Same localStorage-or-memory shim as watermarks.js so
// it degrades to in-memory in Node/tests/private-mode.

const PREFIX = 'openom.ma.';

function defaultStore() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem('__ma_probe__');
      return localStorage;
    }
  } catch {
    /* fall through to memory */
  }
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, v),
  };
}

// Order-independent equality of two summaries: members sorted by id, roles compared, basis compared. `null`
// only equals `null`. Used both to de-dup vs the confirmed view and to compare desired/confirmed.
export function sameSummary(a, b) {
  if (a == null || b == null) return a === b;
  const canon = (s) => JSON.stringify({
    view: [...(s.view ?? [])]
      .map((m) => ({ memberId: m.memberId, role: m.role }))
      .sort((x, y) => (x.memberId < y.memberId ? -1 : x.memberId > y.memberId ? 1 : 0)),
    basis: [...(s.basis ?? [])],
  });
  return canon(a) === canon(b);
}

export class MembershipAsserts {
  #store;

  constructor(store = defaultStore()) {
    this.#store = store;
  }

  #load(treeId) {
    try {
      const raw = this.#store.getItem(PREFIX + treeId);
      if (raw) return JSON.parse(raw);
    } catch {
      /* corrupt/absent → nothing pending */
    }
    return { desired: null, confirmed: null };
  }

  #save(treeId, rec) {
    try {
      this.#store.setItem(PREFIX + treeId, JSON.stringify(rec));
    } catch {
      /* ephemeral — best effort */
    }
  }

  /** Record the intent to assert `current` = {view, basis} — persisted BEFORE the network push. */
  mark(treeId, current) {
    const rec = this.#load(treeId);
    this.#save(treeId, { desired: current, confirmed: rec.confirmed });
  }

  /** Record that the server acknowledged `pushed` = {view, basis} (advances the de-dup baseline). */
  confirm(treeId, pushed) {
    const rec = this.#load(treeId);
    this.#save(treeId, { desired: rec.desired, confirmed: pushed });
  }

  /** True when `current` already matches what the server last acknowledged — nothing to push. */
  isConfirmed(treeId, current) {
    return sameSummary(this.#load(treeId).confirmed, current);
  }

  /** The last recorded desired intent (for a startup flush when the keyring can't be recomputed), or null. */
  desired(treeId) {
    return this.#load(treeId).desired;
  }
}
