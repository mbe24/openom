// SyncController — drives delta-log sync between a local FamilyTree and the server's log. Delta sync is
// simple because deltas are self-contained, commutative, and idempotent: appends never conflict (the
// server's replica dot dedupes re-delivery), and a pull just merges — no CAS/merge-resolution loop like
// snapshots need. This is the client half of the B1 delta-log.
//
// Wiring (all functions exposed, even where no UI consumes them yet):
//   * push()       — seal each locally-produced delta as KIND_DELTA and append it to the remote log.
//   * pull()       — read the remote tail since our cursor, unseal, and merge each into the tree.
//   * adopt()      — reconcile our base with the server snapshot: adopt a base that subsumes more of the
//                    log than our cursor (verify + merge + jump the cursor past the subsumed prefix).
//   * sync()       — one tick: push then pull.
//   * activity()   — the change-history / activity feed (log metadata), for a future activity UI.
//
// The controller captures local deltas via tree.onDelta into an in-memory outbox and seals+pushes them;
// remote deltas are merged via tree.mergeRemote (which never re-emits, so they aren't pushed back).
//
// KNOWN FOLLOW-UPS: the outbox is in-memory, so deltas edited offline and not pushed before a reload are
// re-derived from the local log later, not from here (durable outbox = a later slice); and pull re-merges
// our own just-pushed deltas (idempotent, harmless) unless a replicaKey is provided to skip them.

function memPersist() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v) };
}

function defaultPersist() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem('__synccur_probe__');
      return localStorage;
    }
  } catch {
    /* fall through */
  }
  return memPersist();
}

export class SyncController {
  #tree;
  #remote;
  #docId;
  #seal;
  #open;
  #persist;
  #replicaKey;
  #verify;
  #attribution;
  #outbox = [];
  #pulledCursor;
  #unsub;

  /**
   * @param {object} o
   * @param {object} o.tree        a FamilyTree (onDelta / mergeRemote / snapshotBytes)
   * @param {object} o.remote      a RemoteStore (appendLog / readLog / readSnapshot / activity)
   * @param {string} o.docId
   * @param {(raw: Uint8Array) => Promise<Uint8Array>|Uint8Array} o.seal   raw delta → sealed KIND_DELTA bytes
   * @param {(sealed: Uint8Array) => Promise<Uint8Array>|Uint8Array} o.open sealed bytes → raw delta
   * @param {object} [o.persist]   durable KV for the pull cursor (defaults to localStorage/in-memory)
   * @param {string|null} [o.replicaKey]  our own base64 replica id, to skip our echoes on pull
   * @param {(sealed: Uint8Array, plaintext: Uint8Array) => Promise<void>} [o.verify]  landed-entry author
   *        verification (§B3 launch gate): throws to REJECT an entry (unauthorized author / wrong role /
   *        bad signature at its governing keyring revision). Omit for unattributed (V1 single-owner) trees
   *        — the app injects one that syncs the keyring, then calls the sealer's verifyEntry per attributed
   *        epoch. A rejected entry is dropped (not merged) and reported; the rest still merge (the engine
   *        is order-insensitive), so one bad entry can't stall the log.
   */
  constructor({ tree, remote, docId, seal, open, persist, replicaKey = null, verify = null, attribution = null }) {
    this.#tree = tree;
    this.#remote = remote;
    this.#docId = docId;
    this.#seal = seal;
    this.#open = open;
    this.#persist = persist ?? defaultPersist();
    this.#replicaKey = replicaKey;
    this.#verify = verify;
    // Reads an entry's AAD-bound header WITHOUT decrypting — { keyringRevision, keyId, coversThroughSeq }.
    // Used to read a base snapshot's coverage (adopt) and to tell a malformed entry from a merely-
    // undecryptable one (pull's open guard). Omitted ⇒ no coverage-driven adoption (V1).
    this.#attribution = attribution;
    this.#pulledCursor = this.#loadCursor();
    this.#unsub = tree.onDelta((raw) => this.#outbox.push(raw));
  }

  /** Seal and append every queued local delta to the remote log (in order). Idempotent server-side. */
  async push() {
    let pushed = 0;
    while (this.#outbox.length) {
      const raw = this.#outbox[0];
      const sealed = await this.#seal(raw);
      await this.#remote.appendLog(this.#docId, sealed);
      this.#outbox.shift(); // only after the append lands, so a failure retries the same delta
      pushed += 1;
    }
    return { pushed };
  }

  /**
   * Pull the remote tail after our cursor, VERIFY each entry's author attribution (§B3), and merge the
   * ones that pass. A GENUINELY-rejected entry (bad signature / wrong role) is dropped (never merged) and
   * returned in `rejected`; the rest still merge (order-insensitive), so a single unauthorized entry from a
   * hostile server can't stall or poison the log. A TRANSIENT rejection (`err.retryable` — the governing
   * keyring revision isn't retained yet) instead HOLDS: the pull stops at that entry with the cursor
   * un-advanced and returns its seq as `held`, so a later tick (after a keyring sync) re-verifies it rather
   * than losing it. Own echoes (replicaKey) are skipped without verifying.
   */
  async pull() {
    const tail = await this.#remote.readLog(this.#docId, this.#pulledCursor);
    let merged = 0;
    const rejected = [];
    let held = null;
    for (const e of tail.entries) {
      // Our own echo — nothing to verify or merge, but safe to advance past.
      if (this.#replicaKey && e.replica === this.#replicaKey) {
        this.#pulledCursor = e.seq;
        continue;
      }
      let plain;
      try {
        plain = await this.#open(e.payload);
      } catch (err) {
        // Guard the open so one bad entry can't throw out of the whole pull. A STRUCTURALLY-malformed entry
        // (bad envelope/header) can never be merged → drop it and advance. A WELL-FORMED but currently-
        // undecryptable entry (an epoch we can't reach yet — e.g. a rotation we haven't re-unlocked through)
        // is VALID → HOLD and retry, never drop. The header decoding is the discriminator.
        let wellFormed = false;
        try {
          if (this.#attribution) {
            await this.#attribution(e.payload);
            wellFormed = true;
          }
        } catch {
          /* header itself won't decode → malformed */
        }
        if (wellFormed) {
          held = e.seq;
          break;
        }
        rejected.push({ seq: e.seq, member: e.member ?? null, reason: `unopenable: ${String(err?.message ?? err)}` });
        this.#pulledCursor = e.seq;
        continue;
      }
      if (this.#verify) {
        try {
          await this.#verify(e.payload, plain);
        } catch (err) {
          // A TRANSIENT failure (`retryable`): the governing keyring revision isn't retained
          // yet. HOLD this entry — and, to preserve order, everything after it — WITHOUT
          // advancing the cursor, so a later tick that has synced the keyring re-pulls from
          // here and verifies. Advancing past it (as a genuine rejection does) would drop a
          // valid edit FOREVER: the durable cursor never revisits a seq it moved beyond.
          if (err?.retryable) {
            held = e.seq;
            break;
          }
          // A genuine rejection (bad signature / wrong role / unauthorized author): drop it and
          // move past — the rest still merge (order-insensitive), so one bad entry can't stall.
          rejected.push({ seq: e.seq, member: e.member ?? null, reason: String(err?.message ?? err) });
          this.#pulledCursor = e.seq;
          continue;
        }
      }
      await this.#tree.mergeRemote(plain);
      merged += 1;
      this.#pulledCursor = e.seq;
    }
    this.#saveCursor();
    return { merged, rejected, headSeq: tail.headSeq, held };
  }

  /**
   * Reconcile our local base with the server's snapshot: if the server has a base that subsumes MORE of the
   * log than our cursor, VERIFY it (§B3), merge its state, and jump the pull cursor past the subsumed prefix
   * so those deltas are never replayed. This is the reader-half of the snapshot channel (the origin-half
   * creates the row); idempotent + monotonic — a no-op when the server base isn't ahead, and the cursor only
   * ever advances.
   *
   * `covers_through_seq` is EXCLUSIVE: the base subsumes every delta with seq < covers_through_seq (0 =
   * subsumes nothing, a plain V1 state snapshot), so the last subsumed seq is covers-1 and pull reads after
   * it. The coverage is read from the AAD-bound header BEFORE opening, only to decide "is this ahead of me?"
   * — the cursor is advanced ONLY after the base VERIFIES, so a forged high-coverage base can't skip deltas.
   *
   * Fail-closed: a base we cannot verify OR open is NOT adopted and returns `{ deferred: true }` (never
   * throws, never a permanent reject) — on a shared tree the reconcile then skips the delta pull (a base
   * that won't verify ⇒ snapshot channel not-Ok), and the reader retries until a valid signed base lands
   * (the owner's self-heal). Returns one of:
   *   { rowExists:false }                              — no server row (caller's origin path creates one)
   *   { rowExists:true, adopted:false }                — a row exists but isn't ahead of us; nothing to do
   *   { rowExists:true, deferred:true, reason }         — a base exists but isn't (yet) usable; retry
   *   { rowExists:true, adopted:true, coversThroughSeq } — adopted; the cursor jumped past the prefix
   */
  async adopt() {
    const snap = await this.#remote.readSnapshot(this.#docId);
    if (!snap || !snap.bytes) return { rowExists: false };
    // A base with no declared coverage (or no attribution seam) subsumes nothing → 0. Guard against a
    // missing field so the cursor can never become NaN.
    const covers = (this.#attribution ? (await this.#attribution(snap.bytes)).coversThroughSeq : 0) || 0;
    // Report the base's coverage + etag regardless of whether we adopt it, so the snapshot channel can
    // decide a writer self-heal (a shared tree whose base still subsumes nothing needs a signed one).
    const base = { rowExists: true, coversThroughSeq: covers, version: snap.version };
    const floor = covers - 1; // last seq the base subsumes; pull reads strictly after it
    if (floor <= this.#pulledCursor) return { ...base, adopted: false }; // not ahead of us
    let plain;
    try {
      plain = await this.#open(snap.bytes);
    } catch (err) {
      return { ...base, deferred: true, reason: `snapshot open failed: ${String(err?.message ?? err)}` };
    }
    if (this.#verify) {
      try {
        await this.#verify(snap.bytes, plain);
      } catch (err) {
        // A base we can't verify (yet) — never adopt it. Always retry (deferred, never a hard reject): a
        // retryable hold resolves after a keyring sync, and a crash-window/stale base resolves when the
        // owner's self-heal publishes a signed one.
        return { ...base, deferred: true, reason: String(err?.message ?? err) };
      }
    }
    await this.#tree.mergeRemote(plain);
    this.#pulledCursor = floor;
    this.#saveCursor();
    return { ...base, adopted: true };
  }

  /** The delta cursor — the last log seq merged into the local tree. A self-healed base declares
   *  `covers = pulledSeq + 1` (exclusive), the seq up to which the local state is caught up. */
  pulledSeq() {
    return this.#pulledCursor;
  }

  /** One tick: push local, then pull remote. */
  async sync() {
    await this.push();
    return this.pull();
  }

  /** The change-history / activity feed (log metadata since `since`). */
  async activity(since = -1) {
    return this.#remote.activity(this.#docId, since);
  }

  /** Stop capturing local deltas. */
  stop() {
    this.#unsub?.();
  }

  #cursorKey() {
    return `openom.sync.cursor.${this.#docId}`;
  }
  #loadCursor() {
    try {
      const v = this.#persist.getItem(this.#cursorKey());
      return v == null ? -1 : Number(v);
    } catch {
      return -1;
    }
  }
  #saveCursor() {
    try {
      this.#persist.setItem(this.#cursorKey(), String(this.#pulledCursor));
    } catch {
      /* best effort */
    }
  }
}
