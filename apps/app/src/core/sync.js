// SyncController — drives delta-log sync between a local FamilyTree and the server's log. Delta sync is
// simple because deltas are self-contained, commutative, and idempotent: appends never conflict (the
// server's replica dot dedupes re-delivery), and a pull just merges — no CAS/merge-resolution loop like
// snapshots need. This is the client half of the B1 delta-log.
//
// Wiring (all functions exposed, even where no UI consumes them yet):
//   * push()       — seal each locally-produced delta as KIND_DELTA and append it to the remote log.
//   * pull()       — read the remote tail since our cursor, unseal, and merge each into the tree.
//   * bootstrap()  — a fresh device: adopt the remote snapshot baseline (if any), then pull the tail.
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
  constructor({ tree, remote, docId, seal, open, persist, replicaKey = null, verify = null }) {
    this.#tree = tree;
    this.#remote = remote;
    this.#docId = docId;
    this.#seal = seal;
    this.#open = open;
    this.#persist = persist ?? defaultPersist();
    this.#replicaKey = replicaKey;
    this.#verify = verify;
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
   * ones that pass. An entry that fails verification is dropped (never merged) and returned in `rejected`;
   * the rest still merge (order-insensitive), so a single unauthorized entry from a hostile server can't
   * stall or poison the log. Own echoes (replicaKey) are skipped without verifying.
   */
  async pull() {
    const tail = await this.#remote.readLog(this.#docId, this.#pulledCursor);
    let merged = 0;
    const rejected = [];
    for (const e of tail.entries) {
      if (!(this.#replicaKey && e.replica === this.#replicaKey)) {
        const plain = await this.#open(e.payload);
        if (this.#verify) {
          try {
            await this.#verify(e.payload, plain);
          } catch (err) {
            rejected.push({ seq: e.seq, member: e.member ?? null, reason: String(err?.message ?? err) });
            this.#pulledCursor = e.seq; // drop it and move on — a bad entry doesn't block the good ones
            continue;
          }
        }
        await this.#tree.mergeRemote(plain);
        merged += 1;
      }
      this.#pulledCursor = e.seq;
    }
    this.#saveCursor();
    return { merged, rejected, headSeq: tail.headSeq };
  }

  /**
   * A fresh device: adopt the remote snapshot baseline (if any) then pull the tail. The snapshot is
   * VERIFIED before adoption (§B3) — a forged snapshot is the worst injection (a fresh device swallows the
   * whole tree from it), so if verification throws we do NOT adopt it and the error propagates (fail-closed).
   */
  async bootstrap() {
    const snap = await this.#remote.readSnapshot(this.#docId);
    if (snap && snap.bytes) {
      const plain = await this.#open(snap.bytes);
      if (this.#verify) await this.#verify(snap.bytes, plain); // throws → refuse to bootstrap from it
      await this.#tree.mergeRemote(plain);
    }
    return this.pull();
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
