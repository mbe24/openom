// The app-core worker: the ONE place the claim engine, the DEK sealer, the docsync loop, and the local
// durable store live. Keys never reach the main thread. Exposed via Comlink as a flat API keyed by
// `docId`; each core owns one tree. The main thread provides only a `transport` (a Comlink-proxied
// `fetch` seam) and drives ticks via `syncNow`.
//
// The sync tick is the only async work here: it calls the core's SYNCHRONOUS Rust steps (outbound /
// ingest / markPushed) with `await transport.*` in between. A per-core single-flight guard (`syncing`)
// plus a `dirty` re-run make concurrent ticks safe — the Rust core is never re-entered mid-borrow
// because each step runs to completion before the next `await`.
import * as Comlink from '../vendor/comlink.js';
import init, {
  AppCoreHandle,
  provision as wasmProvision,
  unlock as wasmUnlock,
  recover as wasmRecover,
  changePassphrase as wasmChangePassphrase,
  addMember as wasmAddMember,
  provisionMember as wasmProvisionMember,
  verifyKeyringWalk as wasmVerifyKeyringWalk,
  unlockAsMember as wasmUnlockAsMember,
  wrapChainKeyringUpdate as wasmWrapKeyringUpdate,
  keyringHasBeenShared as wasmHasBeenShared,
  moderatorsFromKeyring as wasmModerators,
} from '../vendor/app-core/openom_app_core.js';
import { IndexedDbStore } from './indexedDbStore.js';
import { indexedDbKeyringStore } from './sealer/keyringStore.js';
import { joinAsMember, publishKeyring } from './sharing.js';

let ready = null;
const ensureInit = () => (ready ??= init());

// The keyring engine this build provisions with (matches core/sealer/index.js). Runtime-selectable
// later (Tauri seam); the web app is chain today.
const KEYRING_ENGINE = 'chain';

// Durable keyring store (IndexedDB; works in a Worker) — persists the genesis keyring on provision so a
// later unlock can load it. The fuller keyring-sync/reconcile is OPE-382.
let keyring = null;
const keyringStore = () => (keyring ??= indexedDbKeyringStore());

// A FRESH replica id per open (invariant that keeps a device's own server history recoverable after a
// lost local store — see review finding C9). 16 random bytes.
function freshReplica() {
  const r = new Uint8Array(16);
  crypto.getRandomValues(r);
  return r;
}

// The engine-opaque anti-rollback watermark, persisted per doc (recover / change-passphrase pass it back
// as the `floor`). Stored in the IndexedDbStore snapshot slot under a meta key — no localStorage in a
// Worker. Overwrite-with-CAS on the current version.
const WM_KEY = (docId) => `${docId}::watermark`;
async function saveWatermark(docId, wm) {
  const prev = await store().readSnapshot(WM_KEY(docId));
  await store().putSnapshot(WM_KEY(docId), wm, prev?.version ?? null);
}
async function loadWatermark(docId) {
  const s = await store().readSnapshot(WM_KEY(docId));
  return s ? s.bytes : new Uint8Array(0);
}

// The durable mirror: a dumb async blob store (IndexedDB on web — also works in the Tauri webview).
// The Rust core owns ALL persistence logic; this just executes the append/readUpdates verbs it dictates
// over already-sealed bytes. Lazily created; shared across cores in this worker (keyed by docId inside).
let idb = null;
const store = () => (idb ??= new IndexedDbStore());

/** docId -> Core. Two replicas of the SAME tree run in SEPARATE workers (same docId, distinct core). */
const cores = new Map();

/** docId -> network transport. Keyed here (not on the Core) so a member JOIN can fetch the keyring history
 * BEFORE its core exists. Set by `attachTransport`, read by the sync tick + join. */
const transports = new Map();
const transportFor = (docId) => transports.get(docId) ?? null;

class Core {
  constructor(handle, docId, persist) {
    this.handle = handle;
    this.docId = docId;
    this.persist = persist; // mirror the local log to IndexedDB (off for in-memory / UI-test mode)
    this.persistLock = Promise.resolve(); // serialize persistence — commit and a tick both trigger it
    this.syncing = false; // single-flight: one tick at a time
    this.dirty = false; // an edit/commit arrived mid-tick — re-run before returning
    this.aborted = false;
  }
}

// Load the durably-persisted log into a fresh handle, then let the engine rebuild from it. `importLog`
// advances the core's OWN persist cursor past what came from durable storage, so nothing re-mirrors.
async function hydrate(core) {
  if (core.persist) {
    const { updates } = await store().readUpdates(core.docId, null);
    if (updates.length) core.handle.importLog(updates);
  }
  core.handle.bootstrap(); // replay the local log into the engine (a no-op on an empty store)
}

// Mirror everything the core has logged since the last persist (local mints + folded server deltas) to
// durable storage. Serialized on the core's persistLock so commit and a running tick can't interleave
// their export→append→mark and double-write. The persist CURSOR lives in the core, not here.
function persistDelta(core) {
  if (!core.persist) return Promise.resolve();
  core.persistLock = core.persistLock.then(async () => {
    const { entries, through } = core.handle.exportUnpersisted();
    if (entries.length) {
      await store().append(core.docId, entries);
      core.handle.markPersisted(through);
    }
  });
  return core.persistLock;
}

function core(docId) {
  const c = cores.get(docId);
  if (!c) throw new Error(`no app-core for doc ${docId}`);
  return c;
}

// Gather a chain tree's retained per-revision keyrings as `[revision, Uint8Array][]` for the §B3 resolver.
// The dag resolves membership from its single anchor, so it retains nothing (returns []).
async function retainedKeyrings(docId, engine) {
  if (engine !== 'chain') return [];
  const head = await keyringStore().head(docId);
  if (!head) return [];
  const pairs = [];
  for (let r = 1; r <= head.revision; r += 1) {
    const bytes = await keyringStore().at(docId, r);
    if (bytes) pairs.push([r, bytes]);
  }
  return pairs;
}

// Activate verify-on-ingest for a SHARED tree: install the §B3 resolver (built from the head keyring + the
// retained revisions) and feed the current moderators to the claim fold. A solo/never-shared tree needs
// neither (only the DEK holder can write), so this is a no-op there. Called on unlock and after each keyring
// change, so ingest verifies peer entries against the current membership.
async function installMembership(core, docId, engine, head) {
  if (!head || !wasmHasBeenShared(engine, head)) return;
  core.handle.setMembership(engine, head, await retainedKeyrings(docId, engine));
  core.handle.setModerators(wasmModerators(engine, head));
}

const api = {
  /** Pre-warm the wasm init so the first open is fast. */
  async warm() {
    await ensureInit();
  },

  /**
   * Open a local-development core (dev key; the demo + sync-e2e path). `treeId` / `replicaId` are byte
   * arrays; `createdBy` is this device's author did:key; `docId` is the local store key. `persist` mirrors
   * the local log to IndexedDB (durable across reload); pass false for in-memory-only tests.
   */
  async openDev(treeId, replicaId, createdBy, docId, persist = false) {
    await ensureInit();
    const handle = AppCoreHandle.dev(treeId, replicaId, createdBy, docId);
    const core = new Core(handle, docId, persist);
    await hydrate(core); // importLog (if persisting) + bootstrap — uniform for both modes
    cores.set(docId, core);
    return true;
  },

  /**
   * Create a brand-new encrypted tree: provision the keyring, persist its genesis head, and open a
   * durable core. Returns the show-once `recoveryCode` + the author `didKey` + advisory self-heal flags
   * (the DEK stays in this worker). `opts`: { passphrase, treeId: Uint8Array, memberId, docId, engine? }.
   */
  async provisionCore({ passphrase, treeId, memberId, docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const res = wasmProvision(engine, passphrase, treeId, memberId, freshReplica(), docId);
    try {
      await keyringStore().saveHead(docId, engine, res.keyring); // persist genesis for later unlock
      // Retain the genesis under revision 1 (chain) so a later share can PUBLISH it — a joining member's
      // genesis-walk must fetch rev 1 from the server.
      if (engine === 'chain') await keyringStore().save(docId, 1, res.keyring);
      await saveWatermark(docId, res.watermark); // the anti-rollback floor for recover / change-passphrase
      const core = new Core(res.takeHandle(), docId, true);
      await hydrate(core); // fresh store → a no-op bootstrap
      cores.set(docId, core);
      return {
        recoveryCode: res.recoveryCode,
        didKey: res.didKey,
        needsReseal: res.needsReseal,
        needsBackfill: res.needsBackfill,
      };
    } finally {
      res.free();
    }
  },

  /**
   * Re-open an existing tree (returning / new device): load its persisted keyring head, unlock, and
   * hydrate the durable core. Returns the author `didKey` + advisory self-heal flags. `opts`:
   * { passphrase, treeId: Uint8Array, memberId, docId, engine? }.
   */
  async unlockCore({ passphrase, treeId, memberId, docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const eng = head.engine || engine;
    const res = wasmUnlock(eng, passphrase, treeId, memberId, freshReplica(), head.bytes, docId);
    try {
      await saveWatermark(docId, res.watermark); // refresh the persisted floor
      const core = new Core(res.takeHandle(), docId, true);
      await hydrate(core); // load the persisted log + bootstrap
      await installMembership(core, docId, eng, head.bytes); // activate §B3 verify if the tree is shared
      cores.set(docId, core);
      return { didKey: res.didKey, needsReseal: res.needsReseal, needsBackfill: res.needsBackfill };
    } finally {
      res.free();
    }
  },

  /**
   * Recover owner access with the recovery code under a new passphrase: re-establishes the keyring, opens
   * a durable core (recovery mints a fresh identity → a new `didKey`), and persists the new keyring +
   * watermark + shows a NEW recovery code. `opts`: { recoveryCode, newPassphrase, treeId, memberId, docId, engine? }.
   */
  async recoverCore({ recoveryCode, newPassphrase, treeId, memberId, docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const floor = await loadWatermark(docId);
    const res = wasmRecover(
      head.engine || engine, recoveryCode, newPassphrase, treeId, memberId, freshReplica(), head.bytes, floor, docId,
    );
    try {
      await keyringStore().saveHead(docId, head.engine || engine, res.keyring); // the recovered keyring
      await saveWatermark(docId, res.watermark);
      const core = new Core(res.takeHandle(), docId, true);
      await hydrate(core);
      cores.set(docId, core);
      return { recoveryCode: res.recoveryCode, didKey: res.didKey, needsReseal: res.needsReseal, needsBackfill: res.needsBackfill };
    } finally {
      res.free();
    }
  },

  /**
   * Change the passphrase: re-wrap the keyring under a new KEK + rotate the recovery code. The DEK is
   * unchanged, so the RUNNING core keeps working (no new core). Returns the fresh recovery code to show.
   * `opts`: { current, next, treeId, memberId, docId, engine? }.
   */
  async changePassphraseCore({ current, next, treeId, memberId, docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const floor = await loadWatermark(docId);
    const res = wasmChangePassphrase(
      head.engine || engine, current, next, treeId, memberId, freshReplica(), head.bytes, floor,
    );
    try {
      await keyringStore().saveHead(docId, head.engine || engine, res.keyring); // the re-wrapped keyring
      await saveWatermark(docId, res.watermark);
      return { recoveryCode: res.recoveryCode };
    } finally {
      res.free();
    }
  },

  /** Whether a keyring has been provisioned for `docId` (→ show unlock vs. welcome at the gate). */
  async hasKeyring(docId) {
    return !!(await keyringStore().loadHead(docId));
  },

  /** Attach the network transport (a Comlink-proxied main-thread `fetch` seam). */
  attachTransport(docId, transport) {
    transports.set(docId, transport);
  },

  setModerators(docId, dids) {
    core(docId).handle.setModerators(dids);
  },

  /**
   * Owner admits a member: HPKE-wrap the tree DEK to the joiner's OOB-verified keys, persist the new shared
   * keyring (+ chain per-revision retention), and refresh this core's §B3 resolver so it now verifies peer
   * entries. The owner's running session is unchanged (an add mints no new epoch). `opts`: { passphrase,
   * treeId, ownerMemberId, minRevision, newMemberId, role, memberAuthorPublic, memberHpkePublic, engine? }.
   * Returns nothing — the caller re-reads membership via the projection.
   */
  async addMember(
    docId,
    { passphrase, treeId, ownerMemberId, minRevision = 0, newMemberId, role, memberAuthorPublic, memberHpkePublic, engine = KEYRING_ENGINE },
  ) {
    const c = core(docId);
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const eng = head.engine || engine;
    const change = wasmAddMember(
      eng, head.bytes, passphrase, treeId, ownerMemberId, freshReplica(), minRevision,
      newMemberId, role, memberAuthorPublic, memberHpkePublic,
    );
    await keyringStore().saveHead(docId, eng, change.keyring);
    await saveWatermark(docId, change.watermark);
    // Chain retention: the new revision is the first 4 bytes of the pinned watermark (revision‖key_id‖H(DEK)).
    if (eng === 'chain') {
      const revision = new DataView(change.watermark.buffer, change.watermark.byteOffset, 4).getUint32(0);
      await keyringStore().save(docId, revision, change.keyring);
    }
    await installMembership(c, docId, eng, change.keyring); // the tree is now shared → verify goes live
    // Publish the shared keyring tail so a member's join can fetch it. Best-effort: if no transport is
    // attached yet, the owner publishes on the next explicit publishKeyring / sync — the local state stands.
    if (eng === 'chain' && transportFor(docId)) {
      await publishKeyring(
        { wasm: { wrapChainKeyringUpdate: wasmWrapKeyringUpdate }, transport: transportFor(docId), keyringStore: keyringStore() },
        { docId },
      );
    }
  },

  /**
   * Mint a joining member's account identity from their passphrase (the first member-flow step, before the
   * owner admits them). Returns { kdfParams, authorPublicKey, hpkePublicKey } — the caller persists kdfParams
   * and hands the two public keys to the owner out-of-band. The secrets stay in the worker.
   */
  async provisionMember(passphrase) {
    await ensureInit();
    const m = wasmProvisionMember(passphrase);
    return { kdfParams: m.kdfParams, authorPublicKey: m.authorPublicKey, hpkePublicKey: m.hpkePublicKey };
  },

  /**
   * Join a shared tree as a member: fetch the keyring history, genesis-walk + invite-pin verify it, retain
   * every verified revision, and unlock as the member — opening a durable, verify-active core. `opts`:
   * { treeId, treeUuid, docId, passphrase, memberId, memberKdfParams, pinnedRevision, pinnedHash, engine? }.
   * `transport` must already be reachable for the keyring fetch (attach it before joining). Returns didKey.
   */
  async joinAsMember(opts) {
    await ensureInit();
    const { docId, engine = KEYRING_ENGINE } = opts;
    if (!transportFor(docId)) throw new Error('attach a transport before joining');
    const res = await joinAsMember(
      { wasm: { verifyKeyringWalk: wasmVerifyKeyringWalk, unlockAsMember: wasmUnlockAsMember }, transport: transportFor(docId), keyringStore: keyringStore() },
      opts,
    );
    try {
      await saveWatermark(docId, res.watermark);
      const c = new Core(res.takeHandle(), docId, true);
      await hydrate(c);
      await installMembership(c, docId, engine, (await keyringStore().loadHead(docId)).bytes);
      cores.set(docId, c);
      return { didKey: res.didKey };
    } finally {
      res.free();
    }
  },

  // --- mint (buffer into the current intention; `commit` seals + persists the batch) --------------

  assertAnchor(docId, id, typeUri) {
    core(docId).handle.assertAnchor(id, typeUri);
  },
  assertClaim(docId, target, predicate, valueJson) {
    core(docId).handle.assertClaim(target, predicate, valueJson);
  },
  supersedeClaim(docId, prior, target, predicate, valueJson) {
    core(docId).handle.supersedeClaim(prior, target, predicate, valueJson);
  },
  removeRecord(docId, target) {
    return core(docId).handle.removeRecord(target);
  },
  revoke(docId, removalOpId) {
    core(docId).handle.revoke(removalOpId);
  },
  async commit(docId) {
    const c = core(docId);
    c.handle.commit();
    await persistDelta(c); // durably mirror the new batch (no-op when not persisting)
    if (c.syncing) c.dirty = true; // a commit during a tick → re-scan outbound
  },

  // --- reads --------------------------------------------------------------------------------------

  project(docId) {
    return core(docId).handle.project();
  },
  oplog(docId) {
    return core(docId).handle.oplog();
  },
  liveRecords(docId) {
    return core(docId).handle.liveRecords();
  },
  liveClaimsOf(docId, target, predicate) {
    return core(docId).handle.liveClaimsOf(target, predicate);
  },
  liveClaimsOfAny(docId, target) {
    return core(docId).handle.liveClaimsOfAny(target);
  },
  resolveId(docId, anchor) {
    return core(docId).handle.resolveId(anchor);
  },
  pendingCount(docId) {
    return core(docId).handle.pendingCount();
  },

  // --- sync ---------------------------------------------------------------------------------------

  /** Run one full tick (push our outbound, then pull + fold the server tail). Single-flighted. */
  async syncNow(docId) {
    return runTick(core(docId));
  },

  /** Clear a core's tree + its durable IndexedDB log (demo reseed / hard local reset). Keeps the DEK. */
  async resetCore(docId) {
    core(docId).handle.reset(); // clears the in-memory tree + the core's own store + persist cursor
    await store().delete(docId); // also wipe the durable IndexedDB mirror, so nothing replays on reload
  },

  /** Delete a doc's durably-persisted log (test cleanup / a hard local reset). */
  async clearPersisted(docId) {
    await store().delete(docId);
  },

  /** Drop a core entirely (frees the wasm handle + the DEK it holds). */
  async close(docId) {
    const c = cores.get(docId);
    if (!c) return;
    c.aborted = true; // any in-flight tick bails at its next aborted-check before touching the handle
    try {
      await c.persistLock; // let an in-flight persist finish writing before we free the handle
    } catch {
      /* persist failed — free anyway */
    }
    try {
      c.handle.free();
    } catch {
      /* already gone */
    }
    cores.delete(docId);
    transports.delete(docId);
  },
};

async function runTick(c) {
  const transport = transportFor(c.docId);
  if (!transport) return { state: 'no-transport' };
  if (c.aborted) return { state: 'stopped' };
  if (c.syncing) {
    c.dirty = true; // fold this request into the running tick
    return { state: 'busy' };
  }
  c.syncing = true;
  try {
    do {
      c.dirty = false;
      if (c.aborted) break;
      await pushOnce(c);
      if (c.aborted) break;
      await pullOnce(c);
    } while (c.dirty);
    if (c.aborted) return { state: 'stopped' }; // torn down mid-tick — don't touch the (maybe-freed) handle
    // `anomalies` (quarantined / undecodable entries) is surfaced, never swallowed; the driver can warn.
    return { state: 'ok', pending: c.handle.pendingCount(), anomalies: c.handle.anomalies() };
  } catch (e) {
    return { state: 'error', message: String(e?.message ?? e) };
  } finally {
    c.syncing = false;
  }
}

async function pushOnce(c) {
  const transport = transportFor(c.docId);
  const out = c.handle.outbound(); // { entries: Uint8Array[], through: number }
  for (const env of out.entries) {
    if (c.aborted) return;
    await transport.appendLog(c.docId, env);
  }
  if (c.aborted) return; // no await between this check and markPushed → close() can't free under us
  c.handle.markPushed(out.through);
}

async function pullOnce(c) {
  // Drain the whole tail this tick — a fresh device against a big tree shouldn't need one syncNow per
  // page. Bounded: stop on an empty page, or if the cursor didn't advance (a non-advancing / hostile
  // server), so this can't spin.
  for (;;) {
    if (c.aborted) return;
    const since = c.handle.serverSince(); // number | undefined
    const page = await transportFor(c.docId).readLog(c.docId, since); // { entries: Uint8Array[], nextCursor }
    if (c.aborted) return;
    c.handle.ingest(page.entries, page.nextCursor);
    await persistDelta(c); // durably mirror the folded server deltas too
    const advanced = c.handle.serverSince() !== since;
    if (!page.entries?.length || !advanced) return;
  }
}

Comlink.expose(api);
