// The app-core worker: the ONE place the claim engine, the DEK sealer, the docsync loop, and the local
// durable store live. Keys never reach the main thread. Exposed via Comlink as a flat API keyed by
// `docId`; each core owns one tree. The main thread provides only a `transport` (a Comlink-proxied
// `fetch` seam) and drives ticks via `syncNow`.
//
// The sync tick is the only async work here: it fetches the remote's object snapshot, calls the core's
// SYNCHRONOUS Rust `sync` step (mirror + fold + compute the upload set), and uploads the diff — with
// `await transport.*` in between. A per-core single-flight guard (`syncing`) plus a `dirty` re-run make
// concurrent ticks safe — the Rust core is never re-entered mid-borrow because each step runs to
// completion before the next `await`.
import * as Comlink from '../vendor/comlink.js';
import { makeError, normalizeUnknown, isAppError } from './errorModel.js';
import init, {
  AppCoreHandle,
  provision as wasmProvision,
  unlock as wasmUnlock,
  recover as wasmRecover,
  changePassphrase as wasmChangePassphrase,
  addMember as wasmAddMember,
  removeMember as wasmRemoveMember,
  changeRole as wasmChangeRole,
  provisionMember as wasmProvisionMember,
  verifyKeyringWalk as wasmVerifyKeyringWalk,
  unlockAsMember as wasmUnlockAsMember,
  wrapChainKeyringUpdate as wasmWrapKeyringUpdate,
  unwrapChainKeyring as wasmUnwrapKeyring,
  keyringHash as wasmKeyringHash,
  syncKeyring as wasmSyncKeyring,
  keyringHasBeenShared as wasmHasBeenShared,
  moderatorsFromKeyring as wasmModerators,
  dagAnchorPin as wasmDagAnchorPin,
  verifyDagAnchor as wasmVerifyDagAnchor,
  acceptRemoteDagAnchor as wasmAcceptRemoteDagAnchor,
  wrapDagKeyringUpdate as wasmWrapDagKeyringUpdate,
  unwrapDagKeyring as wasmUnwrapDagKeyring,
  rotateRecovery as wasmRotateRecovery,
  rotationConfirmed as wasmRotationConfirmed,
  backfillRrk as wasmBackfillRrk,
  resolvedOwnerKey as wasmResolvedOwnerKey,
  recoveryConfirmed as wasmRecoveryConfirmed,
  keyringSummary as wasmKeyringSummary,
  keyringCovers as wasmKeyringCovers,
} from '../vendor/app-core/openom_app_core.js';
import { IndexedDbStore } from './indexedDbStore.js';
import { indexedDbKeyringStore } from './sealer/keyringStore.js';
import {
  joinAsMember, publishKeyring, syncKeyring as syncKeyringImpl,
  joinDagAnchor, publishDagAnchor, syncDagAnchor,
} from './sharing.js';
import { pushMembershipSummary } from './membershipSummary.js';
import { MembershipAsserts } from './membershipAsserts.js';

let ready = null;
const ensureInit = () => (ready ??= init());

// The keyring engine this build provisions with. Runtime-selectable later (Tauri seam); the web app is
// chain today.
const KEYRING_ENGINE = 'chain';

// Compaction cadence (OPE-409): the data channel compacts once this many log objects have accrued since the
// last snapshot (the SnapshotPolicy seam's initial fixed-K bound, driven per sync tick). Overridable via
// `setCompactK` (tests lower it to exercise compaction with few writes).
let compactK = 64;

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

// OPE-407 (explicit create-tree): a DURABLE per-doc marker that this device provisioned a NEW tree whose
// server `trees` row may not exist yet. Set at provision, consumed + cleared on the first sync tick that
// reaches the server (`createTree` is idempotent for the owner). Durable — not just an in-memory flag — so
// an offline provision that later RESTARTS before it ever synced still mints the tree on its first online
// tick, rather than 404ing forever. A JOINing member never sets it: it adopts a tree the owner created.
// Stored in the same per-doc meta slot as the watermark (no localStorage in a Worker); `[1]` = pending.
const NEEDS_TREE_KEY = (docId) => `${docId}::needs-create-tree`;
async function markNeedsCreateTree(docId) {
  const prev = await store().readSnapshot(NEEDS_TREE_KEY(docId));
  await store().putSnapshot(NEEDS_TREE_KEY(docId), new Uint8Array([1]), prev?.version ?? null);
}
async function needsCreateTree(docId) {
  const s = await store().readSnapshot(NEEDS_TREE_KEY(docId));
  return !!s && s.bytes[0] === 1;
}
async function clearNeedsCreateTree(docId) {
  try {
    const prev = await store().readSnapshot(NEEDS_TREE_KEY(docId));
    if (!prev) return; // never marked → nothing to clear
    await store().putSnapshot(NEEDS_TREE_KEY(docId), new Uint8Array([0]), prev.version ?? null);
  } catch {
    // Best-effort: the marker is advisory and createTree is idempotent, so losing the CAS race against
    // another Core for this docId (or a transient store hiccup) just leaves the marker set — a later
    // session re-POSTs (a 200 no-op for the owner) and re-clears. Never wedge the tick on a cleanup write.
  }
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

// The shared REMOTE keyspace is per-TREE (every device of one tree meets there), while the core's LOCAL
// keyspace + the durable store are per-DEVICE (`docId`, so two devices in one page/origin stay isolated). The
// worker maps between them at the transport boundary — the only place it touches a key, and only its leading
// doc segment (never the internal `log/{replica}/{counter}` structure the core owns).
const treeKeyOf = (treeId) => [...new Uint8Array(treeId)].map((b) => b.toString(16).padStart(2, '0')).join('');

class Core {
  constructor(handle, docId, persist, treeId = null, engine = null) {
    this.handle = handle;
    this.docId = docId;
    this.treeId = treeId; // the 16-byte seam id — needed to sync the keyring channel before a data pull
    // The remote keyspace prefix for this tree (falls back to docId if a dev core has no treeId).
    this.treeKey = treeId ? treeKeyOf(treeId) : docId;
    this.engine = engine; // 'chain' | 'dag' | null — only chain has the per-revision keyring channel to sync
    this.shared = false; // set once a §B3 resolver is installed (a shared tree) → the tick keyring-syncs first
    this.persist = persist; // mirror the local log to IndexedDB (off for in-memory / UI-test mode)
    this.persistLock = Promise.resolve(); // serialize persistence — commit and a tick both trigger it
    this.syncing = false; // single-flight: one tick at a time
    this.dirty = false; // an edit/commit arrived mid-tick — re-run before returning
    this.aborted = false;
    this.treeEnsured = false; // OPE-407: skip the durable needs-create-tree check once satisfied this session
    this.reportedFrontier = null; // OPE-409 gate 2: the last pull frontier reported to the server (change-guard)
  }
}

// Load the durably-persisted objects into a fresh handle's local store, then let the engine rebuild from it.
// `import` picks each object's write precondition (immutable vs pointer), so replaying is idempotent.
async function hydrate(core) {
  if (core.persist) {
    const objects = await store().readBlobs(core.docId);
    if (objects.length) core.handle.import(objects);
  }
  core.handle.bootstrap(); // fold the local store into the engine (a no-op on an empty store)
}

// Mirror the core's whole local store to durable storage. `export()` is idempotent to re-persist (immutable
// log objects are content-stable; pointer objects overwrite), so we simply write the current object set.
// Serialized on the core's persistLock so a commit and a running tick can't interleave their writes.
function persistBlobs(core) {
  if (!core.persist) return Promise.resolve();
  core.persistLock = core.persistLock.then(async () => {
    try {
      await store().putBlobs(core.docId, core.handle.export());
    } catch (e) {
      throw storageError(e); // a full/blocked IndexedDB surfaces as storage_quota/storage_blocked, not internal
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
  core.shared = true; // a shared tree → the sync tick pulls the keyring channel before the data channel
}

// Publish this device's current membership so peers can fetch + verify it (owner action, after an add/remove).
// Chain PUTs the missing revision tail; the dag PUTs the full self-contained anchor as the next slot. A no-op
// with no transport attached — the local state stands and publishes on the next call.
async function publishMembership(docId, engine, treeId) {
  if (!transportFor(docId)) return;
  if (engine === 'chain') {
    await publishKeyring(
      { wasm: { wrapChainKeyringUpdate: wasmWrapKeyringUpdate }, transport: transportFor(docId), keyringStore: keyringStore() },
      { docId },
    );
  } else if (engine === 'dag') {
    await publishDagAnchor(
      { wasm: { wrapDagKeyringUpdate: wasmWrapDagKeyringUpdate }, transport: transportFor(docId), keyringStore: keyringStore() },
      { docId, treeId },
    );
  }
}

// Adopt any newer keyring/membership before a data pull (keyring-before-data), refreshing the resolver +
// moderators. A no-op unless the tree is shared and has a treeId. Chain walks the per-revision successors; the
// dag adopts the latest self-contained anchor against its pin + the persisted anti-rollback floor.
async function syncKeyringForTick(c) {
  if (!c.shared || !c.treeId || c.aborted) return;
  if (c.engine === 'chain') {
    const r = await syncKeyringImpl(
      { wasm: { syncKeyring: wasmSyncKeyring, unwrapChainKeyring: wasmUnwrapKeyring }, transport: transportFor(c.docId), keyringStore: keyringStore() },
      { docId: c.docId, treeId: c.treeId },
    );
    if (r.changed) await refreshMembershipAndEpochs(c, 'chain', (await keyringStore().loadHead(c.docId)).bytes);
  } else if (c.engine === 'dag') {
    const r = await syncDagAnchor(
      { wasm: { unwrapDagKeyring: wasmUnwrapDagKeyring, dagAnchorPin: wasmDagAnchorPin, acceptRemoteDagAnchor: wasmAcceptRemoteDagAnchor }, transport: transportFor(c.docId), keyringStore: keyringStore() },
      { docId: c.docId, treeId: c.treeId, floor: await loadWatermark(c.docId) },
    );
    if (r.changed) {
      await saveWatermark(c.docId, r.watermark);
      await refreshMembershipAndEpochs(c, 'dag', (await keyringStore().loadHead(c.docId)).bytes);
    }
  }
}

// After a member adopts a keyring change: refresh the §B3 resolver + moderators AND — if the change rotated
// the write epoch (a removal) — splice the new epoch DEK into the running sealer so the member can decrypt
// post-rotation content (incl. the self-heal cover). adoptEpochs is a no-op on an owner core (no retained
// member secret) and idempotent when no epoch is new, so it is safe to call after any membership change.
async function refreshMembershipAndEpochs(c, engine, head) {
  await installMembership(c, c.docId, engine, head);
  c.handle.adoptEpochs(head);
}

// --- Advisory membership-summary push (OPE-293) ----------------------------------------------------------
//
// After a locally-verified keyring membership change, a SIGNER (owner / co-owner) asserts its resolved
// `{members, basis}` view to the managed server's advisory /access channel — the coarse ACL the server uses
// for collaboration features (notifications, server-side revocation, proposal routing), NEVER the security
// boundary (the signed keyring is that). The push MECHANISM (CAS on `generation`, an at-most-once coverage
// refresh, retry-on-409) lives in `membershipSummary.js`; this wires it to the engine (`keyringSummary` /
// `keyringCovers`, both chain + dag) and triggers it, ordered to UNDER-grant.
//
// Durability: the intent is recorded BEFORE the network call in a store that survives a Worker restart, so a
// crash between the keyring write and the push self-heals on the next flush (tick / reconnect / startup). The
// keyring itself is the authoritative durable source — the view is always recomputable from it.

// One JSON blob in the IndexedDb meta store holds the whole `openom.ma.*` map (a few members + a short basis
// per tree — tiny). A write-through in-memory cache keeps `MembershipAsserts`' synchronous get/set interface
// while persisting durably in a Worker (no localStorage here). Hydrated once, lazily.
const MA_SLOT = 'membership-asserts';
function makeDurableAssertStore() {
  const cache = new Map();
  let hydrated = null; // a once-promise
  let writing = Promise.resolve(); // serialize slot writes so their CAS never races itself
  return {
    ensureHydrated() {
      return (hydrated ??= (async () => {
        try {
          const s = await store().readSnapshot(MA_SLOT);
          if (s?.bytes?.length) {
            const obj = JSON.parse(new TextDecoder().decode(s.bytes));
            for (const [k, v] of Object.entries(obj)) cache.set(k, v);
          }
        } catch {
          /* fresh / unreadable → start empty; the keyring recompute still self-heals */
        }
      })());
    },
    getItem: (k) => (cache.has(k) ? cache.get(k) : null),
    setItem: (k, v) => {
      cache.set(k, v);
      writing = writing.then(async () => {
        try {
          const prev = await store().readSnapshot(MA_SLOT);
          const bytes = new TextEncoder().encode(JSON.stringify(Object.fromEntries(cache)));
          await store().putSnapshot(MA_SLOT, bytes, prev?.version ?? null);
        } catch {
          /* best-effort: a lost CAS / storage hiccup just leaves the cache un-persisted this round */
        }
      });
    },
  };
}
const assertStore = makeDurableAssertStore();
const membershipAsserts = new MembershipAsserts(assertStore);

// Assert this device's current resolved membership to the server's /access (managed-only). `docId` IS the
// tree UUID string the access channel keys on. Best-effort + NEVER throws — the durable intent stays marked
// for a later flush if the network (or a 404 before the tree row exists, a 403 for a non-signer) fails.
async function pushMembership(docId, engine) {
  try {
    await assertStore.ensureHydrated();
    const head = await keyringStore().loadHead(docId);
    if (!head) return;
    const eng = head.engine || engine;
    const s = JSON.parse(wasmKeyringSummary(eng, head.bytes));
    const current = { view: s.members, basis: s.basis };
    if (membershipAsserts.isConfirmed(docId, current)) return; // steady state: the server already has it
    // Record the intent DURABLY before any network — BEFORE the transport check too, so an OFFLINE signer
    // action still leaves a `desired` for the tick flush to push once a transport attaches. Only a signer's
    // own change reaches here, so `desired` is the flush's "this device is a signer" signal (no 403 spam).
    membershipAsserts.mark(docId, current);
    const transport = transportFor(docId);
    if (!transport) return; // managed-only + offline: nothing to push now; the tick flush retries
    const pushed = await pushMembershipSummary(transport, docId, current, {
      coversBasis: (storedBasis) => wasmKeyringCovers(eng, head.bytes, storedBasis),
      refresh: async () => {
        // We're behind the server's basis: pull the newer keyring, then recompute from the fresh head.
        const c = cores.get(docId);
        if (c) await syncKeyringForTick(c);
        const h = await keyringStore().loadHead(docId);
        const s2 = JSON.parse(wasmKeyringSummary(h.engine || eng, h.bytes));
        return { view: s2.members, basis: s2.basis };
      },
    });
    if (pushed) membershipAsserts.confirm(docId, current); // server acked (changed or unchanged) → de-dup
  } catch {
    /* swallow: intent (if marked) is flushed later; the keyring stays the authoritative source */
  }
}

// Retry a pending assert whose intent was recorded but not yet confirmed (a crash/offline/404 between the
// keyring write and the server ack). Gated on a recorded `desired` — which ONLY a signer's own change writes
// — so a plain member's tick never attempts a push it isn't authorized for (the server gates /access to
// signers). Cheap: a no-op in the steady state.
async function flushPendingMembership(c) {
  if (!c || !transportFor(c.docId)) return;
  await assertStore.ensureHydrated();
  if (membershipAsserts.desired(c.docId) == null) return; // this device never asserted → not a signer here
  await pushMembership(c.docId, c.engine);
}

// Map a wasm keyring/unlock error to a specific AppError. A failed anti-rollback check ("rollback" / "rolled
// Map a wasm lifecycle failure (unlock/recover/change) to a specific AppError. The veneer now throws a
// STRUCTURED { code, message } — the typed Rust VaultError mapped to a registry code (OPE-420) — so we read
// the code directly (wrong_passphrase / revision_rollback / recovery_code_invalid / keyring_verify_failed /
// decrypt_failed), no fragile message-matching. The message is kept only as dev-log `cause`, never surfaced.
function vaultError(e) {
  if (e && typeof e === 'object' && typeof e.code === 'string') {
    return makeError(e.code, { cause: e.message });
  }
  return normalizeUnknown(e);
}

// Map an IndexedDB/OPFS failure (a DOMException from the durable store) to a storage AppError, so a full or
// blocked local store surfaces meaningfully instead of as a generic internal error (C4 storage adapter).
function storageError(e) {
  if (e?.name === 'QuotaExceededError') return makeError('storage_quota', { cause: e.name });
  return makeError('storage_blocked', { cause: String(e?.message ?? e) });
}

const api = {
  /** Liveness probe (C3): a trivial round-trip the main-thread heartbeat uses to detect a wedged/silent
   *  worker (one that stopped answering without firing an `error` event). Needs no core. */
  ping() {
    return true;
  },

  /** Pre-warm the wasm init so the first open is fast. */
  async warm() {
    await ensureInit();
  },

  /** Set the compaction cadence K — the log-object count that triggers a snapshot per tick (OPE-409). */
  setCompactK(k) {
    compactK = k;
  },

  /**
   * Open a local-development core (dev key; the demo + sync-e2e path). `treeId` / `replicaId` are byte
   * arrays; `createdBy` is this device's author did:key; `docId` is the local store key. `persist` mirrors
   * the local log to IndexedDB (durable across reload); pass false for in-memory-only tests.
   */
  async openDev(treeId, replicaId, createdBy, docId, persist = false) {
    await ensureInit();
    const handle = AppCoreHandle.dev(treeId, replicaId, createdBy, docId);
    const core = new Core(handle, docId, persist, treeId, null); // dev path: never shared, no keyring sync
    await hydrate(core); // import persisted objects (if persisting) + bootstrap — uniform for both modes
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
      // OPE-407: this device provisioned a NEW tree, so it owns it and must mint the server `trees` row
      // before its first push (`put_blob` no longer mints — it 404s on a missing tree). Recorded DURABLY
      // and performed on the first sync tick, NOT inline here, so provisioning stays local-first: an
      // offline / no-backend device still provisions, and the tree is created on the first tick that
      // reaches the server. Cleared once that createTree succeeds.
      await markNeedsCreateTree(docId);
      const core = new Core(res.takeHandle(), docId, true, treeId, engine);
      await hydrate(core); // fresh store → a no-op bootstrap
      cores.set(docId, core);
      return {
        recoveryCode: res.recoveryCode,
        didKey: res.didKey,
        needsReseal: res.needsReseal,
        needsBackfill: res.needsBackfill,
        needsRrkBackfill: res.needsRrkBackfill,
        writeEpochUnreachable: res.writeEpochUnreachable,
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
    let res;
    try {
      res = wasmUnlock(eng, passphrase, treeId, memberId, freshReplica(), head.bytes, docId);
    } catch (e) {
      throw vaultError(e); // a rollback becomes revision_rollback so the gate shows tamper, not wrong-pass
    }
    try {
      await saveWatermark(docId, res.watermark); // refresh the persisted floor
      const core = new Core(res.takeHandle(), docId, true, treeId, eng);
      // Install §B3 verify BEFORE hydrate: bootstrap re-folds the WHOLE local mirror on every reopen, and a core
      // with membership == None accepts every entry unverified — so a forged snapshot/delta already in the store
      // would be re-adopted on a plain reload. Installing the resolver first gates that fold.
      await installMembership(core, docId, eng, head.bytes); // activate §B3 verify if the tree is shared
      await hydrate(core); // load the persisted log + bootstrap — now gated by the installed membership
      cores.set(docId, core);
      return { didKey: res.didKey, needsReseal: res.needsReseal, needsBackfill: res.needsBackfill, needsRrkBackfill: res.needsRrkBackfill, writeEpochUnreachable: res.writeEpochUnreachable };
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
    let res;
    try {
      res = wasmRecover(
        head.engine || engine, recoveryCode, newPassphrase, treeId, memberId, freshReplica(), head.bytes, floor, docId,
      );
    } catch (e) {
      throw vaultError(e); // a rollback becomes revision_rollback so the gate shows tamper, not a bad code
    }
    try {
      const eng = head.engine || engine;
      await keyringStore().saveHead(docId, eng, res.keyring); // the recovered keyring
      await saveWatermark(docId, res.watermark);
      const core = new Core(res.takeHandle(), docId, true, treeId, eng);
      // Install §B3 verify BEFORE hydrate (see unlockCore): the reopen re-fold must be gated by the membership.
      await installMembership(core, docId, eng, res.keyring); // a recovered shared tree keeps verifying
      await hydrate(core);
      cores.set(docId, core);
      return { recoveryCode: res.recoveryCode, didKey: res.didKey, needsReseal: res.needsReseal, needsBackfill: res.needsBackfill, needsRrkBackfill: res.needsRrkBackfill, writeEpochUnreachable: res.writeEpochUnreachable };
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
    let res;
    try {
      res = wasmChangePassphrase(
        head.engine || engine, current, next, treeId, memberId, freshReplica(), head.bytes, floor,
      );
    } catch (e) {
      throw vaultError(e); // a rollback becomes revision_rollback so the gate shows tamper, not wrong-pass
    }
    try {
      await keyringStore().saveHead(docId, head.engine || engine, res.keyring); // the re-wrapped keyring
      await saveWatermark(docId, res.watermark);
      return { recoveryCode: res.recoveryCode };
    } finally {
      res.free();
    }
  },

  /**
   * Rotate the recovery authority (DAG only, OPE-381): retire the current recovery code for a fresh one so a
   * holder of the OLD code can no longer take over the tree. The DEK is unchanged, so a running core keeps
   * working (no new core). Persists the rotated keyring and returns the NEW code + the `resetAuthority` to
   * confirm. The code is PROVISIONAL: on the append-only log a concurrent rotation could win the merge, so
   * keep the OLD code live until `confirmRotationCore` returns true against the synced keyring.
   * `opts`: { passphrase, treeId, memberId, docId, engine? }.
   */
  async rotateRecoveryCore({ passphrase, treeId, memberId, docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const eng = head.engine || engine;
    const floor = await loadWatermark(docId);
    const res = wasmRotateRecovery(eng, passphrase, treeId, memberId, freshReplica(), head.bytes, floor);
    try {
      await keyringStore().saveHead(docId, eng, res.keyring);
      await saveWatermark(docId, res.watermark);
      return { recoveryCode: res.recoveryCode, resetAuthority: res.resetAuthority };
    } finally {
      res.free();
    }
  },

  /**
   * Confirm a rotation survived the merge (DAG only, the two-phase gate): pass the `resetAuthority` from
   * `rotateRecoveryCore`. Returns true iff it is the authority resolved on the CURRENT (synced) keyring — so
   * sync the keyring before calling. False → the rotation was superseded: the new code is void, the OLD code
   * is still live, and the caller must re-rotate. `opts`: { docId, resetAuthority, engine? }.
   */
  async confirmRotationCore({ docId, resetAuthority, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    return wasmRotationConfirmed(head.engine || engine, head.bytes, resetAuthority);
  },

  /**
   * Member-side heal of a rotation-orphaned epoch (DAG only, OPE-381 / F3): open an epoch the owner can't
   * read (its RRK wrap targets the retired escrow) and re-wrap its DEK to the current escrow. Idempotent
   * (`backfilled` false when there is nothing to heal) — safe to call whenever `needsRrkBackfill` is set.
   * `opts`: { passphrase, memberKdf: Uint8Array, treeId, memberId, docId, engine? }.
   */
  async backfillRrkCore({ passphrase, memberKdf, treeId, memberId, docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const eng = head.engine || engine;
    const floor = await loadWatermark(docId);
    const res = wasmBackfillRrk(eng, passphrase, memberKdf, treeId, memberId, freshReplica(), head.bytes, floor);
    try {
      if (res.backfilled) {
        await keyringStore().saveHead(docId, eng, res.keyring);
        await saveWatermark(docId, res.watermark);
      }
      return { backfilled: res.backfilled };
    } finally {
      res.free();
    }
  },

  /**
   * The resolved owner identity key on the current keyring (DAG only) — capture it right after a recovery so
   * `confirmRecoveryCore` can later check the recovery survived. Returns a Uint8Array (empty if no owner).
   * `opts`: { docId, engine? }.
   */
  async resolvedOwnerKeyCore({ docId, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    return wasmResolvedOwnerKey(head.engine || engine, head.bytes);
  },

  /**
   * Confirm a recovery survived the merge (DAG only, the superseded-recovery signal): pass the owner key
   * captured via `resolvedOwnerKeyCore` right after recovering. Returns true iff that owner is still the
   * resolved owner on the synced keyring. False → a concurrent rotation voided the recovery, so the owner is
   * locked out and must recover again. `opts`: { docId, ownerKey: Uint8Array, engine? }.
   */
  async confirmRecoveryCore({ docId, ownerKey, engine = KEYRING_ENGINE }) {
    await ensureInit();
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    return wasmRecoveryConfirmed(head.engine || engine, head.bytes, ownerKey);
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
    // Chain retention: the new revision is the first 4 bytes of the pinned watermark (revision‖key_id‖H(DEK)).
    if (eng === 'chain') {
      const revision = new DataView(change.watermark.buffer, change.watermark.byteOffset, 4).getUint32(0);
      await keyringStore().save(docId, revision, change.keyring);
    }
    // A solo→shared transition: the running sealer (built while solo) does NOT sign, so its writes would be
    // rejected by peers. Re-unlock the owner on the shared keyring (the DEK is unchanged) → a signing sealer +
    // the §B3 resolver — so subsequent writes are attributed. Mirrors unlockCore; hydrate preserves the log.
    const re = wasmUnlock(eng, passphrase, treeId, ownerMemberId, freshReplica(), change.keyring, docId);
    try {
      await saveWatermark(docId, re.watermark);
      const nc = new Core(re.takeHandle(), docId, c.persist, c.treeId, eng);
      // Install §B3 verify BEFORE hydrate (see unlockCore): the reopen re-fold must be gated by the membership.
      await installMembership(nc, docId, eng, change.keyring); // the tree is now shared → verify goes live
      await hydrate(nc);
      try { c.handle.free(); } catch { /* old handle already gone */ }
      cores.set(docId, nc);
    } finally {
      re.free();
    }
    // Publish the shared keyring so a member's join can fetch it. Best-effort: if no transport is attached yet,
    // the owner publishes on the next explicit publish / sync — the local state stands. Chain publishes the
    // revision tail; the dag PUTs the full self-contained anchor as the next slot.
    await publishMembership(docId, eng, treeId);
    // Under-grant ordering (OPE-293): on an ADD the keyring op is published FIRST (above), THEN the advisory
    // summary — so the server's coarse ACL never lists the new member before the crypto that authorizes them.
    await pushMembership(docId, eng);
  },

  /**
   * Owner removes a member: forward-secret re-epoch (a fresh DEK the removed member can't reach, re-wrapped
   * only for those who remain), persist the rotated keyring (+ chain per-revision retention), re-open the
   * owner's core under the new epoch (the old sealer can no longer sign), and — dag — author a self-heal
   * cover over the removed member's stored history so a fresh replica still verifies it. The rotated keyring
   * is published (chain) and the cover pushed to the data channel (dag). `opts`: { passphrase, treeId,
   * ownerMemberId, minRevision, removeMemberId, engine? }. Returns nothing — the caller re-reads membership.
   */
  async removeMember(
    docId,
    { passphrase, treeId, ownerMemberId, minRevision = 0, removeMemberId, engine = KEYRING_ENGINE },
  ) {
    const c = core(docId);
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const eng = head.engine || engine;
    // Slice 3 (OPE-421) compact-before-remove: on the CHAIN, the delta look-behind will Drop the departing
    // member's pre-removal deltas on a cold replica (absent at head ⇒ indistinguishable from a backdated
    // forge), so pin what we've already folded FIRST. Pull the latest (adopt any snapshot + fold their landed
    // writes), then force an owner-authored compaction under the PRE-removal epoch (K=1) so the snapshot's
    // covered frontier vouches for their history. A no-op if a snapshot already covers it; the docsync
    // covered-monotonicity guard prevents any regression. Dag preserves removed history via the self-heal
    // cover (authorCover) below instead, so this is chain-only. Best-effort: a transient failure leaves the
    // removal to proceed (the client look-behind still rejects forgeries; only the in-transit-preservation is
    // reduced), and the next owner sync re-pins.
    if (eng === 'chain' && transportFor(docId)) {
      try { await syncData(c, 1); } catch { /* preserve-history is best-effort; removal still proceeds */ }
    }
    const change = wasmRemoveMember(
      eng, head.bytes, passphrase, treeId, ownerMemberId, freshReplica(), minRevision, removeMemberId,
    );
    await keyringStore().saveHead(docId, eng, change.keyring);
    // Chain retention: the new revision is the first 4 bytes of the pinned watermark (revision‖key_id‖H(DEK)).
    if (eng === 'chain') {
      const revision = new DataView(change.watermark.buffer, change.watermark.byteOffset, 4).getUint32(0);
      await keyringStore().save(docId, revision, change.keyring);
    }
    // A removal ROTATES the write epoch, so the owner's running sealer is now stale — its writes would seal
    // under a dead epoch. Re-unlock on the rotated keyring → a signing sealer under the fresh epoch + the
    // refreshed §B3 resolver (the removed member now resolves as a since-removed ever-member). Then, on the
    // dag, author a self-heal cover so that member's already-accepted history stays verifiable on a fresh
    // replay (the chain retains per-revision membership, so its history needs no cover). hydrate reloads the
    // durable log, which is what authorCover sweeps.
    const re = wasmUnlock(eng, passphrase, treeId, ownerMemberId, freshReplica(), change.keyring, docId);
    let nc = null;
    try {
      await saveWatermark(docId, re.watermark);
      nc = new Core(re.takeHandle(), docId, c.persist, c.treeId, eng);
      // Install §B3 verify BEFORE hydrate (see unlockCore): the reopen re-fold under the rotated head must be
      // gated by the membership, or the removed member's forgeries in the mirror re-merge unverified.
      await installMembership(nc, docId, eng, change.keyring);
      await hydrate(nc);
      // Author a self-heal cover over the removed member's stored history (dag; a no-op on the chain, which
      // retains per-revision membership). The cover is written to the local store as a Cover log object, so it
      // rides the next data sync to the remote like any object; `authorCover` returns whether one was authored.
      nc.handle.authorCover();
      await persistBlobs(nc); // persist the cover + rotated state before we swap cores
      try { c.handle.free(); } catch { /* old handle already gone */ }
      cores.set(docId, nc);
    } finally {
      re.free();
    }
    // Under-grant ordering (OPE-293): on a REMOVAL the advisory summary is pushed FIRST — so the server's
    // coarse ACL drops the removed member as early as possible — and only THEN the keyring op below. A crash
    // in between leaves the advisory ACL MORE restrictive than the keyring, never less.
    await pushMembership(docId, eng);
    // Publish the rotated keyring so members adopt the removal. Best-effort.
    await publishMembership(docId, eng, treeId);
    // Push the self-heal cover (and any other pending local objects) to the DATA channel so peers covered-accept
    // the removed member's history. Best-effort: if it fails to land, a later tick re-uploads it (idempotent).
    if (transportFor(docId)) await syncData(nc);
  },

  /**
   * Owner changes an existing member's role (OPE-364): `newRole === 'co-owner'` PROMOTES to the signer set;
   * any other (non-signer) role DEMOTES a co-owner. A role change touches signing authority, NOT keys — no
   * new epoch — so unlike `removeMember` the owner's running core stays valid: NO re-unlock, NO self-heal
   * cover. We only persist the new keyring + watermark and refresh the §B3 resolver + moderators so the new
   * authority takes effect for verify-on-ingest (a promoted co-owner's signed writes now verify; a demoted
   * one's over-authority writes are rejected — hard on the dag via StrongDemote, and hard on the chain via the
   * OPE-421 look-behind, with compact-before-demote above preserving their pre-demote history). `opts`:
   * { passphrase, treeId, ownerMemberId, minRevision, targetMemberId, newRole, engine? }.
   */
  async changeRole(
    docId,
    { passphrase, treeId, ownerMemberId, minRevision = 0, targetMemberId, newRole, engine = KEYRING_ENGINE },
  ) {
    const c = core(docId);
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const eng = head.engine || engine;
    // Slice 3 (OPE-421) compact-before-demote: a DEMOTE lowers the target below Maintainer, so on the chain the
    // delta look-behind will Drop their pre-demote commits on a cold replica (their head role no longer
    // satisfies a Delta). Pin what we've folded FIRST — pull the latest + force an owner-authored compaction
    // (the epoch is unchanged, so this runs on the existing core `c`). Chain demote only; a promote grants
    // authority (nothing to preserve), and the dag voids over-authority ops via StrongDemote. Best-effort.
    if (newRole !== 'co-owner' && eng === 'chain' && transportFor(docId)) {
      try { await syncData(c, 1); } catch { /* preserve-history is best-effort; the demote still proceeds */ }
    }
    const change = wasmChangeRole(
      eng, head.bytes, passphrase, treeId, ownerMemberId, freshReplica(), minRevision, targetMemberId, newRole,
    );
    await keyringStore().saveHead(docId, eng, change.keyring);
    // Chain retention: the new revision is the first 4 bytes of the pinned watermark (revision‖key_id‖H(DEK)).
    // The dag watermark is a concatenation of tip op-ids, not a revision — so this is chain-only.
    if (eng === 'chain') {
      const revision = new DataView(change.watermark.buffer, change.watermark.byteOffset, 4).getUint32(0);
      await keyringStore().save(docId, revision, change.keyring);
    }
    await saveWatermark(docId, change.watermark); // advance the anti-rollback floor to the new revision
    // Refresh the resolver + moderators on the EXISTING core (the epoch is unchanged, so adoptEpochs is a
    // no-op) so the new authority takes effect immediately for verify-on-ingest.
    await refreshMembershipAndEpochs(c, eng, change.keyring);
    // Under-grant ordering (OPE-293): a DEMOTE removes authority → push the (restrictive) summary BEFORE the
    // keyring publish; a PROMOTE grants it → publish the keyring FIRST, then the summary. So the advisory ACL
    // is never less restrictive than the crypto at any crash point.
    const demote = newRole !== 'co-owner';
    if (demote) {
      await pushMembership(docId, eng);
      await publishMembership(docId, eng, treeId);
    } else {
      await publishMembership(docId, eng, treeId);
      await pushMembership(docId, eng);
    }
  },

  /**
   * The invite pin for the current keyring head: { revision, hash } — the owner mints this at invite time so
   * a joiner's genesis-walk can bind the verified history to the exact revision the owner published. Chain
   * only. (The full invite link / s_mac protocol is the sharing UI's job; this is the crypto primitive.)
   */
  async keyringHash(docId) {
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    const revision = (await keyringStore().head(docId))?.revision ?? 1;
    return { revision, hash: wasmKeyringHash(head.bytes) };
  },

  /**
   * The OOB trust pin for the current DAG anchor — the dag analog of `keyringHash`. The owner mints this at
   * invite time and hands it to the joiner out-of-band; the joiner passes it to `joinAsMember({ engine:'dag',
   * pin })`. Opaque bytes (the genesis-op id + recovery authority + invite-time frontier). Dag only.
   */
  async dagAnchorPin(docId) {
    const head = await keyringStore().loadHead(docId);
    if (!head) throw new Error(`no keyring stored for ${docId}`);
    return wasmDagAnchorPin(head.bytes);
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
    // The dag joins over a self-contained anchor verified against an OOB pin; the chain genesis-walks the
    // per-revision keyring history. Both return an OpenResult whose handle is the ready member core.
    const res = engine === 'dag'
      ? await joinDagAnchor(
        { wasm: { unwrapDagKeyring: wasmUnwrapDagKeyring, verifyDagAnchor: wasmVerifyDagAnchor, unlockAsMember: wasmUnlockAsMember }, transport: transportFor(docId), keyringStore: keyringStore() },
        opts,
      )
      : await joinAsMember(
        { wasm: { verifyKeyringWalk: wasmVerifyKeyringWalk, unlockAsMember: wasmUnlockAsMember }, transport: transportFor(docId), keyringStore: keyringStore() },
        opts,
      );
    try {
      await saveWatermark(docId, res.watermark);
      const c = new Core(res.takeHandle(), docId, true, opts.treeId, engine);
      // Install §B3 verify BEFORE hydrate (see unlockCore): the reopen re-fold must be gated by the membership.
      await installMembership(c, docId, engine, (await keyringStore().loadHead(docId)).bytes);
      await hydrate(c);
      cores.set(docId, c);
      return { didKey: res.didKey };
    } finally {
      res.free();
    }
  },

  /**
   * Adopt newer keyring revisions from the server on a shared tree (chain), then refresh this core's §B3
   * resolver + moderators so it verifies against the current membership. Called by the driver before a data
   * sync (keyring-before-data), and after a membership change lands. A no-op on a solo/dag/unshared tree.
   * `treeId` is the tree's 16-byte seam id. Returns { changed }.
   */
  async syncKeyring(docId, treeId) {
    const c = core(docId);
    const head = await keyringStore().loadHead(docId);
    if (!head || (head.engine || KEYRING_ENGINE) !== 'chain' || !transportFor(docId)) {
      return { changed: false };
    }
    const r = await syncKeyringImpl(
      { wasm: { syncKeyring: wasmSyncKeyring, unwrapChainKeyring: wasmUnwrapKeyring }, transport: transportFor(docId), keyringStore: keyringStore() },
      { docId, treeId },
    );
    if (r.changed) {
      // Refresh the resolver AND adopt any rotated epoch (OPE-393) — the same as the sync tick. Using plain
      // installMembership here would leave a remaining member unable to read post-rotation content, silently
      // reintroducing the bug OPE-393 fixes if this standalone method is ever wired to a UI action.
      await refreshMembershipAndEpochs(c, 'chain', (await keyringStore().loadHead(docId)).bytes);
    }
    return { changed: r.changed };
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
    await persistBlobs(c); // durably mirror the new batch (no-op when not persisting)
    if (c.syncing) c.dirty = true; // a commit during a tick → re-run the data sync
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

  /** Run one full tick (keyring-before-data, then reconcile the data channel with the remote). Single-flighted. */
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
    // OPE-407: mint this owner's `trees` row before its FIRST push (keyring PUT + blob PUT both 404 on a
    // missing tree). Driven by the durable needs-create-tree marker (set at provision), gated behind an
    // in-memory flag so it's one store read per session, not per tick. `createTree` is idempotent for the
    // owner; a throw (offline / server down) propagates to the catch below → {state:'error'} → the tick
    // retries. A joining member never set the marker, so this is a no-op read for it.
    if (!c.treeEnsured) {
      if (await needsCreateTree(c.docId)) {
        // `docId` is the tree UUID and `treeKey` (used for blob/keyring keys) is the same 16 bytes in
        // hex — both parse to one Postgres UUID (main.js derives docId = treeIdToUuid(treeId bytes)). So
        // createTree(docId) mints the SAME server tree the blob pushes target.
        await transport.createTree(c.docId);
        await clearNeedsCreateTree(c.docId);
      }
      c.treeEnsured = true; // reached only if createTree didn't throw (or wasn't needed)
    }
    do {
      c.dirty = false;
      if (c.aborted) break;
      await syncKeyringForTick(c); // keyring-before-data: verify the arrivals against the CURRENT membership
      if (c.aborted) break;
      await syncData(c);
    } while (c.dirty);
    if (c.aborted) return { state: 'stopped' }; // torn down mid-tick — don't touch the (maybe-freed) handle
    // OPE-293: flush a signer's pending advisory-summary assert (self-heals a crash/offline/pre-create-tree
    // 404 between the keyring change and the push). A no-op unless this device recorded an unconfirmed intent.
    await flushPendingMembership(c);
    // `anomalies` (quarantined / undecodable / §B3-rejected entries) is surfaced, never swallowed.
    return { state: 'ok', pending: c.handle.pendingCount(), anomalies: c.handle.anomalies() };
  } catch (e) {
    // The transport (main-thread RemoteStore) now throws plain AppErrors, which survive the Comlink hop back
    // into the worker; anything else (an internal tick bug) is normalized. The driver classifies on
    // `error.retriable` and localizes on `error.code` (OPE-418).
    return { state: 'error', error: isAppError(e) ? e : normalizeUnknown(e) };
  } finally {
    c.syncing = false;
  }
}

// One data-channel reconciliation: fetch the shared remote's whole snapshot for this doc, hand it to the
// core's `sync` (which mirrors it in, folds, and returns what the remote is missing), upload that diff, then
// mirror the updated local store to durable storage. The core owns the entire keyspace + head-monotonicity
// decision — this is a dumb ferry that never parses, builds, or compares a key.
async function syncData(c, compactKOverride) {
  const transport = transportFor(c.docId);
  if (!transport) return;
  // The compaction cadence: the global tick K, or a caller override. removeMember forces a compaction (K=1)
  // BEFORE rotating so the departing member's folded history is pinned into an owner-authored snapshot.
  const k = compactKOverride === undefined ? compactK : compactKOverride;
  const localPrefix = c.docId + '/'; // the core's own (per-device) keyspace
  const remotePrefix = c.treeKey + '/'; // the shared (per-tree) keyspace on the remote
  // Fetch the remote's whole snapshot, re-keyed into the core's local namespace for `sync`.
  const remote = [];
  for (const { key } of await transport.blobList(remotePrefix)) {
    if (c.aborted) return;
    const bytes = await transport.blobGet(key);
    if (bytes) remote.push({ key: localPrefix + key.slice(remotePrefix.length), bytes });
  }
  if (c.aborted) return;
  // The tick also compacts once ≥ compactK log objects have accrued since the last snapshot (OPE-409): the
  // fresh snapshot is in `put`, and `covered` is the SUBSUMED frontier to send as the x-openom-covered header
  // on that snapshot upload (the server's GC gate 1 trusts only what a snapshot actually folds).
  const { put, covered } = c.handle.sync(remote, k); // { put: [{ key, bytes, pointer }], folded, covered }
  for (const o of put) {
    if (c.aborted) return;
    // Re-key the core's object back into the shared tree namespace for upload; the snapshot carries the header.
    const coveredHeader = o.key.endsWith('/snapshot') ? covered : undefined;
    await transport.blobPut(remotePrefix + o.key.slice(localPrefix.length), o.bytes, o.pointer, coveredHeader);
  }
  if (c.aborted) return;
  await persistBlobs(c);

  // Report our PULL frontier as gate-2 liveness telemetry so the server's log-GC keeps a slow member's
  // un-pulled log tail alive (OPE-409 gate 2). Advisory + best-effort: only when it advanced (change-guarded),
  // and a failure NEVER fails the tick — the floor just stays conservatively low for this member.
  if (c.aborted) return;
  const pull = c.handle.pullFrontier(); // JSON `{replica_hex: counter}`
  if (pull && pull !== '{}' && pull !== c.reportedFrontier) {
    try {
      await transport.putFrontier(c.treeKey, JSON.parse(pull));
      c.reportedFrontier = pull;
    } catch {
      /* advisory telemetry — swallow; gate 2 stays conservative without this report */
    }
  }
}

// Normalize EVERY exposed method's throws/rejections to a plain AppError BEFORE Comlink's own error handler
// sees them (design B1/B2): Comlink's throwTransferHandler forwards a raw Error's `message`/`name`/`stack`
// across the worker→main boundary by default, so an un-normalized throw would leak an internal stack. A
// method that already threw an AppError passes through unchanged (normalizeUnknown is idempotent); anything
// else becomes `{ code:'internal', domain:'app', cause:<string> }` with NO stack. The main thread catches a
// plain object (not an Error subclass), so its custom fields survive the structured clone.
function guardApi(surface) {
  const guarded = {};
  for (const [name, value] of Object.entries(surface)) {
    guarded[name] =
      typeof value === 'function'
        ? async (...args) => {
            try {
              return await value.apply(surface, args);
            } catch (e) {
              throw normalizeUnknown(e);
            }
          }
        : value;
  }
  return guarded;
}

Comlink.expose(guardApi(api));
