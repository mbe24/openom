// The NATIVE-mode app-core client (OPE-427 Full-A / OPE-429): under Tauri, the DEK + claim engine + local
// store all run natively in the Rust host, and this object drives them over `invoke` — presenting the SAME
// method surface `appCore.worker.js` exposes over Comlink, so `main.js` doesn't know whether it's talking to
// the wasm worker (web) or the native host (Tauri). The web build keeps using the worker; `appCoreWorker()`
// picks between them on `__TAURI__`.
//
// Conventions (must match apps/src-tauri/src/lib.rs):
//  - invoke arg keys are camelCase; Tauri maps them to the snake_case Rust params.
//  - byte arguments (ids, keyrings, hops) cross as number arrays (`Array.from`), Vec<u8> the other way.
//  - result structs derive serde camelCase, so fields arrive as recoveryCode/didKey/… already.
//  - unlock/recover/join do NOT hydrate on the host, so this client bootstraps after them (as the worker's
//    unlockCore does its import+bootstrap) — a no-op on a fresh provision.
//
// STATUS: the local-first lifecycle (provision/unlock/recover/change-passphrase + all claim edits + reads +
// membership) is complete and matches the command surface. The sync path (attachTransport/syncNow) is a
// best-effort port of the worker tick and is the runtime-iteration target — it is only reached when a managed
// backend is configured (startSync() early-returns local-only), so it never blocks the local flow.

import { makeError, normalizeUnknown } from './errorModel.js';

const invoke = () => globalThis.__TAURI__?.core?.invoke;

/** Is this a Tauri (native-host) runtime? */
export function isNativeHost() {
  return typeof globalThis.__TAURI__?.core?.invoke === 'function';
}

// A Vec<u8> argument as the number array Tauri deserializes; passes strings/undefined through untouched.
const bytes = (x) => (x == null ? x : Array.from(x));
// A Vec<u8> result (number array) back to a Uint8Array, the shape the web code expects for keyring bytes.
const u8 = (x) => (x == null ? x : x instanceof Uint8Array ? x : new Uint8Array(x));
// The remote (per-tree) blob-key prefix: the 16 tree-id bytes as lowercase hex — the same mapping main.js uses
// for the tree UUID's byte seam (the worker's `treeKey`). The core's LOCAL keyspace is `{docId}/…`; the shared
// REMOTE is `{treeKey}/…`, so the sync tick re-keys between them (exactly as appCore.worker.js does).
const hexKey = (treeId) => Array.from(treeId, (b) => b.toString(16).padStart(2, '0')).join('');

export function createNativeAppCore() {
  const call = (cmd, args) => {
    const inv = invoke();
    if (!inv) return Promise.reject(makeError('internal', { cause: 'native host unavailable (no __TAURI__.core.invoke)' }));
    return inv(cmd, args).catch((raw) => {
      // Tauri rejects our Err(String) with a structured {code,message} JSON — map it to the SAME AppError the
      // wasm worker throws (via makeError), so the gate's rollback/tamper/wrong-passphrase distinctions and the
      // sync driver's retriable/auth classification survive on native (design-review C1). Anything else falls
      // through to the generic normalizer.
      let parsed = null;
      if (typeof raw === 'string') { try { parsed = JSON.parse(raw); } catch { parsed = null; } }
      else if (raw && typeof raw === 'object') parsed = raw;
      if (parsed && typeof parsed.code === 'string') throw makeError(parsed.code, { cause: parsed.message });
      throw normalizeUnknown(raw);
    });
  };

  // Per-doc network transport (set by attachTransport) + the doc→treeKey map (the remote keyspace prefix,
  // recorded whenever a doc is opened) + a single-flight sync guard + the once-per-session create-tree gate.
  const transports = new Map();
  const treeKeys = new Map();
  const syncing = new Map();
  const treeEnsured = new Set();
  const reportedFrontier = new Map(); // last pull-frontier reported per doc (change-guard for the GC telemetry)
  const remember = (docId, treeId) => treeKeys.set(docId, hexKey(treeId));

  const api = {
    // --- session lifecycle (host owns the DEK; no engine arg — the host picks it) ---
    ping: () => Promise.resolve(true), // the native host is in-process; always alive
    warm: () => Promise.resolve(), // nothing to preload
    hasKeyring: (docId) => call('core_has_keyring', { doc: docId }),

    provisionCore: ({ passphrase, treeId, memberId, docId }) => {
      remember(docId, treeId);
      return call('core_provision', { doc: docId, treeId: bytes(treeId), memberId, passphrase });
    },

    async unlockCore({ passphrase, treeId, memberId, docId }) {
      remember(docId, treeId);
      const out = await call('core_unlock', { doc: docId, treeId: bytes(treeId), memberId, passphrase });
      await call('core_bootstrap', { doc: docId }); // hydrate the durable log (the worker's unlockCore does this)
      return out;
    },

    async recoverCore({ recoveryCode, newPassphrase, treeId, memberId, docId }) {
      remember(docId, treeId);
      const out = await call('core_recover', {
        doc: docId, treeId: bytes(treeId), memberId, recoveryCode, newPassphrase,
      });
      await call('core_bootstrap', { doc: docId });
      return out;
    },

    changePassphraseCore: ({ current, next, treeId, memberId, docId }) =>
      call('core_change_passphrase', {
        doc: docId, treeId: bytes(treeId), memberId, oldPassphrase: current, newPassphrase: next,
      }),

    // The demo/dev core (reserved dev key) is web-only — the native host has no keyless dev path.
    openDev: () => Promise.reject(new Error('the demo (dev) core is not available on the native host')),

    resetCore: (docId) => call('core_reset', { doc: docId }),
    close: (docId) => {
      transports.delete(docId);
      treeKeys.delete(docId);
      treeEnsured.delete(docId);
      reportedFrontier.delete(docId);
      return call('core_close', { doc: docId });
    },

    // --- claim edits (buffered; commit seals them) ---
    assertAnchor: (docId, id, typeUri) => call('core_assert_anchor', { doc: docId, id, typeUri }),
    assertClaim: (docId, target, predicate, valueJson) =>
      call('core_assert_claim', { doc: docId, target, predicate, valueJson }),
    supersedeClaim: (docId, prior, target, predicate, valueJson) =>
      call('core_supersede_claim', { doc: docId, prior, target, predicate, valueJson }),
    removeRecord: (docId, target) => call('core_remove_record', { doc: docId, target }),
    revoke: (docId, removalOpId) => call('core_revoke', { doc: docId, removalOpId }),
    commit: (docId) => call('core_commit', { doc: docId }),
    setModerators: (docId, dids) => call('core_set_moderators', { doc: docId, moderators: dids }),

    // --- reads (JSON strings the web code JSON.parses, matching the wasm veneer) ---
    project: (docId) => call('core_project', { doc: docId }),
    oplog: (docId) => call('core_oplog', { doc: docId }),
    liveRecords: (docId) => call('core_live_records', { doc: docId }),
    liveClaimsOf: (docId, target, predicate) =>
      call('core_live_claims_of', { doc: docId, target, predicate }),
    liveClaimsOfAny: (docId, target) => call('core_live_claims_of_any', { doc: docId, target }),
    resolveId: (docId, anchor) => call('core_resolve_id', { doc: docId, anchor }),
    pendingCount: (docId) => call('core_pending_count', { doc: docId }),
    anomalies: (docId) => call('core_anomalies', { doc: docId }),

    // --- soft-removal review queue (OPE-426) ---
    pendingReviews: async (docId) => JSON.parse(await call('core_pending_reviews', { doc: docId })),
    approvePending: (docId, { replica, counter }) =>
      call('core_approve_pending', { doc: docId, replica, counter }),
    discardPending: (docId, { replica, counter }) =>
      call('core_discard_pending', { doc: docId, replica, counter }),

    // --- membership / sharing (owner + member) ---
    provisionMember: async (passphrase) => {
      const m = await call('core_provision_member', { passphrase });
      return { kdfParams: u8(m.kdfParams), authorPublicKey: u8(m.authorPublicKey), hpkePublicKey: u8(m.hpkePublicKey) };
    },
    async addMember(docId, { passphrase, treeId, ownerMemberId, newMemberId, role, memberAuthorPublic, memberHpkePublic }) {
      const out = await call('core_add_member', {
        doc: docId, treeId: bytes(treeId), ownerMemberId, ownerPassphrase: passphrase,
        member: { memberId: newMemberId, role, authorPublicKey: bytes(memberAuthorPublic), hpkePublicKey: bytes(memberHpkePublic) },
      });
      return { keyring: u8(out.keyring) };
    },
    async removeMember(docId, { passphrase, treeId, ownerMemberId, removeMemberId }) {
      const out = await call('core_remove_member', {
        doc: docId, treeId: bytes(treeId), ownerMemberId, ownerPassphrase: passphrase, removeMemberId,
      });
      return { keyring: u8(out.keyring), historyPreserved: out.historyPreserved };
    },
    async changeRole(docId, { passphrase, treeId, ownerMemberId, targetMemberId, newRole }) {
      const out = await call('core_change_role', {
        doc: docId, treeId: bytes(treeId), ownerMemberId, ownerPassphrase: passphrase, targetMemberId, newRole,
      });
      return { keyring: u8(out.keyring), demote: out.demote };
    },
    async joinAsMember({ docId, treeId, memberId, passphrase, memberKdfParams, hops, pinnedRevision, pinnedHash }) {
      remember(docId, treeId);
      const out = await call('core_join_as_member', {
        doc: docId, treeId: bytes(treeId), memberId, passphrase,
        memberKdfParams: bytes(memberKdfParams), hops: bytes(hops), pinnedRevision, pinnedHash: bytes(pinnedHash),
      });
      await call('core_bootstrap', { doc: docId });
      return out;
    },
    async unlockAsMember({ docId, treeId, memberId, passphrase }) {
      remember(docId, treeId);
      const out = await call('core_unlock_as_member', { doc: docId, treeId: bytes(treeId), memberId, passphrase });
      await call('core_bootstrap', { doc: docId });
      return out;
    },
    syncKeyring: (docId, treeId, hops) =>
      call('core_sync_keyring', { doc: docId, treeId: bytes(treeId), hops: bytes(hops) }),

    // --- sync (only reached when a managed backend is configured — startSync() is local-only otherwise) ---
    attachTransport(docId, transport) {
      transports.set(docId, transport);
    },
    // The DATA-channel tick, ported faithfully from appCore.worker.js::syncData: fetch the shared remote (under
    // the per-tree `{treeKey}/` prefix), re-key it into the core's local `{docId}/` namespace, hand it to
    // core_sync (which mirrors in, folds, compacts, and returns the diff to push — each upload carrying the
    // CORE's pointer flag, never a key this side inspects — plus the covered frontier), then re-key each upload
    // back and PUT it (the snapshot carries the covered GC header). Single-flight; failures degrade to
    // {state:'error'} (the driver treats that as offline), never a crash.
    //
    // NOT YET PORTED (itemized, not hand-waved), tracked as OPE-433/434: the keyring-before-data step (fetch
    // newer keyring revisions → core_sync_keyring — needed for a SHARED tree's members to adopt rotations on
    // sync, and the owner PUBLISH of a produced revision) and the OPE-293 advisory-summary flush. So a SOLO
    // owner syncs fully here; a shared-over-server tree needs those two. (Pull-frontier telemetry: DONE below.)
    async syncNow(docId) {
      const transport = transports.get(docId);
      const treeKey = treeKeys.get(docId);
      if (!transport || !treeKey) return { state: 'no-transport' };
      if (syncing.get(docId)) return { state: 'busy' };
      syncing.set(docId, true);
      try {
        // First push per session: mint this owner's server `trees` row (OPE-407). Idempotent for the owner;
        // a joining member 403s here (the owner already created it), so swallow — its blob PUTs still land.
        if (!treeEnsured.has(docId)) {
          try { await transport.createTree(docId); } catch { /* member / already exists */ }
          treeEnsured.add(docId);
        }
        const localPrefix = `${docId}/`;
        const remotePrefix = `${treeKey}/`;
        // PULL: the shared remote, re-keyed into the core's local namespace.
        const remote = [];
        for (const { key } of await transport.blobList(remotePrefix)) {
          const b = await transport.blobGet(key);
          if (b) remote.push([localPrefix + key.slice(remotePrefix.length), Array.from(b)]);
        }
        // The core owns the whole keyspace + head-monotonicity decision; this is a dumb ferry.
        const { uploads, covered } = await call('core_sync', { doc: docId, remote, compactK: 8 });
        // PUSH: re-key each upload back to the shared namespace; the CORE decided pointer; the snapshot carries
        // the covered header (a well-known object key — the one key the worker itself checks, for the header).
        for (const o of uploads) {
          const remoteKey = remotePrefix + o.key.slice(localPrefix.length);
          const coveredHeader = o.key.endsWith('/snapshot') ? covered : undefined;
          await transport.blobPut(remoteKey, new Uint8Array(o.bytes), o.pointer, coveredHeader);
        }
        // Report the pull frontier for GC gate-2 liveness (OPE-409): change-guarded + best-effort — a failure
        // NEVER fails the tick, the floor just stays conservatively low for this member without the report.
        try {
          const frontier = await call('core_pull_frontier', { doc: docId });
          const sig = JSON.stringify(frontier);
          if (sig !== '{}' && sig !== reportedFrontier.get(docId)) {
            await transport.putFrontier(treeKey, frontier);
            reportedFrontier.set(docId, sig);
          }
        } catch { /* advisory telemetry — swallow; gate 2 stays conservative without it */ }
        return { state: 'ok', anomalies: await api.anomalies(docId) };
      } catch (err) {
        return { state: 'error', error: err };
      } finally {
        syncing.set(docId, false);
      }
    },
  };
  return api;
}
