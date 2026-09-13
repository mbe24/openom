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

const invoke = () => globalThis.__TAURI__?.core?.invoke;

/** Is this a Tauri (native-host) runtime? */
export function isNativeHost() {
  return typeof globalThis.__TAURI__?.core?.invoke === 'function';
}

// A Vec<u8> argument as the number array Tauri deserializes; passes strings/undefined through untouched.
const bytes = (x) => (x == null ? x : Array.from(x));
// A Vec<u8> result (number array) back to a Uint8Array, the shape the web code expects for keyring bytes.
const u8 = (x) => (x == null ? x : x instanceof Uint8Array ? x : new Uint8Array(x));

export function createNativeAppCore() {
  const call = (cmd, args) => {
    const inv = invoke();
    if (!inv) return Promise.reject(new Error('native host unavailable (no __TAURI__.core.invoke)'));
    return inv(cmd, args);
  };

  // Per-doc network transport (set by attachTransport), for the sync tick. Keyed by docId.
  const transports = new Map();
  const syncing = new Map(); // single-flight guard per doc

  const api = {
    // --- session lifecycle (host owns the DEK; no engine arg — the host picks it) ---
    ping: () => Promise.resolve(true), // the native host is in-process; always alive
    warm: () => Promise.resolve(), // nothing to preload
    hasKeyring: (docId) => call('core_has_keyring', { doc: docId }),

    provisionCore: ({ passphrase, treeId, memberId, docId }) =>
      call('core_provision', { doc: docId, treeId: bytes(treeId), memberId, passphrase }),

    async unlockCore({ passphrase, treeId, memberId, docId }) {
      const out = await call('core_unlock', { doc: docId, treeId: bytes(treeId), memberId, passphrase });
      await call('core_bootstrap', { doc: docId }); // hydrate the durable log (the worker's unlockCore does this)
      return out;
    },

    async recoverCore({ recoveryCode, newPassphrase, treeId, memberId, docId }) {
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
    pendingReviews: (docId) => call('core_pending_reviews', { doc: docId }),
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
      const out = await call('core_join_as_member', {
        doc: docId, treeId: bytes(treeId), memberId, passphrase,
        memberKdfParams: bytes(memberKdfParams), hops: bytes(hops), pinnedRevision, pinnedHash: bytes(pinnedHash),
      });
      await call('core_bootstrap', { doc: docId });
      return out;
    },
    async unlockAsMember({ docId, treeId, memberId, passphrase }) {
      const out = await call('core_unlock_as_member', { doc: docId, treeId: bytes(treeId), memberId, passphrase });
      await call('core_bootstrap', { doc: docId });
      return out;
    },
    syncKeyring: (docId, treeId, hops) =>
      call('core_sync_keyring', { doc: docId, treeId: bytes(treeId), hops: bytes(hops) }),

    // --- sync (only reached when a managed backend is configured — startSync() is local-only otherwise).
    // RUNTIME-ITERATION TARGET: a best-effort port of the worker's data tick. core_sync returns (uploads,
    // folded); the pointer flag is derived from the key convention here (log objects are immutable, heads/
    // snapshot pointers overwrite), and the covered-header GC optimization is not yet threaded through
    // core_sync. Failures degrade to {state:'error'} (the driver treats that as offline), never a crash.
    attachTransport(docId, transport) {
      transports.set(docId, transport);
    },
    async syncNow(docId) {
      const transport = transports.get(docId);
      if (!transport) return { state: 'no-transport' };
      if (syncing.get(docId)) return { state: 'busy' };
      syncing.set(docId, true);
      try {
        // The core's local keyspace is `{docId}/…`; the shared remote is `{treeKey}/…`. main.js derives the
        // doc UUID and the hex tree key from the same 16 bytes, so re-key between them (as the worker does).
        // The tree key is not known here yet — a follow-up threads it through attachTransport; until then this
        // uses the docId prefix on both sides, which the two-host convergence path already exercises.
        const prefix = `${docId}/`;
        const remote = [];
        for (const { key } of await transport.blobList(prefix)) {
          const b = await transport.blobGet(key);
          if (b) remote.push([key, Array.from(b)]);
        }
        const [uploads] = await call('core_sync', { doc: docId, remote, compactK: 8 });
        for (const [key, b] of uploads) {
          const pointer = key.endsWith('/snapshot') || key.includes('/heads/');
          await transport.blobPut(key, new Uint8Array(b), pointer, undefined);
        }
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
