// Cross-tab local convergence with NO server (OPE-197). Two tabs of the same origin share one local
// DocStore (IndexedDB), but a write in one tab is invisible to the other until it reloads. This adds a
// small tick: when this tab appends to the store, it pings the other tabs over a BroadcastChannel; on a
// ping for a doc a tab has open, that tab merges the store's tail. Set-union makes the tail replay
// idempotent, so the loop is dumb and safe. This is the local-only transport — the SyncController still
// owns server sync; the two compose (the server delivers cross-device, this delivers cross-tab).
const CHANNEL = 'openom.tab-sync';

/**
 * Wire a tree to the cross-tab tick for `docId`. Returns a cleanup function. A no-op where there is no
 * BroadcastChannel (non-browser) or the engine has no syncTail (the legacy treelog engine — those tabs
 * keep converging on reload only, as before).
 */
export function tabSync(tree, docId) {
  if (typeof BroadcastChannel === 'undefined' || typeof tree.syncTail !== 'function') return () => {};
  const channel = new BroadcastChannel(CHANNEL);
  // A locally-produced delta means we just appended — tell the other tabs to catch up. (Remote merges
  // and syncTail do not emit onDelta, so this never echoes a merge back out.)
  const offDelta = tree.onDelta(() => channel.postMessage({ docId }));
  channel.onmessage = (e) => { if (e.data?.docId === docId) tree.syncTail(); };
  return () => { offDelta(); channel.close(); };
}
