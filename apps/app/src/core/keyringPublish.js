// Client-side OUTBOUND publish of a produced chain keyring revision (OPE-301).
//
// The server endpoint + the inbound pull/verify path already existed; this is the missing outbound half.
// After the vault produces + durably persists a new chain keyring revision (provision / recover /
// changePassphrase), the client wraps it as the engine-neutral `KeyringUpdate` transport envelope (the wasm
// `wrapChainKeyringUpdate` export) and PUTs it to `PUT /trees/{id}/keyring` so peers can pull + chain-verify
// it. The server NEVER parses the keyring — it dispatches to the engine verifier and admits (zero-knowledge
// intact); this is purely a transport step, the mirror of `readKeyring` + `acceptRemoteKeyring`.
//
// This is the concrete assembler for the vault's `publishKeyring` seam (createVault) — kept standalone +
// injected with `remote` (like membershipSummary's pushMembershipSummary) so the vault stays decoupled from
// the server and the tree-id mapping. Offline-safety is the seam's contract (the vault swallows a throw
// after the durable local commit), so this can throw freely.

// Format 16 raw tree-id bytes as a canonical UUID string — the server routes `PUT /trees/{uuid}/keyring`
// on a UUID path segment, while the keyring (and the vault seam) carry the tree id as its 16 bytes.
export function treeIdToUuid(treeId) {
  if (!treeId || treeId.length !== 16) {
    throw new Error(`treeIdToUuid: expected 16 bytes, got ${treeId ? treeId.length : 'none'}`);
  }
  const hex = Array.from(treeId, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Build a `publishKeyring(treeId, keyringBytes)` seam for `createVault` from a crypto worker (its
 * `wrapChainKeyringUpdate`) and a RemoteStore (its `putKeyring`). `toUrlId` maps the seam's 16-byte tree id
 * to the server tree id in the URL (default: canonical UUID).
 *
 * @param {{wrapChainKeyringUpdate: (keyring: Uint8Array) => Promise<Uint8Array>}} worker
 * @param {{putKeyring: (id: string, updateBytes: Uint8Array) => Promise<{revision: number|null}>}} remote
 * @param {(treeId: Uint8Array) => string} [toUrlId]
 * @returns {(treeId: Uint8Array, keyringBytes: Uint8Array) => Promise<{revision: number|null}>}
 */
export function makeKeyringPublisher(worker, remote, toUrlId = treeIdToUuid) {
  if (!worker || !remote) throw new Error('makeKeyringPublisher needs { worker, remote }');
  return async (treeId, keyringBytes) => {
    const update = await worker.wrapChainKeyringUpdate(keyringBytes);
    return remote.putKeyring(toUrlId(treeId), update);
  };
}
