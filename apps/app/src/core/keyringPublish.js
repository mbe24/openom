// Tree-id ↔ UUID mapping for the server's keyring/blob routes. (The outbound keyring-publish assembler that
// once lived here, `makeKeyringPublisher`, was removed as dead — the worker publishes inline via
// `wrapChainKeyringUpdate` + `putKeyring`, and the native host via `core_keyring_publish_payload`.)

// Format 16 raw tree-id bytes as a canonical UUID string — the server routes `PUT /trees/{uuid}/keyring`
// on a UUID path segment, while the keyring (and the vault seam) carry the tree id as its 16 bytes.
export function treeIdToUuid(treeId) {
  if (!treeId || treeId.length !== 16) {
    throw new Error(`treeIdToUuid: expected 16 bytes, got ${treeId ? treeId.length : 'none'}`);
  }
  const hex = Array.from(treeId, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// The inverse: recover the 16 seam bytes from a canonical UUID string. A joining member learns only the
// tree UUID (from the invite link) and needs the seam id back for the sealer/keyring scope.
export function uuidToTreeId(uuid) {
  const hex = String(uuid).replace(/-/g, '');
  if (hex.length !== 32 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error(`uuidToTreeId: expected a UUID, got ${uuid}`);
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

