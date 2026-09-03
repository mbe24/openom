// Per-member tree identity — the ONE id, in its two encodings.
//
// The server binds the 16-byte tree id carried INSIDE every signed/sealed payload to the raw
// bytes of the URL's UUID (openom/src/{trees,log,keyring}.rs). So the sealer's scope id and the
// server's resource id are not two ids to reconcile — they are one identity: 16 random bytes
// (the seam id, minted once at provision), whose UUID-string form `treeIdToUuid(bytes)` is the
// URL id, the local doc/keyring key, and the SyncController docId all at once.
//
// The keyring's own tree binding is the ULTIMATE source of truth (any device that legitimately
// holds the keyring already knows the tree's id). This localStorage entry is only a cache so the
// boot/unlock path knows which tree to open BEFORE the keyring is decrypted — it is seeded at
// provision and is re-derivable from the keyring head.
//
// The mint is serialized across tabs (navigator.locks): two tabs of one member both seeing "no id
// yet" at a first provision would otherwise each mint a different id and split the member's one
// tree across two server rows (cas_create accepts both — nothing reconciles them afterwards).

import { treeIdToUuid } from './keyringPublish.js';

const key = (memberId) => `openom.tree.${memberId}`;

function defaultStorage() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem('__treeid_probe__');
      return localStorage;
    }
  } catch {
    /* private mode / Node — fall through */
  }
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v) };
}

const b64 = {
  enc: (bytes) => btoa(String.fromCharCode(...bytes)),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

function read(storage, memberId) {
  try {
    const raw = storage.getItem(key(memberId));
    if (!raw) return null;
    const { seam, uuid } = JSON.parse(raw);
    const bytes = b64.dec(seam);
    if (bytes.length !== 16 || typeof uuid !== 'string') return null;
    return { bytes, uuid };
  } catch {
    return null;
  }
}

function write(storage, memberId, bytes, uuid) {
  try {
    storage.setItem(key(memberId), JSON.stringify({ seam: b64.enc(bytes), uuid }));
  } catch {
    /* best effort — the caller still holds the freshly-minted identity for this session */
  }
}

/**
 * The member's already-minted tree identity, or null if none exists yet (not provisioned).
 * Synchronous — the boot/unlock path uses it to decide the gate before any lock is taken.
 * @returns {{ bytes: Uint8Array, uuid: string } | null}
 */
export function readTreeIdentity(memberId, { storage = defaultStorage() } = {}) {
  if (!memberId) return null;
  return read(storage, memberId);
}

/**
 * Mint-or-read the member's tree identity, serialized across tabs so concurrent first-provisions
 * converge on ONE identity. Call at provision; `readTreeIdentity` suffices at unlock.
 * @returns {Promise<{ bytes: Uint8Array, uuid: string }>}
 */
export async function ensureTreeIdentity(
  memberId,
  {
    storage = defaultStorage(),
    makeBytes = () => crypto.getRandomValues(new Uint8Array(16)),
    locks = typeof navigator !== 'undefined' ? navigator.locks : null,
  } = {},
) {
  if (!memberId) throw new Error('ensureTreeIdentity needs a memberId');
  const existing = read(storage, memberId);
  if (existing) return existing;

  // Mint under a per-member cross-tab lock; re-read inside it so a tab that lost the race adopts
  // the winner's id rather than minting a second one.
  const mint = () => {
    const again = read(storage, memberId);
    if (again) return again;
    const bytes = makeBytes();
    if (bytes.length !== 16) throw new Error('tree seam id must be 16 bytes');
    const uuid = treeIdToUuid(bytes);
    write(storage, memberId, bytes, uuid);
    return { bytes, uuid };
  };
  if (locks?.request) return locks.request(`openom.tree.mint.${memberId}`, mint);
  return mint(); // no navigator.locks (tests / older browsers): best-effort, single-tab-safe
}
