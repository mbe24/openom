// The two-channel invite crypto for Mode A sharing — pure WebCrypto, no server, no wasm.
// See plan/sharing/design.mode-a-client-flow.md §2. The security boundary:
//   * the link secret `s` is KDF-split into `s_mac` (HKDF); `s_mac` authenticates the invitee's key to
//     the owner via HMAC and NEVER reaches the server. The owner admits from a LOCAL mint record.
//   * the MAC binds invite_id ‖ uuid ‖ role ‖ member_id ‖ hpke_public ‖ author_public (length-prefixed),
//     so a server can't swap the account, the keys, the role, or replay across trees/invites.
//   * a leaked link is a bearer token (a family-app-acceptable decision) — hardened server-side (email
//     pin + expiry + one-live-claim), not here.
// The signer FINGERPRINT `fp` (a hash of the tree's signer set) travels in the link too, so the joiner
// can cross-check it against the head it walks to from genesis (§4). Everything is async (crypto.subtle)
// and injectable (`subtle`, `makeBytes`, `now`) for tests.

const enc = new TextEncoder();

const b64u = {
  enc: (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => {
    const t = s.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
  },
};

function bytesOf(x) {
  return typeof x === 'string' ? enc.encode(x) : x;
}

// Unambiguous concatenation: each field prefixed by its u32-BE byte length.
function framed(...parts) {
  const bufs = parts.map(bytesOf);
  const out = new Uint8Array(bufs.reduce((n, b) => n + 4 + b.length, 0));
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const b of bufs) {
    dv.setUint32(off, b.length, false);
    off += 4;
    out.set(b, off);
    off += b.length;
  }
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const MAC_INFO = 'openom:invite:mac';

async function hkdf(subtle, ikm, info) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function hmac(subtle, keyBytes, data) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, data));
}

async function sha256(subtle, data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

async function macTag(subtle, sMac, { inviteId, uuid, role, memberId, hpkePublic, authorPublic }) {
  return hmac(subtle, sMac, framed(inviteId, uuid, role, memberId, hpkePublic, authorPublic));
}

/**
 * Canonical fingerprint of a tree's signer set: SHA-256 over the signers SORTED by member id, each
 * as framed(member_id ‖ author_public), base64url. Both the owner (at mint/admit) and the member
 * (after the genesis-walk) must produce identical bytes, so the encoding is pinned here.
 * @param {{memberId: string, authorPublic: Uint8Array}[]} signers
 */
export async function fingerprintSigners(signers, { subtle = crypto.subtle } = {}) {
  const sorted = [...signers].sort((a, b) => (a.memberId < b.memberId ? -1 : a.memberId > b.memberId ? 1 : 0));
  const parts = sorted.map((s) => framed(s.memberId, s.authorPublic));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const cat = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { cat.set(p, off); off += p.length; }
  return b64u.enc(await sha256(subtle, cat));
}

/**
 * Owner: mint an invite. Returns the shareable `link`, the LOCAL mint `record` (persist DEK-sealed —
 * admit reads ONLY this), and the `pending` payload for the server (which never sees `s`).
 * @param {{ uuid: string, role: string, signers: object[], recipientPin?: string|null, ttlMs?: number,
 *   base?: string, now?: number, subtle?: SubtleCrypto, makeBytes?: (n:number)=>Uint8Array }} o
 */
export async function mint({
  uuid,
  role,
  signers,
  recipientPin = null,
  ttlMs = 7 * 24 * 3600 * 1000,
  base = 'https://openom.app',
  now = Date.now(),
  subtle = crypto.subtle,
  makeBytes = (n) => crypto.getRandomValues(new Uint8Array(n)),
}) {
  const s = makeBytes(32);
  const sMac = await hkdf(subtle, s, MAC_INFO);
  const inviteId = b64u.enc(makeBytes(16));
  const fp = await fingerprintSigners(signers, { subtle });
  const expiry = now + ttlMs;
  const q = `tree=${encodeURIComponent(uuid)}&invite=${encodeURIComponent(inviteId)}&s=${b64u.enc(s)}` +
    `&fp=${encodeURIComponent(fp)}&role=${encodeURIComponent(role)}`;
  return {
    inviteId,
    fp,
    link: `${base}/join#${q}`,
    record: { inviteId, uuid, role, sMac, recipientPin, fp, expiry }, // LOCAL only
    pending: { inviteId, uuid, role, recipientPin, expiry }, // to the server — NO s
  };
}

/** Invitee: parse the invite link's fragment. Throws on a malformed link. */
export function parseLink(url) {
  const frag = url.includes('#') ? url.slice(url.indexOf('#') + 1) : '';
  const p = new URLSearchParams(frag);
  const uuid = p.get('tree');
  const inviteId = p.get('invite');
  const sB64 = p.get('s');
  const fp = p.get('fp');
  const role = p.get('role');
  if (!uuid || !inviteId || !sB64 || !fp || !role) throw new Error('invalid invite link');
  return { uuid, inviteId, s: b64u.dec(sB64), fp, role };
}

/**
 * Invitee: build the claim to submit to the server, MAC'd with `s_mac` over its own keys. `s` comes
 * from the parsed link; `role`/`inviteId`/`uuid` too. The server stores this against the pending invite.
 */
export async function claim({ s, inviteId, uuid, role, memberId, hpkePublic, authorPublic }, { subtle = crypto.subtle } = {}) {
  const sMac = await hkdf(subtle, s, MAC_INFO);
  const tag = await macTag(subtle, sMac, { inviteId, uuid, role, memberId, hpkePublic, authorPublic });
  return { inviteId, memberId, hpkePublic, authorPublic, tag };
}

/**
 * Owner: verify a claim's MAC against the LOCAL mint record. The role/uuid/inviteId come from the
 * RECORD, never the claim — so a tampered claim (or a lying server) fails to match and is rejected.
 * @returns {Promise<boolean>}
 */
export async function verifyClaim(record, claim, { subtle = crypto.subtle } = {}) {
  const expected = await macTag(subtle, record.sMac, {
    inviteId: record.inviteId,
    uuid: record.uuid,
    role: record.role,
    memberId: claim.memberId,
    hpkePublic: claim.hpkePublic,
    authorPublic: claim.authorPublic,
  });
  return timingSafeEqual(expected, claim.tag);
}

export const _internal = { framed, b64u, timingSafeEqual };
