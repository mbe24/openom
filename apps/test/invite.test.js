import { describe, it, expect } from 'vitest';
import { mint, parseLink, claim, verifyClaim, fingerprintSigners } from '../app/src/core/invite.js';

// Two signers; distinct 32-byte author keys.
const OWNER = { memberId: '00000000-0000-0000-0000-0000000000aa', authorPublic: new Uint8Array(32).fill(0xa1) };
const COOWNER = { memberId: '00000000-0000-0000-0000-0000000000bb', authorPublic: new Uint8Array(32).fill(0xb2) };
const signers = [OWNER, COOWNER];

// A would-be member's provisionMember output (simulated — the crypto is tested elsewhere).
const M = {
  memberId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  hpkePublic: new Uint8Array(32).fill(0x11),
  authorPublic: new Uint8Array(32).fill(0x22),
};

const UUID = 'bc4e834a-7856-865c-98f7-7a91502b86bf';
const PINNED_REVISION = 4;
const PINNED_HASH = new Uint8Array(32).fill(0xcd);

async function ownerMints(role = 'Editor') {
  return mint({
    uuid: UUID,
    role,
    signers,
    pinnedRevision: PINNED_REVISION,
    pinnedHash: PINNED_HASH,
    now: 1_000_000,
    ttlMs: 3600_000,
  });
}

describe('invite crypto (two-channel)', () => {
  it('fingerprintSigners is deterministic and order-independent', async () => {
    const a = await fingerprintSigners([OWNER, COOWNER]);
    const b = await fingerprintSigners([COOWNER, OWNER]); // reversed
    expect(a).toBe(b);
    // a different signer set → a different fingerprint
    const c = await fingerprintSigners([OWNER]);
    expect(c).not.toBe(a);
  });

  it('mint → parseLink round-trips, and the server payload never carries the secret', async () => {
    const { link, record, pending, fp } = await ownerMints('Maintainer');
    const parsed = parseLink(link);
    expect(parsed.uuid).toBe(UUID);
    expect(parsed.inviteId).toBe(record.inviteId);
    expect(parsed.fp).toBe(fp);
    expect(parsed.role).toBe('Maintainer'); // the role travels in the link (authentic from the owner)
    expect(parsed.s).toBeInstanceOf(Uint8Array);
    // the server pending payload has NO s / no s_mac — the secret is owner↔invitee only
    expect('s' in pending || 'sMac' in pending).toBe(false);
    expect(pending.role).toBe('Maintainer');
    expect(pending.expiry).toBe(1_000_000 + 3600_000);
    // the head pin round-trips through the link (the joiner's genesis-walk checks the head against it)
    expect(parsed.pinnedRevision).toBe(PINNED_REVISION);
    expect(parsed.pinnedHash).toEqual(PINNED_HASH);
    // and the server pending payload carries NO pin (it's owner↔invitee, over the OOB channel)
    expect('pinnedHash' in pending || 'pinnedRevision' in pending).toBe(false);
  });

  it('mint rejects a missing or malformed head pin', async () => {
    await expect(mint({ uuid: UUID, role: 'Editor', signers, pinnedHash: PINNED_HASH })).rejects.toThrow(/pinnedRevision/);
    await expect(mint({ uuid: UUID, role: 'Editor', signers, pinnedRevision: 1, pinnedHash: new Uint8Array(31) })).rejects.toThrow(/pinnedHash/);
  });

  it('parseLink rejects a link missing the head pin', () => {
    // a link without rev/kh (an older or tampered link) is refused — the pin is mandatory
    const noPin = `https://openom.app/join#tree=${UUID}&invite=x&s=AAAA&fp=y&role=Editor`;
    expect(() => parseLink(noPin)).toThrow(/invalid invite link/);
  });

  it('a genuine claim verifies against the owner record', async () => {
    const { link, record } = await ownerMints('Editor');
    const p = parseLink(link);
    const c = await claim({ s: p.s, inviteId: p.inviteId, uuid: p.uuid, role: p.role, ...M });
    expect(await verifyClaim(record, c)).toBe(true);
  });

  it('rejects a claim with substituted keys (the server-MITM the protocol exists to stop)', async () => {
    const { link, record } = await ownerMints('Editor');
    const p = parseLink(link);
    const c = await claim({ s: p.s, inviteId: p.inviteId, uuid: p.uuid, role: p.role, ...M });
    // a malicious server swaps the invitee's hpke key for one it controls
    const tampered = { ...c, hpkePublic: new Uint8Array(32).fill(0x99) };
    expect(await verifyClaim(record, tampered)).toBe(false);
  });

  it('binds the role: a claim built for a different role than the owner minted fails', async () => {
    const { link, record } = await ownerMints('Editor'); // owner minted role=Editor
    const p = parseLink(link);
    // a claim MAC'd over a different role than the owner's record won't verify (the record's role governs)
    const wrongRole = await claim({ s: p.s, inviteId: p.inviteId, uuid: p.uuid, role: 'Maintainer', ...M });
    expect(await verifyClaim(record, wrongRole)).toBe(false);
    // the correct-role claim verifies
    const ok = await claim({ s: p.s, inviteId: p.inviteId, uuid: p.uuid, role: p.role, ...M });
    expect(await verifyClaim(record, ok)).toBe(true);
  });

  it('binds the account: a claim under a different member_id fails', async () => {
    const { link, record } = await ownerMints('Editor');
    const p = parseLink(link);
    const c = await claim({ s: p.s, inviteId: p.inviteId, uuid: p.uuid, role: p.role, ...M });
    const impostor = { ...c, memberId: '00000000-0000-0000-0000-0000000000ff' };
    expect(await verifyClaim(record, impostor)).toBe(false);
  });

  it('binds the invite/tree: a claim for a different invite id fails', async () => {
    const { record } = await ownerMints('Editor');
    const other = await ownerMints('Editor'); // a different invite (different s + invite_id)
    const p = parseLink(other.link);
    const c = await claim({ s: p.s, inviteId: p.inviteId, uuid: p.uuid, role: p.role, ...M });
    // c is valid for `other`, but replayed against the first record it must fail
    expect(await verifyClaim(record, c)).toBe(false);
  });

  it('parseLink rejects a malformed link', () => {
    expect(() => parseLink('https://openom.app/join#tree=x')).toThrow(/invalid invite link/);
  });
});
