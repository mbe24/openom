// e2e: Mode A invite TRANSPORT + crypto against the real server (slice 1). Host-node (the vitest runner
// is dockerized; a browser hits CORS). Proves: owner creates a tree, mints an invite + POSTs the pending
// record, a second account provisionMembers + submits a MAC'd claim, the owner lists it and verifies the
// MAC against its LOCAL mint record (the anti-server-MITM check), and the server enforces member_id==sub.
// The addMember/genesis-walk join is the next slice-1 unit. Run with the compose server up:
//   node apps/e2e/sharing-invite.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, { provision, provisionMember } from '../app/src/vendor/vault/openom_vault.js';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { treeIdToUuid } from '../app/src/core/keyringPublish.js';
import { mint, parseLink, claim, verifyClaim } from '../app/src/core/invite.js';

const BASE = (process.env.OPENOM_SERVER ?? 'http://localhost:6060').replace(/\/$/, '');
const enc = new TextEncoder();
let failed = 0;
const ok = (c, m) => { console.log(`  ${c ? '✓' : '✗ FAIL:'} ${m}`); if (!c) failed++; };
const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Uint8Array.from(Buffer.from(s, 'base64'));

await init({ module_or_path: readFileSync(fileURLToPath(new URL('../app/src/vendor/vault/openom_vault_bg.wasm', import.meta.url))) });

const TREE = crypto.getRandomValues(new Uint8Array(16));
const uuid = treeIdToUuid(TREE);
const OWNER = crypto.randomUUID();
const MEMBER = crypto.randomUUID();
const authed = (token) => (url, opts = {}) =>
  fetch(url, { ...opts, headers: { ...(opts.headers || {}), authorization: `Bearer ${token}`, 'content-type': 'application/json' } });
const of = authed(OWNER);
const mf = authed(MEMBER);

console.log(`invite transport → ${BASE}\n  tree ${uuid}\n  owner ${OWNER}\n  member ${MEMBER}`);
ok((await fetch(BASE + '/health').then((r) => r.text()).catch(() => '')) === 'openom ok', 'server healthy');

// 1. owner provisions + creates the tree row (so the invite endpoint's owner lookup resolves)
const p = provision('chain', 'owner-pass', TREE, OWNER, crypto.getRandomValues(new Uint8Array(16)));
const sealer = p.takeSealer();
p.free();
const snap = sealer.sealEntry('snapshot', 'openom-json', 'none', 0, new Uint8Array(), 0, new Uint8Array(), enc.encode('{}'));
await new RemoteStore({ baseUrl: BASE, auth: () => OWNER }).putSnapshot(uuid, snap.envelope, null);
snap.free();
sealer.free();
ok(true, 'owner created the tree row');

// 2. owner mints an invite (dummy signer set — fp isn't server-checked; the real fp matters at join)
const { link, record, pending } = await mint({
  uuid, role: 'Editor', signers: [{ memberId: OWNER, authorPublic: new Uint8Array(32).fill(7) }],
  now: Date.now(), ttlMs: 3600_000,
});

// 3. owner POSTs the pending invite
let r = await of(`${BASE}/trees/${uuid}/invites`, { method: 'POST', body: JSON.stringify({ invite_id: pending.inviteId, role: pending.role, expiry: pending.expiry }) });
ok(r.ok, `owner minted the invite on the server (HTTP ${r.status})`);

// 4. member: provisionMember + build the MAC'd claim from the parsed link
const mi = provisionMember('member-pass');
const hpke = mi.hpkePublic;
const author = mi.authorPublic;
const parsed = parseLink(link);
ok(parsed.uuid === uuid && parsed.role === 'Editor', 'member parsed the invite link');
const c = await claim({ s: parsed.s, inviteId: parsed.inviteId, uuid: parsed.uuid, role: parsed.role, memberId: MEMBER, hpkePublic: hpke, authorPublic: author });

// 5. member submits the claim (member_id == the member's JWT sub)
r = await mf(`${BASE}/invites/${encodeURIComponent(parsed.inviteId)}/claim`, { method: 'PUT', body: JSON.stringify({ member_id: MEMBER, hpke_public: b64(c.hpkePublic), author_public: b64(c.authorPublic), tag: b64(c.tag) }) });
ok(r.status === 204, `member submitted the claim (HTTP ${r.status})`);

// the server enforces member_id == JWT sub: the OWNER trying to claim as MEMBER is refused
r = await of(`${BASE}/invites/${encodeURIComponent(parsed.inviteId)}/claim`, { method: 'PUT', body: JSON.stringify({ member_id: MEMBER, hpke_public: b64(c.hpkePublic), author_public: b64(c.authorPublic), tag: b64(c.tag) }) });
ok(r.status === 403, `a claim whose member_id != the JWT sub is refused (HTTP ${r.status})`);

// 6. owner lists + verifies the claim MAC against its LOCAL mint record (the anti-MITM check)
r = await of(`${BASE}/trees/${uuid}/invites`, { method: 'GET' });
const list = await r.json();
ok(list.length === 1 && list[0].claim, 'owner sees exactly one claimed invite');
const cv = list[0].claim;
const verified = await verifyClaim(record, { memberId: cv.member_id, hpkePublic: unb64(cv.hpke_public), authorPublic: unb64(cv.author_public), tag: unb64(cv.tag) });
ok(verified, 'owner verifies the claim MAC (proves the server did not substitute the member key)');
// a server that swapped the key is caught:
const forged = await verifyClaim(record, { memberId: cv.member_id, hpkePublic: new Uint8Array(32).fill(0x99), authorPublic: unb64(cv.author_public), tag: unb64(cv.tag) });
ok(!forged, 'a substituted member key fails the owner MAC check');

console.log(failed ? `\ninvite transport FAILED (${failed})` : '\ninvite transport + crypto OK against the real server');
process.exit(failed ? 1 : 0);
