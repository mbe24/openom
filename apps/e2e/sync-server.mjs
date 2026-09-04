// e2e: the client sync WIRE against the real running server — single-owner produce → PUT → pull → accept.
//
// Not a vitest or Playwright test: a HOST-node script. The vitest runner is dockerized (can't reach the
// host's :6060) and a browser would hit CORS (app origin ≠ server origin), so this runs directly on the
// host against the docker-compose server. It uses the REAL wasm sealer to produce valid sealed Envelopes
// and a real chain keyring, PUTs them to the server (exercising real cas_create + the ChainVerifier + the
// delta log + dev auth + JIT account provisioning), pulls them back, and has a second same-owner device
// unlock and OPEN (accept/verify) them — the whole wire + crypto end to end.
//
// Run it with the compose server up (see docker-compose.yml):
//   node apps/e2e/sync-server.mjs            # defaults to http://localhost:6060
//   OPENOM_SERVER=http://host:port node apps/e2e/sync-server.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, { provision, unlock, wrapChainKeyringUpdate } from '../app/src/vendor/vault/openom_vault.js';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { treeIdToUuid } from '../app/src/core/keyringPublish.js';

const BASE = (process.env.OPENOM_SERVER ?? 'http://localhost:6060').replace(/\/$/, '');
const enc = new TextEncoder();
const dec = new TextDecoder();
let failed = 0;
const ok = (cond, msg) => { console.log(`  ${cond ? '✓' : '✗ FAIL:'} ${msg}`); if (!cond) failed++; };

await init({ module_or_path: readFileSync(fileURLToPath(new URL('../app/src/vendor/vault/openom_vault_bg.wasm', import.meta.url))) });

const TREE = crypto.getRandomValues(new Uint8Array(16)); // this run's tree seam id
const uuid = treeIdToUuid(TREE);
const MEMBER = crypto.randomUUID(); // the dev bearer == the member uuid (fake auth accepts any uuid)
const remote = new RemoteStore({ baseUrl: BASE, auth: () => MEMBER });

console.log(`e2e sync wire → ${BASE}\n  tree ${uuid}\n  member ${MEMBER}`);
ok((await fetch(BASE + '/health').then((r) => r.text()).catch(() => '')) === 'openom ok', 'server healthy');

// device A provisions (chain engine — matches the client + reconcileKeyring)
const p = provision('chain', 'passphrase-A', TREE, MEMBER, crypto.getRandomValues(new Uint8Array(16)));
const keyring = p.keyring; // the genesis keyring anchor
const sealerA = p.takeSealer();
p.free();

// PRODUCE + PUT the snapshot → creates the server tree row (cas_create)
const snap = sealerA.sealEntry('snapshot', 'openom-json', 'none', 0, new Uint8Array(), 0, new Uint8Array(), enc.encode('{"snapshot":true}'));
const snapEnv = snap.envelope;
const h0 = snap.ciphertextHash;
snap.free();
const version = await remote.putSnapshot(uuid, snapEnv, null);
ok(!!version, `tree row created via snapshot PUT (version ${version})`);

// publish the genesis keyring → the real ChainVerifier admits revision 1
const kr = await remote.putKeyring(uuid, wrapChainKeyringUpdate(keyring));
ok(kr.revision === 1, `genesis keyring admitted by the ChainVerifier (revision ${kr.revision})`);

// PRODUCE + append a delta to the log
const d = sealerA.sealEntry('delta', 'openom-ops', 'none', 1, h0, 0, new Uint8Array(), enc.encode('DELTA-PAYLOAD-1'));
const deltaEnv = d.envelope;
d.free();
const seq = await remote.appendLog(uuid, deltaEnv);
ok(seq === 0, `delta appended to the log (seq ${seq})`);
sealerA.free();

// PULL both back
const rs = await remote.readSnapshot(uuid);
ok(rs && rs.bytes.length === snapEnv.length, 'snapshot pulled back');
const log = await remote.readLog(uuid, -1);
ok(log.entries.length === 1, 'delta pulled back from the log');

// ACCEPT: a second SAME-OWNER device unlocks from the keyring and opens (verifies) the pulled bytes
const u = unlock('chain', keyring, 'passphrase-A', TREE, MEMBER, crypto.getRandomValues(new Uint8Array(16)));
const sealerB = u.takeSealer();
u.free();
ok(dec.decode(sealerB.openEntry('snapshot', rs.bytes)) === '{"snapshot":true}', 'device B opened the snapshot');
ok(dec.decode(sealerB.openEntry('delta', log.entries[0].payload)) === 'DELTA-PAYLOAD-1', 'device B opened (accepted) the delta');
sealerB.free();

console.log(failed ? `\ne2e FAILED (${failed} check${failed === 1 ? '' : 's'})` : '\ne2e OK — produce → PUT → pull → accept validated against the real server');
process.exit(failed ? 1 : 0);
