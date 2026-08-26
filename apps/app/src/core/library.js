import { FamilyTree, seedAppId as treelogSeedAppId } from './familyTree.js';
import { ClaimFamilyTree, seedAppId as claimSeedAppId } from './claimFamilyTree.js';
import { tabSync } from './tabSync.js';
import { seedOps, SEED_FOCUS } from './seed.js';
import { khaldunOps, KHALDUN_FOCUS } from './seedKhaldun.js';

// Engine selection during the claim-model migration (OPE-201): the claim-based engine is opt-in via
// localStorage['openom.engine'] === 'claim'; the default stays the treelog engine until the cutover
// (OPE-178). Both share the same public surface, so only the factory + the seed-id helper differ.
function useClaimEngine() {
  try { return globalThis.localStorage?.getItem('openom.engine') === 'claim'; } catch { return false; }
}
const Engine = () => (useClaimEngine() ? ClaimFamilyTree : FamilyTree);
export const seedAppId = (s) => (useClaimEngine() ? claimSeedAppId(s) : treelogSeedAppId(s));

/** Die mitgelieferten Baeume. Jeder liegt in einem eigenen Dokument. */
export const DATASETS = [
  { id: 'bach', doc: 'tree-1', label: 'Bach', ops: seedOps, focus: SEED_FOCUS },
  { id: 'khaldun', doc: 'tree-khaldun', label: 'ابن خلدون', ops: khaldunOps, focus: KHALDUN_FOCUS }
];
export const dataset = (id) => DATASETS.find((d) => d.id === id) ?? DATASETS[0];

/** Die Sammlung der Baeume. Traegt den Lebenszyklus, nicht der Baum selbst. */
export class TreeLibrary {
  #store;
  #schema;
  #open = new Map();
  #ticks = new Map(); // docId -> cross-tab tabSync cleanup

  constructor(store, schema = null) {
    this.#store = store;
    this.#schema = schema;
  }

  async list() {
    return this.#store.list();
  }

  #track(docId, tree) {
    this.#open.set(docId, tree);
    this.#ticks.set(docId, tabSync(tree, docId));
    return tree;
  }

  async open(docId = 'tree-1') {
    if (this.#open.has(docId)) return this.#open.get(docId);
    const tree = new (Engine())(this.#store, docId, this.#schema);
    await tree.hydrate();
    return this.#track(docId, tree);
  }

  async create(docId = 'tree-' + Date.now()) {
    return this.#track(docId, new (Engine())(this.#store, docId, this.#schema));
  }

  async openSeeded(datasetId = 'bach') {
    const set = dataset(datasetId);
    const tree = await this.open(set.doc);
    if (tree.people.size === 0) await tree.seed(set.ops());
    return { tree, focusId: seedAppId(set.focus), datasetId: set.id };
  }

  async reseed(tree, datasetId = 'bach') {
    const set = dataset(datasetId);
    await tree.reset();
    await tree.seed(set.ops());
    return seedAppId(set.focus);
  }

  close(docId) {
    this.#ticks.get(docId)?.();
    this.#ticks.delete(docId);
    this.#open.delete(docId);
  }
}
