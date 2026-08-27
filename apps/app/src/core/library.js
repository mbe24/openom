import { FamilyTree, seedAppId } from './familyTree.js';
import { tabSync } from './tabSync.js';
import { seedOps, SEED_FOCUS } from './seed.js';
import { khaldunOps, KHALDUN_FOCUS } from './seedKhaldun.js';

// The claim-based engine is the app's only family-tree engine; the former treelog fallback (and its
// localStorage['openom.engine'] toggle) was dropped at the cutover. seedAppId maps a symbolic seed id
// to its stable app-facing anchor id.
export { seedAppId };

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
    const tree = new FamilyTree(this.#store, docId, this.#schema);
    await tree.hydrate();
    return this.#track(docId, tree);
  }

  async create(docId = 'tree-' + Date.now()) {
    return this.#track(docId, new FamilyTree(this.#store, docId, this.#schema));
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
