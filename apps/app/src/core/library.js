import { FamilyTree } from './familyTree.js';
import { seedOps, SEED_FOCUS } from './seed.js';
import { khaldunOps, KHALDUN_FOCUS } from './seedKhaldun.js';
import { shadowParity } from './treelog/project.js';

/** Die mitgelieferten Baeume. Jeder liegt in einem eigenen Dokument. */
export const DATASETS = [
  { id: 'bach', doc: 'tree-1', label: 'Bach', ops: seedOps, focus: SEED_FOCUS },
  { id: 'khaldun', doc: 'tree-khaldun', label: 'ابن خلدون', ops: khaldunOps, focus: KHALDUN_FOCUS }
];
export const dataset = (id) => DATASETS.find((d) => d.id === id) ?? DATASETS[0];

/** Die Sammlung der Baeume. Traegt den Lebenszyklus, nicht der Baum selbst. */
export class TreeLibrary {
  #store;
  #open = new Map();

  constructor(store) {
    this.#store = store;
  }

  async list() {
    return this.#store.list();
  }

  async open(docId = 'tree-1') {
    if (this.#open.has(docId)) return this.#open.get(docId);
    const tree = new FamilyTree(this.#store, docId);
    await tree.hydrate();
    this.#open.set(docId, tree);
    void shadowParity(tree); // dark, flag-gated, fire-and-forget; no-op unless openom.engine=shadow
    return tree;
  }

  async create(docId = 'tree-' + Date.now()) {
    const tree = new FamilyTree(this.#store, docId);
    this.#open.set(docId, tree);
    return tree;
  }

  async openSeeded(datasetId = 'bach') {
    const set = dataset(datasetId);
    const tree = await this.open(set.doc);
    if (tree.people.size === 0) {
      await tree.seed(set.ops());
      void shadowParity(tree); // re-check after seeding a fresh demo tree (open() saw it empty)
    }
    return { tree, focusId: set.focus, datasetId: set.id };
  }

  async reseed(tree, datasetId = 'bach') {
    const set = dataset(datasetId);
    await tree.reset();
    await tree.seed(set.ops());
    return set.focus;
  }

  close(docId) {
    this.#open.delete(docId);
  }
}
