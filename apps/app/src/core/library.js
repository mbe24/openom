import { FamilyTree, seedAppId } from './familyTree.js';
import { workerEngine } from './tree/workerEngine.js';
import { seedOps, SEED_FOCUS } from './seed.js';
import { khaldunOps, KHALDUN_FOCUS } from './seedKhaldun.js';

// The claim-based engine (now the app-core Web Worker) is the app's only family-tree engine. seedAppId
// maps a symbolic seed id to its stable app-facing anchor id.
export { seedAppId };

/** Die mitgelieferten Baeume. Jeder liegt in einem eigenen Dokument. */
export const DATASETS = [
  { id: 'bach', doc: 'tree-1', label: 'Bach', ops: seedOps, focus: SEED_FOCUS },
  { id: 'khaldun', doc: 'tree-khaldun', label: 'ابن خلدون', ops: khaldunOps, focus: KHALDUN_FOCUS }
];
export const dataset = (id) => DATASETS.find((d) => d.id === id) ?? DATASETS[0];

/** Die Sammlung der Baeume. Traegt den Lebenszyklus, nicht der Baum selbst. Each tree is a `FamilyTree`
 *  view-model over a `workerEngine` bound to its doc — the worker core (opened by provision/unlock) owns
 *  the engine, DEK, sync, and durable store. `createdBy` is that core's author did:key. */
export class TreeLibrary {
  #worker;
  #schema;
  #open = new Map();

  constructor(worker, schema = null) {
    this.#worker = worker;
    this.#schema = schema;
  }

  async list() {
    return [...this.#open.keys()];
  }

  #build(docId, createdBy) {
    const tree = new FamilyTree(workerEngine(this.#worker, docId), docId, this.#schema, createdBy);
    this.#open.set(docId, tree);
    return tree;
  }

  async open(docId, createdBy = null) {
    if (this.#open.has(docId)) return this.#open.get(docId);
    const tree = this.#build(docId, createdBy);
    await tree.hydrate(); // materialize the worker core's already-hydrated projection
    return tree;
  }

  async create(docId, createdBy = null) {
    return this.#build(docId, createdBy);
  }

  async openSeeded(datasetId = 'bach', createdBy = null) {
    const set = dataset(datasetId);
    const tree = await this.open(set.doc, createdBy);
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
    this.#open.delete(docId);
    try {
      this.#worker.close(docId); // frees the worker core (drops the DEK it holds)
    } catch {
      /* best-effort */
    }
  }
}
