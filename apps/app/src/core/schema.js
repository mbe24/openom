// Custom-Fields: einmal definiert, dann in der Erfassungsmaske gleichrangig
// mit den eingebauten Feldern.
const DEFAULTS = [
  { id: 'occupation', label: 'Occupation', type: 'text' },
  { id: 'emigrated', label: 'Emigrated', type: 'boolean' },
  { id: 'confession', label: 'Confession', type: 'option', options: ['Lutheran', 'Catholic', 'Reformed', 'Other'] }
];

export class SchemaRegistry {
  #fields = DEFAULTS.map((f) => ({ ...f }));
  #listeners = new Set();

  fields() { return this.#fields.map((f) => ({ ...f })); }
  field(id) { return this.#fields.find((f) => f.id === id); }

  onChange(fn) { this.#listeners.add(fn); return () => this.#listeners.delete(fn); }
  #bump() { for (const fn of this.#listeners) fn(); }

  define(def) {
    const id = def.id || def.label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
    if (!id) throw new Error('field needs a label');
    if (this.field(id)) throw new Error('field exists: ' + id);
    this.#fields.push({ id, label: def.label, type: def.type ?? 'text', options: def.options });
    this.#bump();
    return this.field(id);
  }

  update(id, patch) {
    const f = this.field(id);
    if (f) Object.assign(f, patch);
    this.#bump();
    return f;
  }

  /** Loeschen entfernt die Definition, nicht die Werte — kein stiller Datenverlust. */
  remove(id) {
    this.#fields = this.#fields.filter((f) => f.id !== id);
    this.#bump();
  }

  usage(tree, id) {
    return tree.allPeople().filter((p) => {
      const v = p.custom && p.custom[id];
      return v !== undefined && v !== '' && v !== false;
    }).length;
  }
}
