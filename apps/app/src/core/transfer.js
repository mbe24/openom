// Import und Export formatunabhaengig. GEDCOM ist eine Registrierung,
// kein Name in der Architektur.
export class UnsupportedFormatError extends Error {
  constructor(id) { super('format not supported yet: ' + id); this.name = 'UnsupportedFormatError'; }
}

export const OpenomJsonFormat = {
  id: 'openom-json',
  label: 'openom JSON',
  extensions: ['.openom.json', '.json'],
  caps: { import: true, export: true, lossless: true },
  async parse(bytes) {
    const data = JSON.parse(new TextDecoder().decode(bytes));
    return {
      staged: { people: data.people ?? [], families: data.families ?? [] },
      diagnostics: []
    };
  },
  async serialize(tree) {
    const json = JSON.stringify({ format: 'openom-json', version: 1, ...tree.toJSON() }, null, 2);
    return new TextEncoder().encode(json);
  }
};

export const GedcomFormat = {
  id: 'gedcom-7',
  label: 'GEDCOM 7.0',
  extensions: ['.ged'],
  caps: { import: false, export: false, lossless: false },
  async parse() { throw new UnsupportedFormatError('gedcom-7'); },
  async serialize() { throw new UnsupportedFormatError('gedcom-7'); }
};

export class TreeTransfer {
  #formats;
  #tree;

  constructor(tree, formats = [OpenomJsonFormat, GedcomFormat]) {
    this.#tree = tree;
    this.#formats = formats;
  }

  formats() {
    return this.#formats.map((f) => ({ id: f.id, label: f.label, extensions: f.extensions, caps: f.caps }));
  }

  #find(id) {
    const f = this.#formats.find((x) => x.id === id);
    if (!f) throw new UnsupportedFormatError(id);
    return f;
  }

  detect(fileName) {
    const lower = fileName.toLowerCase();
    const hit = this.#formats.find((f) => f.extensions.some((e) => lower.endsWith(e)));
    return hit ? hit.id : null;
  }

  /** Liest und prueft, schreibt nichts — der Report ist der Bestaetigungsschritt. */
  async parse(file, formatId = null) {
    const id = formatId ?? this.detect(file.name ?? '') ?? 'openom-json';
    const fmt = this.#find(id);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const { staged, diagnostics } = await fmt.parse(bytes);
    return {
      formatId: id,
      formatLabel: fmt.label,
      people: staged.people.length,
      families: staged.families.length,
      diagnostics,
      staged
    };
  }

  async apply(report, mode = 'merge') {
    const ops = [];
    if (mode === 'replace') await this.#tree.reset();
    for (const p of report.staged.people) ops.push({ type: 'upsertPerson', id: p.id, fields: p });
    for (const f of report.staged.families) ops.push({ type: 'upsertFamily', id: f.id, fields: f });
    await this.#tree.seed(ops);
    return { people: report.people, families: report.families };
  }

  async export(formatId = 'openom-json') {
    const fmt = this.#find(formatId);
    const bytes = await fmt.serialize(this.#tree);
    return new Blob([bytes], { type: 'application/json' });
  }
}
