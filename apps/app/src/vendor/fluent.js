// Minimale Fluent-Teilmenge: "key = value" mit { $arg }-Platzhaltern und
// mehrzeiligen Werten. Reicht fuer den Prototyp und haelt die Dateien im
// echten .ftl-Format — beim Bundling ersetzt @fluent/bundle diese Datei 1:1.
export class FluentResource {
  constructor(source) {
    this.messages = new Map();
    let key = null;
    let buffer = [];
    const flush = () => {
      if (key) this.messages.set(key, buffer.join('\n').trim());
      key = null;
      buffer = [];
    };
    for (const rawLine of source.split(/\r?\n/)) {
      const line = rawLine.replace(/\s+$/, '');
      if (!line.trim() || line.trimStart().startsWith('#')) { flush(); continue; }
      const match = line.match(/^([a-zA-Z][\w-]*)\s*=\s*(.*)$/);
      if (match) {
        flush();
        key = match[1];
        buffer = [match[2]];
      } else if (key && /^\s+/.test(rawLine)) {
        buffer.push(line.trim());
      }
    }
    flush();
  }
}

export class FluentBundle {
  constructor(locale) {
    this.locale = locale;
    this.messages = new Map();
  }

  addResource(resource) {
    for (const [k, v] of resource.messages) this.messages.set(k, v);
  }

  getMessage(key) {
    const value = this.messages.get(key);
    return value === undefined ? undefined : { value };
  }

  formatPattern(pattern, args = {}) {
    return pattern.replace(/\{\s*\$([\w-]+)\s*\}/g, (_, name) => {
      const v = args[name];
      return v === undefined || v === null ? '' : String(v);
    });
  }
}
