// BlobStore: Dateien liegen inhaltsadressiert NEBEN dem Dokument, nie darin.
// Ein CRDT-Delta traegt so ein paar hundert Byte statt einer Bilddatei, und
// derselbe Scan zweimal hochgeladen ergibt denselben Hash — also einen Eintrag.
//
// Zwei Implementierungen mit identischer Semantik, wie beim DocStore:
// im Browser im Speicher, in Tauri eine blobs-Tabelle in SQLite.

export async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export class MemoryBlobStore {
  #blobs = new Map();   // hash -> { bytes, mime, w, h, created }
  #urls = new Map();    // hash -> objectURL

  caps() {
    return { durable: false, remote: false };
  }

  async put(bytes, meta = {}) {
    const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const hash = await sha256(data);
    if (!this.#blobs.has(hash)) {
      this.#blobs.set(hash, {
        bytes: data, mime: meta.mime ?? 'application/octet-stream',
        w: meta.w ?? null, h: meta.h ?? null, created: new Date().toISOString()
      });
    }
    return hash;
  }

  async has(hash) { return this.#blobs.has(hash); }

  async meta(hash) {
    const b = this.#blobs.get(hash);
    return b ? { mime: b.mime, w: b.w, h: b.h, size: b.bytes.length, created: b.created } : null;
  }

  async get(hash) {
    const b = this.#blobs.get(hash);
    return b ? new Blob([b.bytes], { type: b.mime }) : null;
  }

  /** Stabile URL je Hash — mehrfaches Rendern erzeugt keine neuen Objekte. */
  async url(hash) {
    if (this.#urls.has(hash)) return this.#urls.get(hash);
    const blob = await this.get(hash);
    if (!blob) return null;
    const url = URL.createObjectURL(blob);
    this.#urls.set(hash, url);
    return url;
  }

  async delete(hash) {
    const url = this.#urls.get(hash);
    if (url) { URL.revokeObjectURL(url); this.#urls.delete(hash); }
    this.#blobs.delete(hash);
  }

  async list() { return [...this.#blobs.keys()]; }
}

/** Rust-Seite: blobs(hash TEXT PRIMARY KEY, mime, w, h, bytes BLOB, created). */
export class TauriBlobStore {
  #invoke;
  #urls = new Map();

  constructor(invoke) { this.#invoke = invoke; }

  caps() { return { durable: true, remote: false }; }

  async put(bytes, meta = {}) {
    const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return this.#invoke('blob_put', {
      args: { bytes: Array.from(data), mime: meta.mime ?? null, w: meta.w ?? null, h: meta.h ?? null }
    });
  }

  async has(hash) { return this.#invoke('blob_has', { hash }); }
  async meta(hash) { return this.#invoke('blob_meta', { hash }); }

  async get(hash) {
    const res = await this.#invoke('blob_get', { hash });
    return res ? new Blob([new Uint8Array(res.bytes)], { type: res.mime }) : null;
  }

  async url(hash) {
    if (this.#urls.has(hash)) return this.#urls.get(hash);
    const blob = await this.get(hash);
    if (!blob) return null;
    const url = URL.createObjectURL(blob);
    this.#urls.set(hash, url);
    return url;
  }

  async delete(hash) {
    const url = this.#urls.get(hash);
    if (url) { URL.revokeObjectURL(url); this.#urls.delete(hash); }
    return this.#invoke('blob_delete', { hash });
  }

  async list() { return this.#invoke('blob_list'); }
}

export function createBlobStore() {
  const invoke = globalThis.__TAURI__?.core?.invoke;
  if (invoke) return { blobs: new TauriBlobStore(invoke), kind: 'sqlite (rust)' };
  return { blobs: new MemoryBlobStore(), kind: 'memory (browser)' };
}

/**
 * Bild aufnehmen: auf Kantenlaenge herunterrechnen und als JPEG ablegen.
 * Der Zuschnitt wird NICHT eingebrannt — er lebt als crop am MediaLink, damit
 * dasselbe Foto im Baum das Gesicht und in der Galerie das ganze Bild zeigt.
 */
export async function ingestImage(blobStore, file, { max = 1024 } = {}) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
  const w = Math.round(bitmap.width * scale);
  const h = Math.round(bitmap.height * scale);
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
  bitmap.close?.();
  const blob = await new Promise((res) => canvas.toBlob(res, 'image/jpeg', 0.86));
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const hash = await blobStore.put(bytes, { mime: 'image/jpeg', w, h });
  return { hash, mime: 'image/jpeg', w, h, bytes: bytes.length };
}
