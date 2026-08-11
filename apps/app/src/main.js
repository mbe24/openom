import { createStore } from './core/store.js';
import { TreeLibrary } from './core/library.js';
import { SchemaRegistry } from './core/schema.js';
import { TreeTransfer } from './core/transfer.js';
import { SessionController, LocalOnlyAuth, syncStatus } from './core/session.js';
import { applyTheme, PRESETS } from './core/theme.js';
import { loadLocale, t, locale } from './core/i18n.js';
import { stats, search } from './core/queries.js';
import { h, mount, toast, fullName } from './ui/dom.js';
import { icons } from './ui/icons.js';
import { isCompact } from './ui/viewport.js';
import { createBlobStore, ingestImage } from './core/blobs.js';
import { shortDate } from './core/dates.js';
import { ancestorsView, resetTreeView } from './views/ancestors.js';
import { fanView } from './views/fan.js';
import { graphView } from './views/graph.js';
import { detailView } from './views/detail.js';
import { editorView } from './views/editor.js';
import { peopleView } from './views/people.js';
import { settingsView } from './views/settings.js';
import { transferView } from './views/transfer.js';
import { onboardingView } from './views/onboarding.js';
import { lockView } from './views/lock.js';

const VIEWS = {
  tree: { render: ancestorsView, title: 'view-ancestors', tab: 'tree' },
  fan: { render: fanView, title: 'view-fan', tab: 'tree' },
  graph: { render: graphView, title: 'view-graph', tab: 'graph' },
  detail: { render: detailView, title: 'view-detail', tab: 'tree' },
  editor: { render: editorView, title: 'view-editor', tab: 'tree' },
  people: { render: peopleView, title: 'view-people', tab: 'people' },
  settings: { render: settingsView, title: 'view-settings', tab: 'settings' },
  transfer: { render: transferView, title: 'view-transfer', tab: 'settings' },
  onboarding: { render: onboardingView, title: 'view-onboarding', tab: 'tree' }
};

class App {
  view = 'tree';
  focusId = null;
  activeFamilyId = null;
  pathTargetId = null;
  peopleSort = 'surname';
  peopleFilter = null;
  viewStack = [];
  datasetId = 'bach';
  // Sperre: im Mockup eine Attrappe, aber mit echtem Ablauf.
  lockEnabled = false;
  lockAfter = 'never';       // 'never' | 5 | 30 (Minuten)
  locked = false;
  graphPanel = true;
  graphZoom = 'fit';
  graphAnchor = null;
  showCollateral = true;
  mode = 'system';
  accentId = 'sage';
  accent = { l: 49.8, c: 0.0444, h: 166.4 };
  accentAdjusted = [];
  importReport = null;
  pendingNewId = null;
  focusReturnId = null;
  paletteOpen = false;
  history = [];

  constructor(root) {
    this.root = root;
    this.schema = new SchemaRegistry();
    const { blobs, kind: blobKind } = createBlobStore();
    this.blobs = blobs;
    this.blobKind = blobKind;
    this.session = new SessionController(new LocalOnlyAuth());
    this.locale = 'en';
  }

  async boot() {
    // Erst hier, weil nur ein Oeffnungsversuch verraet, ob IndexedDB im
    // aktuellen Browsermodus wirklich benutzbar ist.
    const { store, kind } = await createStore();
    this.storeKind = kind;
    this.library = new TreeLibrary(store);
    await loadLocale(this.locale);
    const { tree, focusId } = await this.library.openSeeded(this.datasetId);
    this.tree = tree;
    tree.blobs = this.blobs;   // Bytes bleiben getrennt, aber erreichbar
    this.focusId = focusId;
    this.transfer = new TreeTransfer(tree);
    this.applyAccent();
    tree.onRevision(() => this.render());
    this.schema.onChange(() => this.render());
    window.addEventListener('resize', () => this.render());
    this.watchIdle();
    window.addEventListener('openom:touchmode', () => this.render());
    // Schriften kommen nachtraeglich: danach einmal neu zeichnen, damit
    // Namenskuerzung und Layout mit den echten Metriken rechnen.
    if (document.fonts) {
      document.fonts.addEventListener?.('loadingdone', () => this.render());
      document.fonts.ready.then(() => this.render());
    }
    this.bindKeys();
    this.render();
  }

  get generations() {
    return stats(this.tree).generations;
  }

  applyAccent() {
    const res = applyTheme(this.accent, this.effectiveMode());
    this.accent = res.accent;
    this.accentAdjusted = res.adjusted;
  }

  effectiveMode() {
    if (this.mode !== 'system') return this.mode;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  // ------------------------------------------------------------ commands
  setView(view) {
    // Detail und Editor sind Zwischenstationen: der Weg dorthin wird gestapelt,
    // damit Zurueck Schritt fuer Schritt zurueckfuehrt und der Reiter stimmt.
    const stops = view === 'detail' || view === 'editor';
    if (stops) {
      // Ist das Ziel schon Station auf dem Weg, wird zurueckgesprungen statt
      // nachgeschoben — sonst fuehrt Zurueck in das gerade verlassene Formular.
      const at = this.viewStack.lastIndexOf(view);
      if (at >= 0) this.viewStack.length = at;
      else if (this.view !== view) this.viewStack.push(this.view);
    } else {
      this.viewStack = [];
    }
    // Verlaesst man die Tafel, wird sie beim naechsten Besuch neu zentriert.
    if (this.view === 'tree' && view !== 'tree') resetTreeView();
    this.view = view;
    this.render();
  }
  /** Ansicht, in die der Zurueck-Pfeil fuehrt. */
  get viewOrigin() {
    return this.viewStack.length ? this.viewStack[this.viewStack.length - 1] : null;
  }
  goBack() {
    const prev = this.viewStack.pop() ?? 'tree';
    this.view = prev;
    this.render();
  }
  /** Reiter, der zur aktuellen Ansicht gehoert — bei Detail der Herkunftsreiter. */
  activeTab() {
    const base = this.viewStack.find((v) => v !== 'detail' && v !== 'editor');
    const origin = (this.view === 'detail' || this.view === 'editor') && base;
    return (VIEWS[origin || this.view] ?? VIEWS.tree).tab;
  }
  setFocus(id) {
    if (!id || id === this.focusId) return;
    this.history.push(this.focusId);
    this.focusId = id;
    this.activeFamilyId = null;
    if (this.view === 'editor') this.view = 'detail';
    this.render();
  }
  back() { const prev = this.history.pop(); if (prev) { this.focusId = prev; this.render(); } }
  setActiveFamily(id) { this.activeFamilyId = id; this.render(); }
  setPathTarget(id) { this.pathTargetId = id; this.render(); }
  setPeopleSort(key) { this.peopleSort = key; this.render(); }
  showSiblingsOf(id) {
    this.peopleFilter = { kind: 'siblings', of: id, label: t('label-siblings') };
    this.setView('people');
  }
  showChildrenOf(familyId) {
    this.peopleFilter = { kind: 'children', familyId, label: t('label-children') };
    this.setView('people');
  }
  clearPeopleFilter() { this.peopleFilter = null; this.render(); }
  toggleGraphPanel() { this.graphPanel = this.graphPanel === false; this.render(); }

  setZoom(z) {
    this.graphZoom = z === 'fit' ? 'fit' : Math.min(2.5, Math.max(0.2, z));
    this.render();
  }
  toggleCollateral() { this.showCollateral = !this.showCollateral; this.render(); }
  setMode(mode) { this.mode = mode; this.applyAccent(); this.render(); }
  setAccent(preset) {
    this.accentId = preset.id;
    this.accent = { l: preset.l, c: preset.c, h: preset.h };
    this.applyAccent();
    this.render();
  }
  async setLocale(id) { this.locale = await loadLocale(id); this.render(); }

  async updatePerson(patch, opts) { await this.tree.updatePerson(this.focusId, patch, opts); }

  /**
   * Bild zu einer Person: Bytes in den BlobStore, Metadaten ins Dokument.
   * Getrennt, damit ein Sync spaeter Deltas von Bytes trennt.
   */
  async setPortraitFile(personId, file) {
    if (!file || !/^image\//.test(file.type)) { toast(t('media-not-image')); return; }
    try {
      const meta = await ingestImage(this.blobs, file, { max: 1024 });
      await this.tree.attachMedia(personId, { ...meta, role: 'portrait' });
      this.render();
    } catch (e) {
      toast(String(e.message ?? e));
    }
  }

  async removePortrait(personId) {
    const p = this.tree.portraitOf(personId);
    if (p) { await this.tree.detachMedia(p.link.id); this.render(); }
  }
  async deletePerson() {
    const id = this.focusId;
    this.back();
    await this.tree.deletePerson(id);
  }
  async addParents(sex) {
    this.#rememberFocus();
    // Wer neu ist, ergibt sich aus dem Vorher-Nachher — nicht aus einem leeren
    // Namen: der Vater erbt den Nachnamen des Kindes.
    const priorPair = this.tree.parentsOf(this.focusId);
    const prior = new Set([priorPair.father?.id, priorPair.mother?.id].filter(Boolean));
    const fam = await this.tree.addParents(this.focusId,
      sex === 'M' ? { given: '', surname: this.tree.person(this.focusId)?.surname ?? '', sex: 'M' } : null,
      sex === 'F' ? { given: '', surname: '', sex: 'F' } : null);
    const created = fam.spouses.find((id) => !prior.has(id));
    if (created) { this.pendingNewId = created; this.setFocus(created); this.setView('editor'); }
  }
  async addParentFor(childId, sex) {
    if (!childId) return;
    const prev = this.focusId;
    this.focusId = childId;
    await this.addParents(sex);
    if (!this.focusId) this.focusId = prev;
  }
  async addMarriage() {
    this.#rememberFocus();
    const fam = await this.tree.addMarriage(this.focusId, { given: '', surname: '', sex: 'U' }, {});
    this.activeFamilyId = fam.id;
    const spouse = fam.spouses.find((s) => s !== this.focusId);
    if (spouse) { this.pendingNewId = spouse; this.setFocus(spouse); this.setView('editor'); }
  }
  /** Die Person, zu der etwas angelegt wurde — dorthin kehrt der Fokus zurueck. */
  #rememberFocus() { this.focusReturnId = this.focusId; }

  /** Ehe loesen — Personen bleiben, Undo nimmt es zurueck. */
  async removeMarriage(familyId) {
    await this.tree.removeMarriage(familyId);
    toast(t(isCompact() ? 'rel-marriage-removed-compact' : 'rel-marriage-removed'));
    this.render();
  }
  async detachChild(familyId, personId) {
    await this.tree.unlinkChild(familyId, personId);
    toast(t(isCompact() ? 'rel-child-removed-compact' : 'rel-child-removed'));
    this.render();
  }
  async detachParent(childId, parentId) {
    const fam = this.tree.childFamilyOf(childId);
    if (!fam) return;
    await this.tree.unlinkSpouse(fam.id, parentId);
    toast(t(isCompact() ? 'rel-parent-removed-compact' : 'rel-parent-removed'));
    this.render();
  }
  /** Vorhandene Person als Elternteil eintragen. */
  async linkParent(childId, personId, sex) {
    await this.tree.addParents(childId, sex === 'M' ? personId : null, sex === 'F' ? personId : null);
    this.render();
  }
  /** Vorhandene Person als Partner: neue Ehe, ohne jemanden anzulegen. */
  async linkPartner(personId) {
    await this.tree.addMarriage(this.focusId, personId, {});
    this.render();
  }
  async linkChildTo(familyId, personId) {
    await this.tree.addChild(familyId, personId);
    this.render();
  }

  async addChild(familyId) {
    this.#rememberFocus();
    const child = await this.tree.addChild(familyId, { given: '', surname: this.tree.person(this.focusId)?.surname ?? '', sex: 'U' });
    this.pendingNewId = child.id;
    this.setFocus(child.id);
    this.setView('editor');
  }

  /**
   * Abbrechen darf keine leere Person hinterlassen. Da eine Aktion genau ein
   * Commit ist, nimmt ein Undo Person und Verknuepfung zusammen zurueck.
   */
  async cancelEditor() {
    const id = this.pendingNewId;
    const p = id ? this.tree.person(id) : null;
    const empty = p && !(p.given || '').trim();
    this.pendingNewId = null;
    if (empty && id === this.focusId) {
      await this.tree.undo();
      const parent = this.history.pop();
      if (parent) this.focusId = parent;
      this.activeFamilyId = null;
      this.goBack();
      return;
    }
    if (this.focusReturnId) { this.focusId = this.focusReturnId; this.focusReturnId = null; }
    if (this.viewStack.length) this.goBack(); else this.setView('detail');
  }

  commitEditor() {
    this.pendingNewId = null;
    // Der Blick bleibt bei der Person, zu der man jemanden eingetragen hat.
    if (this.focusReturnId) { this.focusId = this.focusReturnId; this.focusReturnId = null; }
    // Zurueck dorthin, wo das Anlegen begann — aus dem Baum in den Baum.
    if (this.focusReturnId) { this.focusId = this.focusReturnId; this.focusReturnId = null; }
    if (this.viewStack.length) this.goBack(); else this.setView('detail');
  }
  async createFirstPerson(fields) {
    const p = await this.tree.createPerson(fields);
    this.focusId = p.id;
    this.setView('tree');
  }
  async reseed() {
    this.focusId = await this.library.reseed(this.tree, this.datasetId);
    toast(t('action-reset-seed'));
    this.render();
  }

  addField(def) { try { this.schema.define(def); } catch (e) { toast(String(e.message ?? e)); } }
  removeField(id) { this.schema.remove(id); }

  async parseImport(file) {
    try {
      this.importReport = await this.transfer.parse(file);
    } catch (e) {
      this.importReport = null;
      toast(String(e.message ?? e));
    }
    this.render();
  }
  async applyImport(mode) {
    if (!this.importReport) return;
    const res = await this.transfer.apply(this.importReport, mode);
    this.importReport = null;
    toast(res.people + ' people imported');
    this.render();
  }
  clearImport() { this.importReport = null; this.render(); }
  async exportAs(formatId) {
    const blob = await this.transfer.export(formatId);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'openom-tree.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  // ------------------------------------------------------------ keyboard
  bindKeys() {
    window.addEventListener('keydown', async (e) => {
      const meta = e.metaKey || e.ctrlKey;
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName ?? '');
      if (meta && e.key.toLowerCase() === 'k') { e.preventDefault(); this.togglePalette(true); return; }
      if (meta && e.key.toLowerCase() === 'n') { e.preventDefault(); this.setView('onboarding'); return; }
      if (meta && e.key.toLowerCase() === 'z') {
        e.preventDefault();
        if (e.shiftKey) await this.tree.redo(); else await this.tree.undo();
        return;
      }
      if (this.paletteOpen && e.key === 'Escape') { this.togglePalette(false); return; }
      if (typing) return;
      const { father, mother } = this.tree.parentsOf(this.focusId);
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        const target = e.shiftKey ? mother : father;
        if (target) this.setFocus(target.id);
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const kids = this.tree.childrenOf(this.focusId);
        if (kids[0]) this.setFocus(kids[0].id);
        return;
      }
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault();
        const sibs = this.tree.siblingsOf(this.focusId);
        if (!sibs.length) return;
        const all = [...sibs, this.tree.person(this.focusId)].filter(Boolean)
          .sort((a, b) => (a.birth ?? '').localeCompare(b.birth ?? ''));
        const idx = all.findIndex((p) => p.id === this.focusId);
        const next = all[idx + (e.key === 'ArrowRight' ? 1 : -1)];
        if (next) this.setFocus(next.id);
      }
    });
  }

  async setDataset(id) {
    if (id === this.datasetId) return;
    this.datasetId = id;
    const { tree, focusId } = await this.library.openSeeded(id);
    this.tree = tree;
    this.focusId = focusId;
    this.viewStack = [];
    this.view = 'tree';
    resetTreeView();
    this.render();
  }

  setLockEnabled(on) {
    this.lockEnabled = on;
    if (!on) { this.locked = false; this.lockAfter = 'never'; }
    this.armIdle();
    this.render();
  }
  setLockAfter(v) { this.lockAfter = v; this.armIdle(); this.render(); }
  lock() { if (!this.lockEnabled) return; this.locked = true; this.paletteOpen = false; this.render(); }
  unlock() { this.locked = false; this.render(); this.armIdle(); }
  /** Zeitgeber neu stellen; laeuft nur, wenn Sperre und Frist gesetzt sind. */
  armIdle() {
    clearTimeout(this._idle);
    if (!this.lockEnabled || this.lockAfter === 'never' || this.locked) return;
    this._idle = setTimeout(() => this.lock(), this.lockAfter * 60000);
  }
  watchIdle() {
    const bump = () => { if (!this.locked) this.armIdle(); };
    for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
      window.addEventListener(ev, bump, { passive: true });
    }
  }

  togglePalette(open) { this.paletteOpen = open; this.render(); if (open) setTimeout(() => document.getElementById('palette-input')?.focus(), 0); }

  // ------------------------------------------------------------ render
  render() {
    if (this.locked) { mount(this.root, lockView(this)); return; }
    const view = VIEWS[this.view] ?? VIEWS.tree;
    const portrait = (window.innerWidth || 1280) <= 820;
    const sub = ['detail', 'editor', 'transfer', 'onboarding'].includes(this.view);
    // Alle Ansichten reichen bis an den oberen Rand: die Titelzeile liegt ohne
    // Flaeche darueber.
    // Nur die Arbeitsflaechen reichen unter die Titelzeile. Wo Text scrollt,
    // bleibt sie eine feste Leiste — sonst wandert Gelesenes hinter den Namen.
    const canvasView = ['tree', 'fan', 'graph'].includes(this.view);
    const scrolls = !['tree', 'fan', 'graph'].includes(this.view);
    const shell = h('div', { class: 'shell view-' + this.view + (canvasView ? ' canvas-view' : '') + (canvasView && scrolls ? ' fade-top' : '') },
      this.renderRail(view),
      h('div', { class: 'main' }, this.renderTitleBar(view),
        h('div', { class: 'content' }, view.render(this)),
        this.renderSearchFab(),
        this.renderViewToggleFab(),
        this.renderTabBar(view)),
      this.paletteOpen ? this.renderPalette() : null
    );
    // Neuzeichnen ersetzt den Inhalt — ohne das hier springt jede Einstellung
    // zurueck an den Anfang der Seite.
    const prev = this.root.querySelector('.content');
    const keep = prev && this._scrollView === this.view ? prev.scrollTop : 0;
    mount(this.root, shell);
    this._scrollView = this.view;
    if (keep) {
      const next = this.root.querySelector('.content');
      if (next) next.scrollTop = keep;
    }
  }

  /**
   * Suche im Hochformat: unten links, in Baum und Graph an derselben Stelle.
   * Rechts stehen die Aktionen der Ansicht, links das Navigieren.
   */
  renderSearchFab() {
    if (!isCompact() || !['tree', 'fan', 'graph'].includes(this.view)) return null;
    return h('div', { class: 'graph-fabs floating left' },
      h('button', { class: 'fab', type: 'button', title: t('action-search'),
        'aria-label': t('action-search'), onClick: () => this.togglePalette(true) }, icons.search(22)));
  }

  /** Baum und Faecher wechseln sich im Hochformat ueber einen Knopf rechts ab. */
  renderViewToggleFab() {
    if (!isCompact() || !['tree', 'fan'].includes(this.view)) return null;
    const toFan = this.view === 'tree';
    const label = t(toFan ? 'view-fan' : 'view-ancestors');
    // Akzentfarbe in zwei Toenen: der Knopf zeigt, wohin er fuehrt.
    return h('div', { class: 'graph-fabs floating' },
      h('button', { class: 'fab ' + (toFan ? 'accent' : 'accent-alt'), type: 'button',
        title: label, 'aria-label': label,
        onClick: () => this.setView(toFan ? 'fan' : 'tree') }, (toFan ? icons.fan : icons.tree)(22)));
  }

  renderRail(view) {
    const tab = this.activeTab();
    const item = (id, icon, target) => h('button', {
      class: 'rail-item', type: 'button', 'aria-current': String(tab === id),
      title: t('tab-' + id), onClick: () => this.setView(target)
    }, icon(26));
    return h('nav', { class: 'rail' },
      item('tree', icons.tree, 'tree'),
      item('graph', icons.graph, 'graph'),
      item('people', icons.people, 'people'),
      item('settings', icons.settings, 'settings'));
  }

  renderTabBar(view) {
    const tab = this.activeTab();
    const item = (id, icon, target) => h('button', {
      type: 'button', 'aria-current': String(tab === id), title: t('tab-' + id),
      onClick: () => this.setView(target)
    }, icon(26));
    return h('nav', { class: 'tabbar' },
      item('tree', icons.tree, 'tree'),
      item('graph', icons.graph, 'graph'),
      item('people', icons.people, 'people'),
      item('settings', icons.settings, 'settings'));
  }

  renderTitleBar(view) {
    const person = this.tree.person(this.focusId);
    const isTreeArea = ['tree', 'fan'].includes(this.view);
    const portrait = (window.innerWidth || 1280) <= 820;
    const compact = isCompact();
    // Auf dem Handy ist die Detailansicht ein Vollbild: sie braucht einen Rueckweg.
    const sub = ['detail', 'editor', 'transfer', 'onboarding'].includes(this.view);
    return h('header', { class: 'titlebar' },
      h('div', { class: 'title' }, h('span', {}, 'open'), h('span', { class: 'om' }, 'om')),

      h('div', { class: 'titlebar-actions' },
        isTreeArea && !compact ? h('div', { class: 'segmented' },
          h('button', { type: 'button', 'aria-pressed': String(this.view === 'tree'),
            title: t('view-ancestors'), 'aria-label': t('view-ancestors'),
            onClick: () => this.setView('tree') }, t('view-ancestors')),
          h('button', { type: 'button', 'aria-pressed': String(this.view === 'fan'),
            title: t('view-fan'), 'aria-label': t('view-fan'),
            onClick: () => this.setView('fan') }, t('view-fan'))) : null,
        // In einer Unteransicht gehoert die Leiste dem Zurueckweg — Suche, Daten
        // und Neu sind Werkzeuge der Hauptansichten.
        // Die Lupe steht nur dort, wo eine Flaeche zu durchsuchen ist — als
        // schwebender Knopf in Baum, Faecher und Graph.
        !compact && this.view === 'graph'
          ? h('button', { class: 'icon-button' + (this.graphPanel === false ? '' : ' on'),
              title: t('graph-panel'), 'aria-label': t('graph-panel'),
              'aria-pressed': String(this.graphPanel !== false),
              onClick: () => this.toggleGraphPanel() }, icons.panel(22))
          : null,
        portrait || compact || !['tree', 'fan', 'graph'].includes(this.view)
          ? null
          : h('button', { class: 'icon-button', title: t('action-search') + ' (⌘K)', onClick: () => this.togglePalette(true) }, icons.search(22)),
        null)
    );
  }

  renderPalette() {
    const portrait = isCompact();
    const results = h('div', { class: 'command-results' + (portrait ? ' no-bar' : '') });
    // Auf dem Handy sagt kein Balken, wie viel noch kommt — also die Zahl,
    // und zwar dort, wo am Rechner die Tastenkuerzel stehen.
    const footer = h('div', { class: 'muted', style: { fontSize: 'var(--t-tiny)' } });
    const update = (value) => {
      const hits = search(this.tree, value, 50);
      footer.textContent = !portrait
        ? '⌘K · ↑ father · ⇧↑ mother · ↓ eldest child · ←→ siblings · ⌘Z undo'
        : !String(value).trim() ? t('search-prompt')
        : hits.length ? t('search-hits', { count: hits.length })
        : t('search-none');
      results.replaceChildren(...hits.map((p) => h('button', {
        type: 'button',
        onClick: () => { this.togglePalette(false); this.setFocus(p.id); }
      },
        // Name oben, Lebensdaten darunter — nebeneinander franst die Spalte aus,
        // weil "ca. 1712" und "1747 – 1804" verschieden lang sind.
        h('span', { class: 'stack', style: { gap: '2px', minWidth: '0', width: '100%' } },
          h('span', { style: { fontFamily: 'var(--font-name)', fontSize: '17px', display: 'block' } }, fullName(p)),
          h('span', { class: 'muted tabular', style: { fontSize: 'var(--t-small)', display: 'block' } },
            [shortDate(p.birth), shortDate(p.death)].filter(Boolean).join(' – ') || t('label-no-year'))))));
    };
    const input = h('input', { id: 'palette-input', placeholder: t('action-search'),
      onInput: (e) => update(e.target.value) });
    update('');
    return h('div', { class: 'command-palette', onClick: (e) => { if (e.target.classList.contains('command-palette')) this.togglePalette(false); } },
      h('div', { class: 'command-panel' }, input, results, footer));
  }
}

const app = new App(document.getElementById('app'));
window.openom = app;
app.boot().catch((e) => {
  document.getElementById('app').innerHTML =
    '<pre style="padding:24px;color:#c2743f;white-space:pre-wrap">' + String(e && e.stack || e) + '</pre>';
});
