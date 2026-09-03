// AuthSession — the ONE seam the app's networking + composition depend on for identity.
//
// It is the forward-compat boundary (design.local-accounts-auth §1): everything below it —
// `RemoteStore`'s bearer, the member id the vault provisions/unlocks under, the composition
// root's tear-down-on-identity-change — talks to THIS interface and nothing else. Swapping the
// auth provider (DevAuth now; SupabaseAuth / ClerkAuth / any OIDC later) is a one-line change at
// composition; no other client code moves. The wire is identical in every mode
// (`Authorization: Bearer <token>`, `member_id` = the token's `sub`); only the token's
// provenance differs, and it is hidden here.
//
//   interface AuthSession {
//     getAccessToken({ forceRefresh } = {}): Promise<string>  // the Bearer value; refresh behind the seam
//     memberId(): string | null                               // the account UUID == the token's `sub`
//     signIn(opts): Promise<Account>                          // provider-specific; DevAuth = create a local account
//     signOut(): Promise<void>
//     onChange(cb): () => void                                // cb() on identity change; returns an unsubscribe
//     capabilities(): { canRegister, canLogin, sync }
//   }
//
// INVARIANT (enforced at the composition root, not here): memberId() === the token's `sub` ===
// the member id passed to the vault's provision/unlock. The server ACL is keyed on the keyring
// member ids, so a divergence 403s every request. Never generate that id independently of this seam.

const uuidv4 = () =>
  globalThis.crypto?.randomUUID?.() ??
  // Fallback for a crypto-less context (should not happen in a browser / Node 18+).
  'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });

/**
 * DevAuth — the local, self-serve, MULTI-account provider (design §6). A "local account" is just
 * `{ id: <uuid v4>, label: <display name> }`; there is no server user store, no email/password —
 * locally an account IS a UUID. The account list + the active id live in localStorage, so two tabs
 * of the same origin are two independent users, and a `storage` event makes a create/switch/sign-out
 * in one tab fan out to the others.
 *
 * localStorage is the single source of truth (read on every access) so cross-tab state never drifts;
 * writes go to storage first, then notify local subscribers (the `storage` event fires only in OTHER
 * tabs, so same-tab changes are announced directly).
 *
 * The bearer is minted by `#tokenFor(id)`. Today it returns the raw account UUID — option (A) in the
 * design: the server under `AUTH=dev` accepts a `Bearer <uuid>`. The `#tokenFor` seam is the single
 * place option (B) plugs in later: call a local-only `/dev/token` route, mint/cache a real HS256 JWT
 * (`sub=<uuid>`), and honour `forceRefresh` to exercise the production verify path — no other change.
 */
export class DevAuth {
  #storage;
  #broadcast;
  #makeId;
  #subs = new Set();
  #onStorage;

  static ACCOUNTS_KEY = 'openom.auth.accounts';
  static ACTIVE_KEY = 'openom.auth.activeId';

  /**
   * @param {object} [deps]
   * @param {Storage} [deps.storage]      a localStorage-like store (get/set/removeItem); injected for tests
   * @param {EventTarget} [deps.broadcast] where cross-tab `storage` events arrive (the `window`); injected for tests
   * @param {() => string} [deps.makeId]  uuid v4 factory (injected for deterministic tests)
   */
  constructor({ storage = globalThis.localStorage, broadcast = globalThis, makeId = uuidv4 } = {}) {
    this.#storage = storage;
    this.#broadcast = broadcast;
    this.#makeId = makeId;
    // Cross-tab: another tab's create/switch/sign-out mutates the shared localStorage and fires a
    // `storage` event HERE. Re-read (storage is the source of truth) and notify — two tabs, two users.
    this.#onStorage = (e) => {
      if (!e || (e.key !== DevAuth.ACCOUNTS_KEY && e.key !== DevAuth.ACTIVE_KEY)) return;
      this.#notify();
    };
    this.#broadcast?.addEventListener?.('storage', this.#onStorage);
  }

  // ---- persistence (localStorage is the source of truth) ----

  #readJson(key, fallback) {
    try {
      const raw = this.#storage?.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch {
      return fallback;
    }
  }
  #write(key, value) {
    try {
      this.#storage?.setItem(key, value);
    } catch {
      /* ephemeral (private mode / no storage) — dev only */
    }
  }

  /** All local accounts, `[{ id, label }]`. */
  list() {
    const accs = this.#readJson(DevAuth.ACCOUNTS_KEY, []);
    return Array.isArray(accs) ? accs : [];
  }

  /** The active account `{ id, label }`, or null when signed out. */
  activeAccount() {
    let activeId;
    try {
      activeId = this.#storage?.getItem(DevAuth.ACTIVE_KEY) ?? null;
    } catch {
      activeId = null;
    }
    if (!activeId) return null;
    return this.list().find((a) => a.id === activeId) ?? null;
  }

  // ---- the AuthSession seam ----

  memberId() {
    return this.activeAccount()?.id ?? null;
  }

  // eslint-disable-next-line no-unused-vars -- forceRefresh is a no-op for option (A); the seam for option (B).
  async getAccessToken({ forceRefresh = false } = {}) {
    const id = this.memberId();
    if (!id) throw new Error('DevAuth.getAccessToken: no active account (sign in first)');
    return this.#tokenFor(id, { forceRefresh });
  }

  // The single swap point between option (A) raw-uuid bearer (today) and option (B) a minted +
  // cached HS256 JWT from a local-only `/dev/token`. Today the uuid IS the bearer; a later option-B
  // mode replaces the body here (fetch/cache a JWT, refetch on `forceRefresh`) with nothing above it changing.
  async #tokenFor(id, _opts = {}) {
    return id;
  }

  /**
   * Create a new local account and make it active (the dev equivalent of "sign in"). The production
   * auth-gate calls `signIn`; only this "create a local account" body is dev-specific.
   * @param {{ label?: string }} [opts]
   * @returns {Promise<{ id: string, label: string }>}
   */
  async signIn({ label } = {}) {
    return this.createAccount(label);
  }

  createAccount(label) {
    const account = { id: this.#makeId(), label: label || 'Local account' };
    const accounts = [...this.list(), account];
    this.#write(DevAuth.ACCOUNTS_KEY, JSON.stringify(accounts));
    this.#write(DevAuth.ACTIVE_KEY, account.id);
    this.#notify();
    return account;
  }

  /** Switch the active account by id. Unknown id → no-op. */
  switchTo(id) {
    if (!this.list().some((a) => a.id === id)) return null;
    this.#write(DevAuth.ACTIVE_KEY, id);
    this.#notify();
    return this.activeAccount();
  }

  /** Sign out (clear the active account; the account list is kept for switching back). */
  async signOut() {
    try {
      this.#storage?.removeItem(DevAuth.ACTIVE_KEY);
    } catch {
      /* ephemeral */
    }
    this.#notify();
  }

  onChange(cb) {
    this.#subs.add(cb);
    return () => this.#subs.delete(cb);
  }

  capabilities() {
    // Local accounts are self-serve: create ("register"), switch ("login"), and they sync.
    return { canRegister: true, canLogin: true, sync: true };
  }

  #notify() {
    for (const cb of this.#subs) {
      try {
        cb();
      } catch (e) {
        console.warn('[openom] auth onChange subscriber threw', e);
      }
    }
  }

  /** Detach the cross-tab listener (tests / teardown). */
  dispose() {
    this.#broadcast?.removeEventListener?.('storage', this.#onStorage);
    this.#subs.clear();
  }
}

/**
 * SupabaseAuth — a documented stub implementing the SAME AuthSession seam over supabase-js. NOT wired
 * or imported anywhere; it exists so the production swap is one line at composition
 * (`new SessionController(new SupabaseAuth(client))`) with nothing else in the client changing.
 *
 * Shape only (uncomment + `npm i @supabase/supabase-js` when wiring):
 *   getAccessToken() → session.access_token  (supabase-js refreshes under the hood; forceRefresh → refreshSession())
 *   memberId()       → session.user.id       (the token's `sub`)
 *   signIn/out       → client.auth.signInWithPassword / signOut
 *   onChange         → client.auth.onAuthStateChange
 */
export class SupabaseAuth {
  #client;
  #session = null;
  #subs = new Set();

  constructor(client) {
    this.#client = client;
    // client.auth.onAuthStateChange((_event, session) => { this.#session = session; this.#notify(); });
  }

  async getAccessToken({ forceRefresh = false } = {}) {
    if (forceRefresh) {
      // const { data } = await this.#client.auth.refreshSession();
      // this.#session = data.session;
    }
    const token = this.#session?.access_token;
    if (!token) throw new Error('SupabaseAuth: no session');
    return token;
  }

  memberId() {
    return this.#session?.user?.id ?? null;
  }

  async signIn(credentials) {
    return this.#client.auth.signInWithPassword(credentials);
  }

  async signOut() {
    return this.#client.auth.signOut();
  }

  onChange(cb) {
    this.#subs.add(cb);
    return () => this.#subs.delete(cb);
  }

  capabilities() {
    return { canRegister: true, canLogin: true, sync: true };
  }
}

/**
 * SessionController — the app-facing handle over a swappable `#auth` backend. It IS an AuthSession
 * (delegates the whole seam) so the rest of the app depends on one stable object and one "who's
 * logged in" truth, while the provider under it is chosen once at composition (the swap point).
 */
export class SessionController {
  #auth;

  constructor(auth) {
    if (!auth) throw new Error('SessionController needs an AuthSession backend');
    this.#auth = auth;
  }

  getAccessToken(opts) {
    return this.#auth.getAccessToken(opts);
  }
  memberId() {
    return this.#auth.memberId();
  }
  signIn(opts) {
    return this.#auth.signIn(opts);
  }
  signOut() {
    return this.#auth.signOut();
  }
  onChange(cb) {
    return this.#auth.onChange(cb);
  }
  capabilities() {
    return this.#auth.capabilities();
  }

  /** The underlying provider (for provider-specific dev affordances: DevAuth.list/switchTo/createAccount). */
  get backend() {
    return this.#auth;
  }
}
