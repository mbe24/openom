/** Lokalmodus: eine anonyme Session, damit der App-Code in beiden Modi gleich ist. */
export class LocalOnlyAuth {
  #session = { kind: 'local', id: 'local', label: 'local only' };
  current() { return this.#session; }
  async register() { throw new Error('Unsupported in local mode'); }
  async login() { throw new Error('Unsupported in local mode'); }
  async refresh() { return this.#session; }
  async logout() { return; }
  capabilities() { return { canRegister: false, canLogin: false, sync: false }; }
}

export class SessionController {
  #auth;
  constructor(auth) { this.#auth = auth; }
  get session() { return this.#auth.current(); }
  get capabilities() { return this.#auth.capabilities(); }
  async login(c) { return this.#auth.login(c); }
  async register(c) { return this.#auth.register(c); }
  async logout() { return this.#auth.logout(); }
}

/** Nur lesbarer Zustand fuer die Anzeige. */
export const syncStatus = {
  state: 'local',
  lastSyncedAt: null,
  label() { return this.state; }
};
