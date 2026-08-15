# Verifying the Tauri build

The whole key-custody path (openom-vault-host + the command mirror) is cargo-tested, and the
Tauri crate type-checks (`cargo check -p openom-tauri` passes in a WebKitGTK container). What's
left is **runtime** verification: actually running the app and exercising the flows.

Two ways to run it. Android is attractive because the app runs *inside the emulator*, sidestepping
the Windows policy that blocks freshly-built `.exe`s — but the cargo **build** step still runs
dependency build-scripts on the host, which is the thing that policy blocks (that's why the pure
crates build in Docker). So the first real question is:

> **Does `cargo`/`tauri` build in your own terminal, or does it hit "Access is denied (os error 5)"?**

The agent's context hits it; yours might not. Find out cheaply before anything else.

---

## Step 0 — does a build run in your terminal?

```sh
# from apps/
pnpm install            # if not already
pnpm exec tauri --version
```

If that prints a version, try the smallest possible build (desktop):

```sh
pnpm dev                # = tauri dev; builds + launches the desktop app
```

- **It launches** → your terminal is not under the build-script block. Great — desktop and Android
  will both work. Do the desktop checklist below, then Android.
- **`os error 5` during the cargo step** → the policy affects your terminal too. Build under **WSL2**
  instead (WSL2 can build for Android and drive the Windows emulator over adb; for desktop, WSL2 +
  WSLg runs the Linux build's GUI). Ping me and we'll wire the WSL path.

---

## Desktop runtime checklist (`pnpm dev`)

Run each; all should hold. This exercises the real Rust host (invoke round-trip + SQLite in the app
data dir).

1. **Provision + durability.** Start a tree, set a passphrase, save the recovery code → onboarding.
   Quit the app entirely, relaunch → the unlock gate appears → unlock → your tree is there.
   *(Proves the keyring + tree persisted to `vault.sqlite`/`tree.sqlite` and re-unlock re-derives.)*
2. **Change-passphrase invalidates the old.** Settings → Change passphrase. Relaunch → the OLD
   passphrase is refused, the NEW one opens it; the OLD recovery code no longer works, the new one does.
3. **Tamper/rollback message.** With the app closed, lower the stored `keyring_revision` in
   `vault.sqlite` by hand (any SQLite browser). Relaunch → unlock → you should see the "out of date or
   tampered — refusing to open it" message, not "wrong passphrase". *(Proves the watermark refusal.)*
4. **Auto-lock.** Set Settings → Auto-lock to 5 min (or use "Lock now") → the tree drops to the unlock
   gate; unlock returns to it intact.
5. **Crash consistency.** Add a person, then kill the app hard (Task Manager) a second later. Relaunch
   + unlock → the person is either fully there or absent, never a half-written tree.

Where the databases live: `%APPDATA%\org.openom.app\` (the identifier in tauri.conf.json).

---

## Android bring-up

Prerequisites (you've set ANDROID_HOME / ANDROID_NDK_HOME / NDK_HOME; also needed):

```sh
# JAVA_HOME → Android Studio's bundled JBR, e.g.
#   setx JAVA_HOME "C:\Program Files\Android\Android Studio\jbr"
# Rust targets for Android:
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Start an emulator (Android Studio → Device Manager → launch an AVD), or plug in a device with USB
debugging on. Then:

```sh
# from apps/
pnpm android:init       # generates src-tauri/gen/android (one time; commit or gitignore — your call)
pnpm android:dev        # builds + installs + runs on the emulator/device
```

Then run the same checklist (1, 2, 4, 5 — skip the manual-SQLite step 3, or use `adb` to pull
`vault.sqlite` from the app's data dir). This verifies the exact same Rust host on Android.

Note: `pnpm android:init` and `:dev` invoke cargo → same build-script policy caveat as Step 0.

### Not yet built (Phase 2)

The mobile hardening — mandatory background-lock, `FLAG_SECURE` (block the app-switcher snapshot),
and hardware-gated biometric unlock — is a separate `openom-mobile` Tauri plugin, not yet written.
So on this first Android run: no biometrics, and backgrounding won't force a lock yet. That's the
next milestone; getting the base app running + the checklist passing is the goal here.
