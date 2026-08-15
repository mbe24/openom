# Running the Android build under WSL2

Native Windows cargo is blocked here (the host policy refuses to execute freshly-built build
scripts — "Access is denied (os error 5)", regardless of folder). WSL2 is Linux, so that policy
doesn't apply; we build there and drive the **Windows** emulator over a shared `localhost`.

Do the stages in order. Run WSL commands in the **Ubuntu** shell (`wsl` from a terminal), Windows
commands in **PowerShell**. Report back at each ✅ checkpoint.

---

## Stage 0 — shared localhost (mirrored networking)

So Linux `adb` sees the Windows emulator with no bridging. Needs Windows 11 22H2+.

Create/edit `C:\Users\MikaelBeyene\.wslconfig` (Windows side):

```ini
[wsl2]
networkingMode=mirrored
```

Then, in PowerShell:

```powershell
wsl --shutdown
```

Reopen Ubuntu. ✅ Checkpoint: `wsl` back at a prompt.

---

## Stage 1 — toolchain in Ubuntu

```sh
sudo apt update
sudo apt install -y build-essential curl unzip openjdk-21-jdk

# Rust (if not already in this distro) + the Android targets
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Node + pnpm (via nvm keeps it simple)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
. "$HOME/.nvm/nvm.sh"
nvm install --lts
npm install -g pnpm
```

✅ Checkpoint: `rustc --version`, `java -version` (shows 21), `pnpm --version` all print.

---

## Stage 2 — Android SDK + NDK (Linux)

WSL2 needs its **own** Linux SDK/NDK — the Windows ones have Windows host binaries. Command-line
tools only, no Studio:

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
mkdir -p "$ANDROID_HOME/cmdline-tools"
cd /tmp
curl -o cmdtools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q cmdtools.zip -d "$ANDROID_HOME/cmdline-tools"
mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0" "ndk;27.1.12297006"
```

Persist the env in `~/.bashrc` (so new shells and `pnpm` see it):

```sh
cat >> ~/.bashrc <<'EOF'

# openom Android build
export ANDROID_HOME="$HOME/Android/Sdk"
export NDK_HOME="$ANDROID_HOME/ndk/27.1.12297006"
export ANDROID_NDK_HOME="$NDK_HOME"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
. "$HOME/.cargo/env"
EOF
source ~/.bashrc
```

✅ Checkpoint: `adb --version` prints, `ls "$NDK_HOME"` lists NDK files.

---

## Stage 3 — the repo, in the Linux filesystem

Building on `/mnt/c/...` is painfully slow (cross-fs). Clone into the ext4 home instead:

```sh
cd ~
git clone <your repo URL or: /mnt/c/dev/openom> openom
cd openom/apps
pnpm install

# .env — JAVA_HOME_JBR is a Windows thing; not needed here (JAVA_HOME is already the Linux 21).
```

✅ Checkpoint: `pnpm install` completes.

---

## Stage 4 — see the Windows emulator from WSL2

Start your **Windows** emulator (Studio → the Pixel 9 AVD) if it isn't up. Then in Ubuntu:

```sh
adb kill-server
adb devices
```

With mirrored networking, this should list your emulator (e.g. `emulator-5554  device`). If it's
empty, tell me — there's a shared-adb-server fallback, but mirrored usually just works.

✅ Checkpoint: `adb devices` shows the emulator.

---

## Stage 5 — build + run

```sh
cd ~/openom/apps
pnpm android:init      # regenerate gen/android in this clone
pnpm android:dev       # builds the Rust host for Android, installs, launches
```

First build is slow (cold Rust compile). Then the app appears on the emulator.

Then the checklist in `VERIFY.md` — the key line: **provision → fully quit the app → relaunch →
unlock**. If your tree comes back, the Rust key-custody host works on-device.
