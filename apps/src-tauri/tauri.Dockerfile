# A rust image with the WebKitGTK system libraries the Tauri shell (openom-tauri) needs, so its crate
# can be `cargo check`/`test`ed locally in Docker exactly as the desktop CI does — the plain rust:1-bookworm
# the normal runner (scripts/cargo.mjs) uses lacks them, which is why that runner excludes openom-tauri.
# Mirrors the apt list in .github/workflows/desktop.yml. Self-contained: copies nothing (the workspace is
# bind-mounted at run time), so any dir works as the build context.
#
#   docker build -t openom-tauri-check -f apps/src-tauri/tauri.Dockerfile apps/src-tauri
#   docker run --rm -v "<repo>":/work -v openom-cargo-registry:/usr/local/cargo/registry \
#     -v openom-cargo-target-tauri:/tmp/target -w /work -e CARGO_TARGET_DIR=/tmp/target \
#     openom-tauri-check cargo check -p openom-tauri
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
      libssl-dev libgtk-3-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
