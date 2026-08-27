# Reusable Kani (bit-precise model checking, CBMC backend) image for the openom workspace.
#
# Kani has no native Windows support and isn't in the workspace's stable cargo image, so — like
# cargo-fuzz — it runs in a container (or a local install for those who have it). This image bakes in
# the Kani driver + its CBMC/toolchain bundle so `cargo kani` runs offline afterwards.
#
# Build (scripts/kani.mjs does this automatically if the tag is missing):
#   docker build -f docker/kani.Dockerfile -t openom-kani:latest docker
# Run a crate's proofs:
#   node scripts/kani.mjs -p openom-claim
#
# The build context is `docker/` (this file is self-contained — it copies nothing from the repo; the
# workspace is bind-mounted at run time).
FROM rust:1-bookworm

# `cargo kani setup` fetches a prebuilt CBMC + the Kani compiler bundle; a couple of runtime libs and
# python (used by some of Kani's helper scripts) round it out. Keep the layer lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install the Kani driver, then fetch its toolchain + solver bundle INTO the image (~1 GB, one-time —
# cached as a layer). `--locked` pins the driver; `cargo kani setup` pulls the matching backend, so the
# two stay consistent. Baked into $HOME/.kani (HOME=/root), which the run-time container reuses.
RUN cargo install --locked kani-verifier \
    && cargo kani setup

# Fail the build early if the driver or its bundle didn't land.
RUN cargo kani --version
