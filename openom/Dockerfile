# Dev image for the openom server. Builds and runs in a Linux container because
# this host's policy blocks executing freshly built binaries.
#
# Deliberately tiny: because the server uses rustls (not OpenSSL), it needs no apt
# packages at all. The only layer is cargo-watch, which rebuilds and restarts
# `cargo run -p openom` when a source file changes. The server binary is NOT baked
# in — it compiles at runtime against the bind-mounted source, with the cargo
# registry and target dirs cached in volumes (see docker-compose.yml). So editing
# server code live-reloads without ever rebuilding this image, and the dependency
# compile happens once into the target volume, not into an image layer.
ARG RUST_IMAGE=rust:1-bookworm
FROM ${RUST_IMAGE}

# A BuildKit cache mount keeps the crate downloads out of the image and makes a
# rebuild of this one layer incremental.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-watch --locked

WORKDIR /work
