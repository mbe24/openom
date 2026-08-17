# Concepts

## Local-first and zero-knowledge

openom treats a family tree as a document that lives on your device. The client is the stateful,
key-holding side; the server is stateless and keyless. It stores only opaque sealed blobs and non-secret
metadata, and can never read a tree — trust lives on the device, not in the backend.

The client seals every tree before upload with a data key derived from your passphrase. The server sees
ciphertext plus the minimum metadata it needs to route and meter it — never plaintext, and never a key.

## State is a log, not a row

Every edit is a small, self-contained operation appended to a sealed, append-only log. The tree you see is
*derived* by replaying that log, with periodic snapshots so a fresh device does not replay everything from
the beginning.

Because the operations are designed to commute, two devices that edit while offline converge automatically
once they sync. There is no merge server: the backend only relays bytes it cannot read, and correctness
comes from the operations themselves.

## Sharing is a client-verified guarantee

Membership and roles — Viewer, Editor, Maintainer, Owner — are carried by a signed *keyring*: a
hash-chained, append-only record of who may do what. Clients verify the keyring, and every landed entry's
authorship, themselves. Access control is therefore a cryptographic guarantee rather than a promise the
server could quietly break.
