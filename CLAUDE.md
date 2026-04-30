# CLAUDE.md — sendto-protocol

Wire format, crypto primitives, and API contract for **SendTo** — end-to-end encrypted file and message transfer. Consumed by `sendto-clients` (CLI/daemon/desktop/mobile) and `sendto-service` (relay + coordination server).

See the workspace-level OVERVIEW.md for product context, feature matrix, and roadmap.

## What's in this crate

- Single crate: `sendto-protocol`.
- Modules:
  - `api` — REST request/response types (auth, devices, messages, inbox, sessions).
  - `types` — domain enums, blob envelope format, device-name validation.
  - `crypto` — X25519 + XChaCha20-Poly1305 with per-transfer BLAKE3 KDF.
  - `daemon` — IPC types for `sendto` CLI ↔ daemon local socket.

## Build & test

```sh
cargo check
cargo test                 # 13 crypto roundtrip tests + 7 type tests
cargo clippy -- -D warnings
```

## Conventions

- **Do not break the wire.** The blob envelope (`"ST02"` magic + version byte + chunks + `"STTR"` trailer) is versioned. Additive changes only; new algorithms require a protocol version bump.
- Crypto context strings are domain-separated (`sendto.v2.transfer`). Never reuse across purposes.
- All public types are `Serialize + Deserialize` and JSON-compatible.
- `thiserror` for error types. No `anyhow` in library code.
- Public API of this crate is not yet `1.0`; minor versions may break types.

## Don't

- Don't swap ciphers without a protocol version bump.
- Don't add `unsafe` blocks.
- Don't add runtime dependencies (`tokio`, `reqwest`, etc.). This is a pure protocol/types crate; async and HTTP belong in the consumers.
- Don't weaken crypto defaults (chunk size, nonce derivation, KDF context) — they're security-load-bearing.

## Related repos

- [sendto-clients](https://github.com/sendtomy/sendto-clients) — every client surface.
- [sendto-service](https://github.com/sendtomy/sendto-service) — relay + coordination server.
