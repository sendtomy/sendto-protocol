# sendto-protocol

Shared wire format, crypto primitives, and API contract for [SendTo](https://github.com/sendtomy) — end-to-end encrypted file and message transfer.

Consumed by:
- **[sendto-clients](https://github.com/sendtomy/sendto-clients)** — CLI, daemon, desktop Tauri app, mobile Tauri app, system tray.
- **[sendto-service](https://github.com/sendtomy/sendto-service)** — Axum relay + coordination server.

## What's in this crate

| Module    | Contents                                                                 |
|-----------|--------------------------------------------------------------------------|
| `api`     | REST request/response types (auth, devices, messages, inbox, sessions)   |
| `types`   | Domain enums, blob envelope format, device-name validation               |
| `crypto`  | X25519 + XChaCha20-Poly1305 with per-transfer BLAKE3 KDF                 |
| `daemon`  | IPC types for the `sendto` CLI ↔ daemon local socket                     |

## Crypto primitives

- **Key agreement:** X25519 (`x25519-dalek`).
- **Authenticated encryption:** XChaCha20-Poly1305 (`chacha20poly1305`).
- **Per-transfer KDF:** BLAKE3 derive-key with context `sendto.v2.transfer`, domain-separated.
- **Blob envelope:** 40-byte prologue (`"ST02"` magic + version 2 + algorithm ID 2 + chunk size) + sender ephemeral public key + transfer nonce + chunks + 48-byte trailer (`"STTR"` + chunk count + plaintext size + BLAKE3 hash).

See `src/crypto.rs` and `src/types.rs` for details.

## Development

```sh
cargo test      # 13 crypto roundtrip tests + 7 type tests
cargo clippy -- -D warnings
```

## Stability

- Wire format is versioned (byte 4 of the blob prologue). Additive changes only; new algorithms require a version bump.
- Crypto context strings are fixed. Never reuse across purposes.
- This crate is **pre-1.0**; minor versions may break API types until `1.0`.

## License

MIT.
