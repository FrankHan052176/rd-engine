# rd-engine

Protocol-compatible replacement runtime for RustDesk: one engine that speaks the
original wire contract on both sides (viewer and host) and produces the
flutter-rust-bridge (frb) and OpenHarmony HAR (ohrs) artifacts the clients
consume.

Upstream protobuf messages, packet framing and cryptographic primitives stay
authoritative — `hbb_common` is a pinned dependency, not a fork of the protocol.
Field meanings, authentication compatibility, identity and permission decisions
are not repurposed for media features.

## Layout

| Path | Contents |
| --- | --- |
| `src/transport.rs` | framed, encrypted duplex transport; one ordered writer owns the crypto sequence |
| `src/handshake.rs`, `src/authentication.rs` | secure handshake and both authentication roles |
| `src/session.rs`, `src/viewer.rs`, `src/host.rs` | session actor, viewer role, host role |
| `src/rendezvous.rs` | hbbs/hbbr ID routing |
| `src/media_capability.rs`, `src/media_color.rs` | typed capability and color contracts |
| `src/platform/ohos_*.rs` | OpenHarmony decode/publish/capability providers |
| `src/platform/windows_*.rs` | Windows Desktop Duplication + NVENC producer |
| `native/windows-capture`, `native/windows-nvenc` | native sources for the Windows producer (see their `ORIGIN.md`) |
| `examples/` | host-viewer, rendezvous and OHOS capability probes |
| `tests/` | direct auth, pinned host and rendezvous integration tests |
| `docs/MODERN_RUNTIME.md` | the design and acceptance contract this engine is built against |

## Build

```bash
cargo test                     # host platform
cargo build --release --bin rd-engine-windows-host --target x86_64-pc-windows-msvc
cargo check --target aarch64-unknown-linux-ohos
```

The crate carries its own `[workspace]` so it builds independently of any
application tree. `hbb_common` is pinned by revision in `Cargo.toml`; bump it
deliberately and re-run the tests.

## Provenance

Extracted from `rustdesk4ohos@refactor/protocol-compatible-runtime`
(`01e176672`) subtree `crates/rd-engine`. That repository keeps the full history;
this one starts from the import commit.

## Status

Implemented: full-duplex transport, both authentication roles, hbbs/hbbr routing,
the color/capability contract, the Windows native producer source and the OHOS
platform providers. Open: real-hardware NVENC/D3D11 validation, and peer sessions
against unmodified official clients. Acceptance order and gates are in
`docs/MODERN_RUNTIME.md`.
