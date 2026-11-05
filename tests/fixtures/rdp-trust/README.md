# RDP certificate-trust test fixture

Public, synthetic TLS material for `src/protocol/rdp/tls.rs`'s tests. It is **not** a
Windows identity, not a RustDesk identity, and never used outside these tests.

| file | what it is |
| --- | --- |
| `leaf.der` | one self-signed X.509v3 leaf, DER, ECDSA P-256 / SHA-256 |
| `leaf-key.der` | that leaf's PKCS#8 private key, DER |

## The private key here is deliberately public

`leaf-key.der` is committed on purpose so a test can run a real TLS handshake with
this leaf. It protects nothing: it was generated only for these tests, it is not used
by any build, deployment or device, and nothing in the engine trusts it implicitly.
**Never use it, or a certificate derived from it, in production.**

## What the tests rely on

- `subject` = `issuer` = `CN=rd-engine-rdp-trust-fixture, O=rd-engine` (self-signed).
- `notBefore` `2026-01-01T00:00:00Z`, `notAfter` `2036-01-01T00:00:00Z` (UTC, UTCTime).
- SAN `DNS:localhost`, `IP:127.0.0.1`; EKU serverAuth; KU digitalSignature;
  basicConstraints CA:false.
- `leaf.der` SHA-256
  `d7627513f8876ef4424d2f6caafef5941de543fe058d7900b873b9bedb1ae157`
  (key SHA-256 `d530b067d42d0170a37dc86aae58136f0942e29b27f53899ffaba9bf81bce94f`).

The tests assert the *metadata a client is shown* against these values, so changing
the fixture without updating `src/protocol/rdp/tls.rs` breaks them on purpose.

## Provenance

Generated with OpenSSL 3.6.3 as fresh test material (no copied vendor, no real
identity). The generating script and receipt live outside this tree at
`.build-deps/rdp-vnc-verification/generate-rdp-trust-fixture.py` and
`.build-deps/rdp-vnc-verification/rdp-trust-fixture.json`.
