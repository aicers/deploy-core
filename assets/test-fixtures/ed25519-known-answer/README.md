# Ed25519 known answer

A raw manifest block and the Ed25519 signature ring 0.17.14 produced over it,
kept so the signature can be reproduced byte for byte by any other
implementation of the same deterministic algorithm.

- `manifest.json` is the message, exactly as the bytes on disk.
- `signature.hex` is the 64-byte signature in lowercase hex.

The key is the RFC 8032 §7.1 TEST 1 key, which is public test data and not
project key material. The signature was produced by `Ed25519KeyPair` from
`from_seed_unchecked` over that seed, then `sign` over the file's bytes.
