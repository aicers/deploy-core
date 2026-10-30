# Signed format-6 package with placeholder images

A signed format-6 component package whose two declared image members are
placeholder bytes, not image archives. Its manifest and signatures verify
under `verify::verify_package`, which never reads an archive, but
`package::verify_contents` and every image archive check refuse it as an
invalid archive. It is kept as that negative case.

- `package.pkg` is the package, in container format 3.
- `ed25519-public-key.hex` is the raw Ed25519 public key that signed it, in
  lowercase hex.
- `ml-dsa-87-public-key.hex` is the raw ML-DSA-87 public key that signed it,
  in lowercase hex.

## How it was re-framed

The package was first written in container format 2, signed with Ed25519
alone, and that private key was discarded, so the package cannot be
regenerated. When container format 3 replaced format 2, it was re-framed
once: its manifest block and its archive block were copied byte for byte
from the format-2 package, followed by fresh Ed25519 and pure ML-DSA-87
signatures over that manifest block, the two keys' IDs and a format-3 footer.
The two blocks are unchanged; only the envelope and the footer are new. The
re-framing was done once, with OpenSSL 3.5 and a throwaway program that is
not part of the repository, and both new private keys were discarded.

`format-2/` holds the original format-2 `package.pkg` and the
`public-key.hex` that signed it, unchanged, as a genuine format-2 package
that this build refuses. Neither it nor the re-framed package is ever
replaced.

The signed package whose images verify in full is `../signed-v6-images`.
