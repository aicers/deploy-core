# Signed format-6 package with verifiable images

A genuinely signed format-6 component package whose image members are real,
canonical image archives, so `package::verify_contents` accepts it in full.
It holds a Compose file and two declared images for `example-app` 1.0.0 in
`example-product`, built for `x86_64`:

- `images/database.tar` — a normalized third-party database, tagged only
  with its canonical `runtime.invalid/.../database:cfg-<config digest>`
  alias, with managed lifecycle and registry provenance.
- `images/web.tar` — a product-built image tagged
  `ghcr.io/example/example-app:1.0.0`, with shared lifecycle.

Every image is built by `image::test_support::SyntheticImageArchiveBuilder`
with uncompressed layers under the canonical image manifest.

- `package.pkg` is the package, in container format 3.
- `ed25519-public-key.hex` is the raw Ed25519 public key that signed it, in
  lowercase hex.
- `ml-dsa-87-public-key.hex` is the raw ML-DSA-87 public key that signed it,
  in lowercase hex.

Only the public halves were kept: the fixture is test trust and nothing
else, and both private keys were discarded once the package was written.

## How it was re-framed

The package was written at manifest format 6 in container format 2, signed
with Ed25519 alone. It is the one package with real images at manifest
format 6 that verifies in full, so when container format 3 replaced format 2
it was not regenerated — the example below writes the current manifest
format — but re-framed: its manifest block and its archive block were copied
byte for byte, followed by fresh Ed25519 and pure ML-DSA-87 signatures over
that manifest block, the two keys' IDs and a format-3 footer. The re-framing
was done once, with OpenSSL 3.5 and a throwaway program that is not part of
the repository. No format-2 copy of this package is kept.

## Regenerating it

Write it into an empty directory, then replace all three files together:

```sh
mkdir /tmp/signed-v6-images
cargo run --example write_signed_v6_fixture --features test-support -- /tmp/signed-v6-images
```

That writes `package.pkg`, `ed25519-public-key.hex` and
`ml-dsa-87-public-key.hex`. The example mints fresh keys on every run, so all
three change each time, and none is reproducible byte for byte. It also
writes the current manifest format rather than format 6, which is why the
checked-in package was re-framed rather than regenerated. Everything the keys
do not touch is checked: `tests/signed_fixtures.rs` prepares the same members
through the example's own `fixture` module and requires the checked-in
package to carry that signed manifest, apart from its leading
`format_version`, which is the version the package was written at, to verify
in full, and to report the manifest digest the builder wrote for each image.
The example prints those digests as it writes the package.

The metadata-only package from before image-content validation, whose image
members are placeholder bytes, is kept as a negative case in
`../signed-v6-placeholder-images`.
