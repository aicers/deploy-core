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

- `package.pkg` is the package, exactly as published.
- `public-key.hex` is the raw Ed25519 public key that signed it, in
  lowercase hex. Only this half was kept: the fixture is test trust and
  nothing else, and its private key was discarded once the package was
  written.

## Regenerating it

Write it into an empty directory, then replace both files together:

```sh
mkdir /tmp/signed-v6-images
cargo run --example write_signed_v6_fixture --features test-support -- /tmp/signed-v6-images
```

The example mints a fresh key on every run, so `package.pkg` and
`public-key.hex` both change each time, and neither is reproducible byte for
byte. Everything the key does not touch is: `tests/signed_fixtures.rs`
prepares the same members through the example's own `fixture` module and
requires the checked-in package to carry exactly that signed manifest, to
verify in full, and to report the manifest digest the builder wrote for each
image. The example prints those digests as it writes the package.

The metadata-only package from before image-content validation, whose image
members are placeholder bytes, is kept as a negative case in
`../signed-v6-placeholder-images`.
