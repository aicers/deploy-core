# Signed format-6 package with placeholder images

A signed format-6 component package whose two declared image members are
placeholder bytes, not image archives. Its manifest and signature verify
under `verify::verify_package`, which never reads an archive, but
`package::verify_contents` and every image archive check refuse it as an
invalid archive. It is kept, unchanged, as that negative case.

- `package.pkg` is the package, exactly as written.
- `public-key.hex` is the raw Ed25519 public key that signed it, in
  lowercase hex. Its private key was discarded once the package was written,
  so the package cannot be regenerated. It is never replaced.

The signed package whose images verify in full is `../signed-v6-images`.
