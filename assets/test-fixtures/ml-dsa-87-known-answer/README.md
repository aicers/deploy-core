# ML-DSA-87 known answer

An interoperability vector: a pure ML-DSA-87 (FIPS 204) signature made by
OpenSSL 3.5 over a raw manifest block, kept so the verifier is shown to accept
a signature produced by another implementation.

- `message.bin` is the message: the bytes of
  `../ed25519-known-answer/manifest.json`, exactly.
- `public-key.hex` is the raw 2,592-byte public key in lowercase hex (5,184
  characters).
- `signature.hex` is the 4,627-byte signature over `message.bin`, pure
  ML-DSA-87 with an empty context, in lowercase hex.
- `context-signature.hex` is a signature over the same message under the same
  key with the context string `deploy-core`. FIPS 204 binds the context into
  what is signed, so a verifier using the empty context must refuse it.

They were made with OpenSSL 3.5.9:

```sh
openssl genpkey -algorithm ML-DSA-87 -out k.pem
openssl pkey -in k.pem -pubout -outform DER | tail -c 2592 \
  | xxd -p | tr -d '\n' > public-key.hex
cp ../ed25519-known-answer/manifest.json message.bin
openssl pkeyutl -sign -rawin -inkey k.pem -in message.bin \
  | xxd -p | tr -d '\n' > signature.hex
openssl pkeyutl -sign -rawin -inkey k.pem -in message.bin \
  -pkeyopt context-string:deploy-core \
  | xxd -p | tr -d '\n' > context-signature.hex
```

and a trailing newline appended to each `.hex` file. `k.pem` was discarded:
the private key is not committed, and nothing here can be re-signed.

OpenSSL signs ML-DSA with fresh randomness, so running the commands again
yields a different key and different signatures. This is a verification
vector, not a byte-for-byte one.
