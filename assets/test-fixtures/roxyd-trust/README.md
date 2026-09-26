# roxyd trust test keys

Test-only private keys for the `roxyd_trust` key-matching and chain tests. They
are trusted nowhere and protect nothing; they exist because the certificate
generator the tests use cannot mint RSA keys or the other encodings below.

Each was generated once with OpenSSL 3.6 and is an unencrypted PKCS#8
`PRIVATE KEY` block. The RSA keys came from

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:<bits>
```

with these options:

- `rsa-2048-ca.pem`, `rsa-2048-leaf.pem`: `<bits>` = 2048.
- `rsa-1024.pem`, `rsa-2560.pem`, `rsa-4096.pem`, `rsa-8192.pem`: the bit
  count the name gives.
- `rsa-2048-e3.pem`: 2048, and `-pkeyopt rsa_keygen_pubexp:3`.
- `rsa-2048-e-over-33-bits.pem`: 2048, and
  `-pkeyopt rsa_keygen_pubexp:8589934593` (2^33 + 1).

The EC key came from

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:explicit
```

and is `p256-explicit-params.pem`: a P-256 key whose curve is spelled out as
explicit parameters rather than named.
