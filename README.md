# deploy-core

Product-neutral deploy primitives shared by an installer and an on-host root agent.

`deploy-core` is the slim, component-agnostic core of the deploy stack:

- **transport** / **exec** / **executor** — the SSH-and-local execution vocabulary
  and the elevated command runner.
- **layout** — the on-host directory layout derived from a single namespace.
- **manifest** / **payload** — the artifact manifest and the container format it
  rides in: a self-extracting payload appended to a base executable, and the very
  same container with no base as a `.pkg` module package, read by one reader.
- **module_spec** — the declarative per-module install spec a package carries in
  its manifest (unit template, bootroot registration template, placement class),
  and the validator every read path runs over it.
- **image** — the typed declaration a container image artifact makes from
  manifest format 6 on: its owning namespace and component, its dependency
  name, the explicit `name:tag` references it is restored under, its one Linux
  platform, its config digest, its reference lifecycle and its provenance, with
  the Docker reference syntax every read path checks and the canonical
  `runtime.invalid` alias helper. It states signed facts only and checks no
  image bytes.
- **systemd** — the one systemd serialization and rejection rule, which decides
  whether a package-declared string is representable in a unit file at all and
  turns a host-resolved value into directive text.
- **render** — the generic, catalogue-free renderer that turns a declared spec
  plus a host-resolved render context into unit text and a unit file name, and
  the placement check that says whether the artifact belongs on this host.
- **verify** — the one package verifier the control plane and the root daemon
  both reach a verdict through: the Ed25519 signature over the raw manifest
  bytes, the trust anchors and withdrawn builds a caller injects, the
  namespace-scoped request a package declaring images is verified under, and
  the error taxonomy downstream repositories match on.
- **package** — full-content verification: `verify_contents` copies a signed
  package once into private retained storage, authenticates that copy with
  exactly the verdicts **verify** gives, requires one requested architecture,
  refuses legacy undeclared images, checks every outer member and then every
  image archive against its signed declaration, and only then returns
  `VerifiedContents` — the authenticated manifest, every artifact's bytes, the
  image evidence and the exact package bytes. Every step runs under the finite
  resource policy: one ceiling per resource — stored and decoded bytes,
  entries, path lengths, JSON documents and nesting, disk and buffers — each
  starting at a generous library default that a caller may lower and never
  raise. The evidence is read through the read-only `RetainedBytes` handle: a
  private, already unlinked copy the library made of an untrusted source in
  one pass, exposing no path, file or descriptor, so nothing outside the
  library can change it between the check and the use. And the receipt and
  error types of no-clobber, durable publication, which never replaces an
  existing entry and reports a failure after the output became visible as
  uncertain durability rather than as success. Unsigned preparation builds
  the other side: `prepare_package` copies each input once into private
  storage and builds one raw manifest and one compressed archive block from
  those copies, checked by the same content core, into a `PreparedPackage`
  that is unsigned and untrusted for installation; its `PreparationBinding`
  is the data a signing request is correlated by. `persist` writes the two
  blocks and the binding record as a new three-file directory, and
  `reopen_prepared` turns one back into a package only against an
  independently saved binding, after fresh copies and full revalidation.
  Detached finalization closes the loop without holding a key:
  `finalize_package` holds a prepared package to the caller's saved binding,
  rehashes both blocks, assembles the signed container from exactly those
  bytes and an Ed25519 signature over the raw manifest, and runs the full
  `verify_contents` pipeline over it under the caller's own trust, returning
  the `FinalizedPackage` that direct installation and store publication both
  consume. `prepare_sign_finalize` composes the three steps with one signing
  callback, validating identically.
- **trust_set** — the generation document that verifier's injected material is
  delivered as, and the reader that refuses a malformed one rather than
  repairing it: a version gate, a structural decode that admits no unknown
  field, and the semantic checks over the anchors and withdrawn builds. It
  opens no file and performs no I/O.
- **release_trust** — the on-host release-trust tree that document is installed
  into: a sibling of the mTLS tree holding `active` and `gen-<n>/`, where one
  generation is the delivered container, the verified member and a one-integer
  `epoch` record finalised together. It exports the epoch reader, the one
  constructor that turns the active generation back into **verify**'s injected
  trust set, and the two install-time admission doors — a seed that refuses a
  tree already carrying a generation and an operator-mediated replace that does
  not — which verify a delivered container against the trust set it carries
  before the tree's one crate-internal installer stages it. Separately it
  exports the runtime accept path the control plane pushes over, which judges a
  delivered generation against the **active** one's trust set and applies the
  `epoch` floor: the state query a caller asks before it pushes, the accept for
  one delivered generation, and the ordered chain replay that catches a lagging
  host up. There is no other way for a dependent crate to write the tree.
- **engine** — the install/update diff engine (compute what changed).
- **apply** — the apply primitives that actuate a diff on a host (place files,
  create directories, run root commands, load images, extract bundles).
- **bootroot_cmd** — the wrapper around the on-host PKI command.
- **registration** — service registration against the on-host PKI.
- **roxyd_selfupdate** — the roxyd self-update rollback supervisor units as
  data: the three activation services and the deadline timer, with no renderer
  and nothing to substitute. This crate is their single owner and the installer
  is its only consumer, embedding these bytes from its pinned dependency onto
  both host populations — the ones it provisions and the ones roxyd onboards
  through its join flow — so neither can roll back under different rules.
- **roxyd_selfupdate_contract** — the frozen on-disk contract those units
  coordinate through, and a sibling of **roxyd_selfupdate** rather than part of
  it: the record directory, the file names, the canonical roxyd binary path,
  the decision subcommand and its three activation reasons, the self-test
  freshness window and nonce rules, a resolver for every path composed from
  them, and the versioned JSON record types with the `FORMAT` revision each
  carries. Unlike the unit text it has two writers, the installer and the
  on-host agent, which is why one definition lives here rather than a copy in
  each — a second copy diverges after deployment with both repositories' tests
  green. Neither module depends on the other.
- **roxyd_trust** — trust-material activation for the on-host agent: the X.509
  validator for roxyd's staged cert/key/CA triple, over the crate-internal
  tree-neutral generation engine (stage, validate the copy, swap `active`,
  prune) that every root-owned trust tree under **layout** shares.

It carries no product concept — no component catalog, no per-component
renderers — so both the installer and the per-machine root daemon depend
on it and share one implementation.

## Testing

```sh
cargo test
```

The `test-support` feature exposes test-only account fixtures
(`Principal::Fixture` / `ServiceAccount::Fixture`), payload fixtures such as
`payload::widen_envelope_blocks`, and `image::test_support` — a builder for
synthetic image archives the image validator accepts, and a classifier that
holds any image archive against a declaration — so a **dependent** crate's
tests can construct them across the crate boundary. With
`package::prepare_sign_finalize` and a test key minted per test, those
archives become genuinely signed format-6 packages that pass every final
check; `tests/signed_fixtures.rs` builds one through the public API alone.
Enable it only as a `[dev-dependencies]` feature — never under normal
`[dependencies]` — so the fixtures stay absent from every release build.

The checked-in image archive fixtures, and how each one is regenerated, are
described in `assets/test-fixtures/images/INVENTORY.md`. The manual Docker
interoperability procedure is `docs/image-archive-interoperability.md`.

## License

See the repository for license information.
