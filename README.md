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
- **systemd** — the one systemd serialization and rejection rule, which decides
  whether a package-declared string is representable in a unit file at all and
  turns a host-resolved value into directive text.
- **render** — the generic, catalogue-free renderer that turns a declared spec
  plus a host-resolved render context into unit text and a unit file name, and
  the placement check that says whether the artifact belongs on this host.
- **verify** — the one package verifier the control plane and the root daemon
  both reach a verdict through: the Ed25519 signature over the raw manifest
  bytes, the trust anchors and withdrawn builds a caller injects, and the error
  taxonomy downstream repositories match on.
- **trust_set** — the generation document that verifier's injected material is
  delivered as, and the reader that refuses a malformed one rather than
  repairing it: a version gate, a structural decode that admits no unknown
  field, and the semantic checks over the anchors and withdrawn builds. It
  opens no file and performs no I/O.
- **engine** — the install/update diff engine (compute what changed).
- **apply** — the apply primitives that actuate a diff on a host (place files,
  create directories, run root commands, load images, extract bundles).
- **bootroot_cmd** — the wrapper around the on-host PKI command.
- **registration** — service registration against the on-host PKI.
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

The `test-support` feature exposes the test-only account fixtures
(`Principal::Fixture` / `ServiceAccount::Fixture`) so a **dependent** crate's tests
can construct them across the crate boundary. Enable it only as a
`[dev-dependencies]` feature — never under normal `[dependencies]` — so the
fixtures stay absent from every release build.

## License

See the repository for license information.
