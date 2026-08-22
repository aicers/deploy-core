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
  and nothing to substitute. This crate is their single owner — the installer
  and roxyd's own `join` both embed these bytes from their pinned dependency,
  so the hosts each onboards cannot roll back under different rules.
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
