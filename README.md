# deploy-core

Product-neutral deploy primitives shared by an installer and an on-host root agent.

`deploy-core` is the slim, component-agnostic core of the deploy stack:

- **transport** / **exec** / **executor** — the SSH-and-local execution vocabulary
  and the elevated command runner.
- **layout** — the on-host directory layout derived from a single namespace.
- **manifest** / **payload** — the artifact manifest and the self-extracting
  payload format.
- **engine** — the install/update diff engine (compute what changed).
- **apply** — the apply primitives that actuate a diff on a host (place files,
  create directories, run root commands, load images, extract bundles).
- **bootroot_cmd** — the wrapper around the on-host PKI command.
- **registration** — service registration against the on-host PKI.
- **roxyd_trust** — trust-material activation for the on-host agent.

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
