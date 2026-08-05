# Instructions for AI coding agents

The marked regions below are generated from
[aicers/agent-instructions](https://github.com/aicers/agent-instructions).
Do not edit them here — change the wording upstream, tag a release, and
re-run its sync. The drift check in CI fails if this copy diverges.

<!-- BEGIN shared:workflow v1 -->
## Language

- Code, comments, commit messages, PR descriptions, and issues are written
  in English.

## Commit messages

- Title: preferably under 50 characters, start with an imperative verb
  (e.g., `Add`, `Fix`, `Remove`).
- Do NOT use prefixes such as `feat:`, `chore:`, or `fix:`.
- Do NOT put issue or PR numbers in the title.
- Body: wrap at 72 characters, free-form, explain *why* not *what*.
- Separate title and body with a blank line.
- Reference issues in the body, not the title: `Closes #N` to close an
  issue, or `Part of #N` when the commit addresses part of one.

## Branching and pushing

- NEVER push directly to `main`. Always create a new branch before
  pushing.
- Branch names must follow the format `<github-username>/issue-#` (e.g.,
  `alice/issue-42`). If there is no related issue, ask the user how to
  proceed before creating the branch.
- The sole exception is a branch carrying a synced update to the shared
  blocks below, which uses `<github-username>/instructions-<label>` and
  needs no issue.

## GitHub issues and PRs

- Do NOT hard-wrap lines in issue or PR body text. GitHub renders
  Markdown, so manual line breaks hurt readability. (This applies to the
  body text only — commit messages still wrap at 72.)
- Issues and PRs share ONE number namespace, so `gh issue edit N` and
  `gh issue view N` can silently operate on PR #N when N is a PR. Before
  ANY `gh` write (edit, close, comment), confirm the target's type and
  identity with a read first: `gh issue view N --json
  number,title,state,url`, and check `/pull/` vs `/issues/` in the URL.
- Never act on failed or garbled command output. Re-verify every create
  and edit with a structured `--json` re-query before reporting success.

## Attribution

- Do NOT add `Co-Authored-By` lines naming an AI (`Claude`, `Codex`,
  `Gemini`, or any similar name) to commit messages.
- Do NOT add "Generated with Claude Code", "Generated with Codex",
  "Generated with Gemini", or any similar AI attribution to PR
  descriptions or issue comments.
<!-- END shared:workflow -->

<!-- BEGIN shared:rust v2 -->
## Coding standards (Rust)

### Errors and panics

- **Error types**: Use `anyhow::Result` for application code and
  `thiserror` for library code — that is, use `thiserror` when a caller
  needs to match on the error kind, `anyhow` otherwise.
- **Context**: Attach context to every fallible call that crosses a
  meaningful boundary: `.with_context(|| format!("reading config from
  {path}"))`. State what was being attempted and on which concrete target
  (path, host, service name). Start lowercase, no trailing period, and do
  not repeat what an outer layer will already say.
- **No `unwrap()`**: Do not use `unwrap()` in production code. Usage in
  tests is permitted.
- **`expect("reason")`**: Use when you are certain a panic will NOT occur.
  The message must explain *why* the condition is invariant. Never
  `expect()` on a value derived from network input, file contents, or
  configuration — those are recoverable errors, not invariants.
- **`panic!("reason")`**: Use when you intentionally need to crash the
  program to alert the user of a critical, unrecoverable state.
- **Indexed access**: Prefer methods that return `Option`/`Result`
  (`.get()`, `.first()`, `.next()`) over `[]` on `&[T]`, `Vec<T>`, and
  arrays. Indexing is acceptable only when the bound is established
  immediately above the access and is locally obvious to a reader.
  Indexing a `HashMap`/`BTreeMap` with `[]` is never acceptable.

### Types and conversions

- **Prefer `enum` over `String`** whenever a finite set of values is
  expected.
- **Type casting (`as`)**: `as` checks nothing and reports nothing. Use
  the checked form wherever one exists. Two directions have none, and
  there `as` is a decision to be stated, not a reflex.
  - **Integer to integer, lossless**: use `From` — `u64::from(value)`,
    not `value as u64`. The compiler enforces the losslessness: change
    the types so the conversion no longer fits and the impl is gone and
    the build fails, where `as` would silently start truncating.
  - **Integer to integer, otherwise**: use `TryFrom`/`try_into()` and
    propagate the `TryFromIntError`.
  - **Float to integer**: no `TryFrom` exists, and `as` saturates and
    maps `NaN` to 0. Check the value is finite and in range yourself,
    or use `num-traits`' `ToPrimitive` (`to_u32()`, ...) in a crate
    that already depends on it — subject to the dependency rule below,
    since an explicit check needs nothing. Either way, decide about the
    fraction: `ToPrimitive` rejects `NaN` and out-of-range, then
    truncates toward zero, so `(-0.9_f64).to_u32()` is `Some(0)`. Where
    the value was supposed to be integral, handling the `None` is not
    enough — test `fract() == 0.0` too.
  - **Integer to float**: `From` where it exists (`f64::from(x: u32)`)
    — exactly the conversions that cannot lose anything. Past them
    nothing checks: `u64 as f64` rounds above 2^53, and `f32` stops
    being exact above 2^24. Nor does `ToPrimitive` here — `to_f64()`
    and `to_f32()` are `Some(x as _)`, leaving a `None` arm that can
    never run. Use `as` after deciding rounding is acceptable across
    the value's real range, and record why where that is not obvious.
  - **Float to float**: `f64::from(x: f32)` widens exactly. Narrowing
    has no checked form — `f64 as f32` rounds to nearest, so a value
    just past `f32::MAX` lands back on it, and only one large enough to
    overflow becomes infinity. Neither is an error. Same rule: a
    decision, never a default.
  - `num-traits` is also the right tool for code generic over numeric
    types. Use `num-derive` only to derive its `FromPrimitive` and
    `ToPrimitive` on simple enums or newtypes; it is not std's
    `TryFrom`, which an enum rejecting an unknown discriminant still
    needs.

### Ownership and performance

- **Minimizing `clone`**: Avoid unnecessary `clone()` or similar methods
  (e.g., `to_string()`, `to_owned()`). Performance-critical code must not
  harbour hidden copies.
  - **Prefer references and slices**: Use `&str` over `String` and `&[T]`
    over `Vec<T>` for function parameters and struct field getters. This
    avoids copies and increases compatibility via deref coercion.
  - **Defer cloning**: When cloning is unavoidable, call it at the latest
    possible stage to minimise the scope of copied data and to make the
    necessity visible.
  - **Use clone-avoiding idioms**: Prefer `Iterator::cloned()`,
    `Option::cloned()`, and `Option::as_deref()` over explicit
    `.map(Clone::clone)` or manual unwrap-and-clone patterns.
- **Sorting**: Prefer `sort_unstable`, `sort_unstable_by`, and
  `sort_unstable_by_key` over their stable counterparts. The unstable
  variants are faster and allocate no extra memory. Use stable `sort` only
  when equal elements must preserve their original relative order, and
  `sort_by_cached_key` when the key is expensive to compute.

### Async

Where the crate has async code:

- Use the `tokio` runtime. Avoid blocking operations in async contexts.
- **No orphan tasks**: Do not discard the `JoinHandle` returned by
  `tokio::spawn`. Hold it, or use a `JoinSet`, and cancel outstanding
  tasks on shutdown. A dropped handle turns a task failure into silence.
- **No locks across `.await`**: Never hold a `std::sync::Mutex`/`RwLock`
  guard across an `.await` point (`clippy::await_holding_lock`). Use
  `tokio::sync` primitives, or scope the guard so it is dropped first.
- **Cancellation safety**: Every branch of `tokio::select!` must be
  cancel-safe. Where a future is not, spawning it and selecting on the
  handle is not by itself the fix: a losing branch drops the handle,
  the task detaches, and it keeps running unobserved — exactly the
  orphan the rule above forbids. Spawn it once into a `JoinSet` or a
  field the loop owns, select on that, and join or abort it at
  shutdown.

### `unsafe`

- Do not introduce new `unsafe`. If FFI or a platform call makes it
  unavoidable, keep the block as small as possible and precede it with a
  `// SAFETY:` comment stating the invariant that makes it sound.
- Note that in edition 2024 `std::env::set_var`/`remove_var` are `unsafe`;
  the `SAFETY` comment must justify why no other thread can be reading the
  environment at that point.

### Files and I/O

- **Atomic writes**: Write state, config, and other files that another
  process may read atomically — write to a temporary file in the same
  directory, then `fs::rename`. Never truncate-and-write in place.
- **Restrictive permissions at creation**: A file holding a secret gets
  its final permissions as it is created, never afterwards —
  `set_permissions` once the bytes are on disk leaves a window in which
  the file is world-readable. On Unix that is
  `OpenOptions::new().mode(0o600)`, from
  `std::os::unix::fs::OpenOptionsExt`. These crates target Unix; if one
  ever ships elsewhere, the equivalent has to exist before the first
  byte is written.

### Output and logging

- Reserve `stdout` for output the user asked for. All diagnostics,
  progress, and debugging go through `tracing`.

### Secrets

- Do not carry a secret (token, password, private key material) as a
  bare `String`. Wrap it in a newtype whose hand-written `Debug` prints
  `<redacted>`, so a `#[derive(Debug)]` on an enclosing struct cannot
  leak it.
- Never interpolate a secret into a `tracing` event, an error message,
  or a `Display` implementation.
- A secret read from a file or an environment variable is still a
  secret. Wrap it at the boundary where it enters the program, not
  wherever it is eventually used.

### Certificate verification

Where the crate verifies certificates:

- Verification is never disabled or weakened to make something work. If
  a handshake or a chain check fails, fix the trust anchors, the SANs,
  or the clock. There is no temporary exception here — only permanent
  ones that were introduced temporarily.
- All verification lives in one dedicated module per crate, named in the
  repository-specific section below, whether it reaches for a library's
  escape hatch (`rustls`'s `dangerous()`, a hand-written
  `ServerCertVerifier` or `ClientCertVerifier`) or drives a verifier
  directly (`webpki`'s `EndEntityCert`). Do not verify anywhere else,
  and do not add a new path without a design decision recorded in the
  pull request.
- Never widen what is accepted — algorithms, key usages, name
  constraints, validity windows — to make one certificate pass. Widening
  admits every other certificate that fits the new opening, not only the
  one in front of you.

### Cryptography

Where the crate handles key material or secrets:

- Compare secrets, tokens, MACs, and certificate fingerprints in
  constant time — `ring::constant_time::verify_slices_are_equal` in a
  crate that already depends on `ring`. Never `==`: the derived
  `PartialEq` on a secret-bearing type is a timing oracle.
- Draw key material, and any value whose security rests on being
  unguessable (session identifiers, API keys, opaque bearer tokens),
  from a cryptographically secure source (`ring::rand::SystemRandom`)
  — never from a general-purpose PRNG, a timestamp, or a process ID.
  A signed token such as a JWT is not drawn this way at all: its
  strength comes from the signing key, which is key material.
- A nonce must meet whatever its construction documents, which is
  usually uniqueness under a given key rather than randomness. Counter
  and deterministically derived nonces are correct where the algorithm
  calls for them. What is never acceptable is reusing one under the
  same key.
- Do not implement a cryptographic primitive by hand. If the operation is
  not available in an existing dependency, that is a design discussion,
  not a coding task.

### Visibility, imports, and modules

- **Visibility**: Expose the minimum necessary scope.
  - Prefer `pub(super)` or `pub(crate)` over `pub`. Use `pub` only for
    library public APIs exported from `lib.rs`.
  - When adding a new item, start with the most restrictive visibility and
    widen only when a compiler error or an explicit design decision
    requires it.
- **Imports**: Do NOT use wildcard imports (`use module::*`). The only
  exception is `use super::*` inside `#[cfg(test)]` test modules.
- **Module files**: Prefer `module_name.rs` over `module_name/mod.rs`. Use
  the named sibling file style introduced in Rust 2018.

### Constants and comments

- Use `const` for fixed values instead of "magic strings/numbers".
- Define constants at the top of the file. A `const` used by exactly one
  function may live inside that function.
- Keep test-only constants near the tests for readability.
- Delete redundant or "noisy" comments that just describe code syntax.

### Documentation (rustdoc)

- Every public item opens its doc comment with one concise summary
  sentence. For functions that sentence starts with a verb in the
  **third-person singular** ("Creates...", "Returns...",
  "Calculates..."); types, traits, modules, and constants take a noun
  phrase instead ("A connection pool that...").
- Every public function returning `Result` needs an `# Errors` section,
  and every one that can panic needs a `# Panics` section, describing the
  conditions rather than restating the type.
- Mark functions whose return value is the entire point with `#[must_use]`.

### Dependencies

- Adding a dependency requires a stated reason. Prefer the standard
  library, then an existing dependency of the crate, before adding a new
  one.
- Do not add a dependency for functionality that a crate already in
  `Cargo.toml` provides.

### Testing

- Use `tempfile::tempdir()` for tests that need temporary files or
  directories. Never write to fixed paths.
- Do not mutate the process environment in tests. Pass the value in as a
  parameter, or set it for a child process with `Command::env`. In
  edition 2024 `env::set_var` is `unsafe` because another thread reading
  the environment concurrently is undefined behaviour, and a `Mutex`
  shared between tests does not establish otherwise: it serialises the
  tests and says nothing about a runtime thread or a dependency reading
  in the background. Where tests already do this, removing it is the
  fix, not adding another lock.
- Do not synchronise with `sleep`. Await the condition, or use
  `tokio::time` pause/advance with the `test-util` feature.
- Do not hard-code port numbers; bind port 0 and read back the assigned
  address.
- Tests must not reach the network. Use a local mock server.

### Linting and formatting

- **Linting**: Code MUST pass `cargo clippy` with `-D warnings`, over
  every target and every feature configuration the crate supports. The
  repository-specific section below names the exact invocations; they
  must match what CI runs.
  - `--all-targets` covers lib, bins, tests, benches, and examples. It
    does NOT touch features — with it alone, code behind a non-default
    feature is never linted at all.
  - `--all-features` is correct only when every feature can be on at
    once. Where a crate has mutually exclusive features, that
    combination does not compile; lint each configuration separately
    with `--no-default-features --features <name>`.
- **Formatting**: Code MUST be formatted with `rustfmt`. `group_imports`
  is still nightly-gated, so it cannot live in `rustfmt.toml` — pass it on
  the command line, exactly as CI does:

  ```sh
  cargo fmt -- --config group_imports=StdExternalCrate
  ```

  Plain `cargo fmt`, including editor format-on-save, will NOT group
  imports and will produce a result CI rejects.
- **`#[allow(...)]`**:
  - Avoid `#[allow(...)]` as much as possible.
  - If `allow` is necessary, you MUST add a comment explaining why.
  - Exceptions: `clippy::too_many_lines` can be treated loosely.
<!-- END shared:rust -->

## This crate

- `deploy-core` is a library. `bootler` depends on it at a pinned git
  rev, and the per-machine root daemon depends on it too, so a change
  here reaches a shipping installer without an intermediate release to
  catch it.
- Errors are `thiserror`, and callers match on the variants.
- It carries no product concept — no component catalog, no
  per-component renderers. Keep it that way: anything that names a
  product belongs in the caller.
- Certificate verification lives in `src/roxyd_trust.rs`, which drives
  `webpki`'s `EndEntityCert` directly rather than going through
  `rustls`. That is the one module the shared rule refers to.

## Features

`test-support` exists only to expose the test-only account fixtures
(`Principal::Fixture`, `ServiceAccount::Fixture`) across the crate
boundary, since `cfg(test)` is invisible to dependents. Enable it in a
dependent's `[dev-dependencies]` only — never under `[dependencies]`,
so the fixtures stay out of every release build.

## CI requirements

Before pushing, run what CI runs:

```sh
cargo fmt -- --check --config group_imports=StdExternalCrate
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features test-support -- -D warnings
cargo test
cargo test --features test-support
```

Clippy and the tests each run twice because `--all-targets` touches no
features: code behind `test-support` is invisible to the first run, and
that feature exists precisely to change what compiles.
