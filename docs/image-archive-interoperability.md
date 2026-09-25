# Image archive interoperability procedure

deploy-core decides whether a container image archive is acceptable from its
bytes alone: one OCI-layout, single-image `docker save` profile with a Docker
compatibility `manifest.json` and uncompressed or gzip layers. Whether Docker
itself loads such an archive, and refuses nothing the profile admits, is a
separate question that no automated test answers. This document is the manual
procedure that gathers that evidence.

## What this evidence gates

- Support for a particular Docker store and engine version combination is
  claimed only once this procedure has been run against it and its results
  are recorded. A combination nobody has run is unsupported, whatever the
  profile says.
- Missing evidence is reported as **not run**. It is never mocked, never
  inferred from another combination, and never replaced by a test.
- No automated test, example code path or library code invokes Docker.
  Runtime validation never invokes Docker either: `check_image_archive` and
  the validator behind it read bytes only.
- The procedure runs only against **disposable** daemons made for it — a
  throwaway virtual machine or a daemon in its own container with its own
  data root. It never runs against a user's daemon, whose images, tags and
  store it would change.
- Producer-normalized output — the archives bootler's production supply will
  write from real `docker save` exports — is added to the samples below once
  bootler provides it.

## Before you start

Prepare two disposable daemons of the engine version under test:

- one with the classic **graphdriver** image store (`"features":
  {"containerd-snapshotter": false}` in `daemon.json`);
- one with the **containerd** image store (`"features":
  {"containerd-snapshotter": true}`).

For each, record:

- the engine version, from `docker version --format '{{.Server.Version}}'`;
- the store mode, from `docker info --format '{{.Driver}}'` and
  `docker info --format '{{json .DriverStatus}}'`;
- the architecture, from `docker info --format '{{.Architecture}}'`.

Build the example from this repository, whose logic is the public
`image::test_support` API:

```sh
cargo build --example write_synthetic_image --features test-support
EXAMPLE=target/debug/examples/write_synthetic_image
```

Its `write` subcommand writes a sample archive and a matching declaration.
Its `classify` subcommand prints `accepted` and exits 0, or prints the refusal
and exits 1; it exits 2 on a usage or file error.

## Step 1: produce samples

Write at least one sample per architecture the engine runs, with one tag and
with several:

```sh
$EXAMPLE write sample-one.tar sample-one.declaration.json amd64 \
  registry.example/interop/sample:1.0
$EXAMPLE write sample-many.tar sample-many.declaration.json amd64 \
  registry.example/interop/sample:1.0 registry.example/interop/sample:latest
```

## Step 2: load only accepted samples

For each sample, classify it first, and load it only when the classifier
accepts it:

```sh
$EXAMPLE classify sample-one.tar sample-one.declaration.json   # must print: accepted
docker load -i sample-one.tar
```

Load every accepted sample into both disposable daemons, the graphdriver
store and the containerd store. Record the `docker load` output.

## Step 3: check what Docker restored

In each daemon, for each loaded sample:

1. **Tags.** `docker image ls --format '{{.Repository}}:{{.Tag}}'` lists
   exactly the declaration's `public_refs` for this image — every declared
   tag, and no other tag and no `<none>` entry for it.
2. **Config ID.** `docker image inspect <ref> --format '{{.Id}}'` equals the
   declaration's `config_digest`. On the containerd store `.Id` may report
   the image's manifest digest instead. In that case record it, check that
   it equals the sample's manifest digest (the `digest` of its `index.json`
   descriptors), and confirm the config digest by saving the loaded
   reference again and reading the `Config` path of that archive's
   `manifest.json`. Note which check matched.
3. **Platform.** The output of

   ```sh
   docker image inspect <ref> \
     --format '{{.Os}}/{{.Architecture}}/{{with index . "Variant"}}{{.}}{{end}}'
   ```

   matches the declaration's platform: `linux`, the declared architecture,
   and the declared variant or an empty variant for a declared `null`. The
   `index` form matters: when an image has no variant, the inspect output has
   no `Variant` key, and a plain `{{.Variant}}` fails with `map has no entry
   for key "Variant"`.

A mismatch in any of these is a failed run for that store and version, and is
recorded as such.

## Step 4: raw exports are refused before any load

Confirm that the classifier refuses raw `docker save` output from both stores
before anything is loaded. For each daemon:

1. Pull or build a tiny image — `FROM scratch` with one small file — and save
   exactly one reference:

   ```sh
   docker save -o raw.tar <ref>
   ```

2. Derive the declaration from the saved archive itself, so the verdict
   reflects the representation and not a declaration mismatch:
   - **`public_refs`** is exactly the `RepoTags` array of the archive's
     `manifest.json`:

     ```sh
     tar -xOf raw.tar manifest.json
     ```

     If the archive has no `manifest.json`, use `[<ref>]`, the reference
     passed to `docker save`, and record that this fallback was used.
   - **`config_digest`** is `sha256:` followed by the hex in the record's
     `Config` path (`blobs/sha256/<hex>`, or `<hex>.json` in a classic
     export). It must equal:

     ```sh
     docker image inspect <ref> --format '{{.Id}}'
     ```

     That inspect value is also the fallback when there is no
     `manifest.json`. Record any disagreement. On the containerd store
     `.Id` reports the digest of the image index `index.json` points to,
     not the config digest; that disagreement is expected there, and
     `config_digest` still follows the `Config` path.
   - **Architecture and variant** are `.Architecture` and `.Variant` of the
     same inspect, read with the `index` form from step 3. An empty or absent
     variant becomes `null`.
   - **Owner, dependency, lifecycle and provenance** are fixed: owner
     `example-product`/`example-app`, dependency `app`, lifecycle
     `shared_external`, and provenance `product_build` with repository
     `https://example.com/synthetic-images.git` and commit
     `0123456789abcdef0123456789abcdef01234567`.

   Write the declaration as JSON in the form `PayloadArtifact.image` takes in
   a package manifest, for example `raw.declaration.json`.
3. Record the commands, their output and the resulting declaration file with
   the capture's provenance.
4. Classify it and record the exact error the classifier reports:

   ```sh
   $EXAMPLE classify raw.tar raw.declaration.json   # expected: refused, exit 1
   ```

   An `accepted` here is a finding against the profile, not a success.

A capture kept as evidence is checked in under
`assets/test-fixtures/images/` as a `docker-capture` fixture, with its full
provenance in `inventory.json` and the verdict the validator reports; see
`assets/test-fixtures/images/INVENTORY.md`.

## Step 5: record the run

For each daemon, record:

- the engine version, store mode and architecture;
- every command run and its output;
- for each sample, whether it was accepted, loaded, and passed step 3;
- for each raw export, its derived declaration and the exact refusal.

Report the result per store and version as run, with its outcome, or as
**not run**.

## Recorded runs

### 2026-09-25: Docker Engine 29.8.1, `arm64`, both stores

Two disposable daemons, each a `docker:29-dind` container
(`docker@sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0`)
run with `--privileged` and its own data root inside the container. Server
components: Engine 29.8.1, containerd v2.3.5, runc 1.5.1, all `linux/arm64`.

- **graphdriver store:** `daemon.json` set
  `{"features":{"containerd-snapshotter":false}}`, and `docker info`
  reported the driver `overlay2`.
- **containerd store:** `daemon.json` set
  `{"features":{"containerd-snapshotter":true}}`, and `docker info`
  reported the driver `overlayfs` with driver type
  `io.containerd.snapshotter.v1`.

**Samples (steps 1–3).** `write` produced four samples, each classified
`accepted` before loading:

- `amd64` and `arm64`, each with one tag
  (`registry.example/interop/sample-<arch>:1.0`);
- `amd64` and `arm64`, each with two tags
  (`registry.example/interop/many-<arch>:1.0` and `:latest`).

The checked-in `explicit-variant` fixture (`arm64`/`v8`) was loaded as well,
since `write` only produces a null variant.

On both daemons, every sample loaded and passed step 3:

- **Tags.** `docker load` reported exactly the declared tags, and
  `docker image ls -a` listed exactly those tags, with no other tag and no
  `<none>` entry.
- **Config ID.** On the graphdriver store, `.Id` equalled the declared
  `config_digest` for every sample. On the containerd store, `.Id` was the
  sample's manifest digest (the `digest` of its `index.json` descriptor).
  Saving `sample-arm64:1.0` and `many-amd64:latest` again from that daemon
  gave a `manifest.json` whose `Config` path is the declared
  `config_digest`. The manifest-digest check and the re-save check both
  matched.
- **Platform.** `linux/amd64/` and `linux/arm64/` (empty variant) for the
  null-variant samples, and `linux/arm64/v8` for `explicit-variant`, on both
  stores.

**Raw exports (step 4).** Each daemon built `FROM scratch` with one six-byte
file and saved `registry.example/interop/raw-<store>:1.0`. The declarations
were derived from each archive's `manifest.json`, with no fallback. Neither
export was loaded anywhere. `classify` refused both, exit code 1:

- graphdriver:
  ``image archive `raw-gd.tar` uses a legacy docker-save export file``
  (`UnsupportedArchive`, `LegacyExportFile`). The export carries
  `repositories`, `blobs/` directory entries and `LayerSources`.
- containerd:
  ``image archive `raw-cd.tar` uses a nested image index``
  (`UnsupportedArchive`, `NestedIndex`). `index.json` points to an image
  index that also lists an attestation manifest. `.Id` was that index's
  digest, not the config digest, and this disagreement was recorded.

Both exports are checked in as the `docker-capture` fixtures
`docker-graphdriver-scratch` and `docker-containerd-scratch`, with their full
capture records in `assets/test-fixtures/images/inventory.json`.

**Result.** Engine 29.8.1 on `arm64`, graphdriver store: run, passed.
Engine 29.8.1 on `arm64`, containerd store: run, passed. No other engine
version, architecture or store combination has been run.
