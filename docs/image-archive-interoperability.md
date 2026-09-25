# Image archive interoperability procedure

deploy-core decides whether a container image archive is acceptable from its
bytes alone: one OCI-layout, single-image `docker save` profile with a Docker
compatibility `manifest.json` and uncompressed or gzip layers. Whether Docker
itself loads such an archive, and refuses nothing the profile admits, is a
separate question that no automated test answers. This document is the manual
procedure that gathers that evidence.

## What this evidence gates

- Support for a particular Docker store and engine version combination is
  claimed only once this procedure has been run against it, every check
  passed, and the exact commands and their outputs are retained. A
  combination nobody has run is unsupported, whatever the profile says.
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

### Kinds of evidence

Every statement in a run record is one of these, and says which:

- **Retained output** — a command that was run, kept with its exact command
  line, its complete output and its exit code in a checked-in transcript.
  Only retained output can support a pass.
- **Historical observation** — something a run reported, as a summary or a
  recorded value, without keeping the command output that showed it. It is
  kept as recorded and is never presented as a transcript.
- **Later extraction** — output produced afterwards from a checked-in
  artifact, such as reading `manifest.json` out of a checked-in capture. It
  is labelled with when it was made and is never presented as the output of
  the original command.

### Results

Each store and version combination a run covers gets one result:

- **passed** — every check in steps 2 to 4 matched, and the retained output
  shows every one of them;
- **failed** — a check did not match. A failed check stays failed whatever
  else the run recorded;
- **incomplete** — no check is known to have failed, but outputs a pass
  needs were not retained. Nothing can be claimed from it;
- **not run**.

A failed check and missing evidence are different findings and are reported
separately: a run can be both failed and incomplete. Neither is a pass.

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

Capture every command from here on as retained output: print the exact
command line, then its combined standard output and standard error, then its
exit code, into one transcript per daemon. Run under `LC_ALL=C` so dates and
messages are in English. The script used for run 2, under
[Recorded runs](#recorded-runs), does this and can serve as a template.

## Step 1: produce samples

Write at least one sample per architecture the engine runs, with one tag and
with several:

```sh
$EXAMPLE write sample-one.tar sample-one.declaration.json amd64 \
  registry.example/interop/sample:1.0
$EXAMPLE write sample-many.tar sample-many.declaration.json amd64 \
  registry.example/interop/sample:1.0 registry.example/interop/sample:latest
```

`write` produces the same image for the same architecture, so samples of one
architecture share a config digest and differ only in their tags.

## Step 2: load only accepted samples

For each sample, classify it first, and load it only when the classifier
accepts it:

```sh
$EXAMPLE classify sample-one.tar sample-one.declaration.json   # must print: accepted
docker load -i sample-one.tar
```

Load every accepted sample into both disposable daemons, the graphdriver
store and the containerd store. Load one sample at a time, into a store that
holds no image with that sample's config digest: after step 3 for a sample,
remove its tags with `docker image rm <ref>...` before loading the next.
Otherwise a later sample with the same config adds its tags to the image an
earlier one restored, and the tag check can no longer tell which load
restored which tag.

## Step 3: check what Docker restored

In each daemon, for each loaded sample, run and retain:

1. **Tags.** `docker load` reports exactly the declaration's `public_refs`,
   and `docker image ls -a --no-trunc --format '{{.Repository}}:{{.Tag}}
   {{.ID}}'` lists exactly those tags for this image — every declared tag,
   and no other tag and no `<none>` entry for it. For each declared
   reference, `docker image inspect <ref> --format '{{json .RepoTags}}'`
   lists exactly the declared tags.
2. **Config ID.** For each declared reference,

   ```sh
   docker image inspect <ref> --format '{{.Id}}'
   ```

   prints exactly the declaration's `config_digest`. This equality is the
   check, and it is mandatory: a loaded sample whose `.Id` differs has
   failed this check for that store and version, and the combination is
   **failed**.

   Nothing else substitutes for it. On the containerd store `.Id` reports
   the image's manifest digest, not its config digest. Two diagnostics may
   be recorded next to a mismatch, as **supplemental** evidence only:
   - whether `.Id` equals the sample's manifest digest, the `digest` of its
     `index.json` descriptors;
   - whether saving the loaded reference again gives a `manifest.json` whose
     `Config` path names the declared `config_digest`.

   Either diagnostic may explain the mismatch. Neither turns a failed
   config-ID check into a pass.
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
recorded as such, with the observed value next to the declared one.

## Step 4: raw exports are refused before any load

Confirm that the classifier refuses raw `docker save` output from both stores
before anything is loaded. Do this in each daemon before step 2 loads any
sample, and never load the raw export anywhere. For each daemon:

1. Build a tiny image — `FROM scratch` with one small file — and save
   exactly one reference:

   ```sh
   docker save -o raw.tar <ref>
   ```

2. Derive the declaration from the saved archive itself, so the verdict
   reflects the representation and not a declaration mismatch:
   - **`public_refs`** is exactly the `RepoTags` array of the archive's
     `manifest.json`. Run, and retain the output of:

     ```sh
     tar -xOf raw.tar manifest.json
     ```

     If the archive has no `manifest.json`, use `[<ref>]`, the reference
     passed to `docker save`, and record that this fallback was used.
   - **`config_digest`** is `sha256:` followed by the hex in the record's
     `Config` path (`blobs/sha256/<hex>`, or `<hex>.json` in a classic
     export). Also run, and retain the output of:

     ```sh
     docker image inspect <ref> --format '{{.Id}}'
     ```

     That inspect value is the fallback when there is no `manifest.json`.
     Record any disagreement between the two. On the containerd store `.Id`
     reports the digest of the image index `index.json` points to, not the
     config digest; the declaration still follows the `Config` path. This
     derivation is not step 3's config-ID check, and a disagreement here is
     recorded but does not decide the raw export's verdict.
   - **Architecture and variant** are `.Architecture` and `.Variant` of the
     same inspect, read with the `index` form from step 3. An empty or absent
     variant becomes `null`.
   - **Owner, dependency, lifecycle and provenance** are fixed: owner
     `example-product`/`example-app`, dependency `app`, lifecycle
     `shared_external`, and provenance `product_build` with repository
     `https://example.com/synthetic-images.git` and commit
     `0123456789abcdef0123456789abcdef01234567`.

   Write the declaration as JSON in the form `PayloadArtifact.image` takes in
   a package manifest, for example `raw.declaration.json`, and retain its
   contents in the transcript.
3. Classify it and retain the exact error the classifier reports:

   ```sh
   $EXAMPLE classify raw.tar raw.declaration.json   # expected: refused, exit 1
   ```

   An `accepted` here is a finding against the profile, not a success.

A capture kept as evidence is checked in under
`assets/test-fixtures/images/` as a `docker-capture` fixture, with its full
provenance in `inventory.json` and the verdict the validator reports; see
`assets/test-fixtures/images/INVENTORY.md`. A capture is never replaced or
renamed afterwards: a new run's capture gets a new name and its own record.

## Step 5: record the run

Check the transcripts in under `docs/image-archive-interop-runs/`, in a
directory named for the date, engine version, architecture and run. For each
daemon they show:

- the engine version, store mode and architecture;
- every command run, its complete output and its exit code;
- for each sample, its declaration, the `classify` verdict, the `docker load`
  output, the image listing and the three step 3 inspects;
- for each raw export, the `manifest.json` output, the inspect output, the
  derived declaration and the exact refusal, before any sample was loaded.

Then add the run to [Recorded runs](#recorded-runs) and report each store and
version combination as passed, failed, incomplete or not run, as defined
under [Results](#results). A combination is reported as passed only when its
transcript shows every check above. Where an output was not retained, say
which, and do not reconstruct it from a summary, another engine or another
store.

## Recorded runs

### Support summary

| Engine | Architecture | Store | Result | Evidence |
| --- | --- | --- | --- | --- |
| 29.8.1 | `arm64` | graphdriver | passed | run 2 |
| 29.8.1 | `arm64` | containerd | failed: config ID | runs 1 and 2 |

No other engine version, architecture or store combination has been run;
each is **not run**.

### Run 2, 2026-09-25: Docker Engine 29.8.1, `arm64`, both stores

A fresh run with every output retained. The transcripts are in
[`image-archive-interop-runs/2026-09-25-engine-29.8.1-arm64-run-2/`](image-archive-interop-runs/2026-09-25-engine-29.8.1-arm64-run-2/):

- `run.sh` — the script that ran the procedure. It printed each command
  verbatim, then its combined output and its exit code. It ran from
  `target/interop-run/` of a checkout at commit
  `4dee63ef87026c810f3554b50ecc0a7421b8d8ed`, under `LC_ALL=C`.
- `samples.txt` — step 1, from
  2026-09-25T13:37:15Z: building the example, the four `write` commands,
  copying the `explicit-variant` fixture, and each sample's declaration,
  SHA-256 and `index.json`.
- `graphdriver.txt` — the graphdriver daemon, 2026-09-25T13:37:15Z to
  13:37:27Z.
- `containerd.txt` — the containerd daemon, 2026-09-25T13:37:28Z to
  13:37:41Z.
- `graphdriver-superseded-attempt.txt` — an earlier graphdriver attempt the
  same day, kept for completeness and not part of this run's result. It
  loaded all samples into one store without removing tags between them, so
  its tag check is inconclusive (see step 2), and its raw export was not
  kept. Its `tar -tv` dates print in the host's Korean locale.

**Daemons.** Two disposable daemons, each a `docker:29-dind` container
(`docker@sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0`)
started with `docker run -d --rm --privileged`, with its own data root inside
the container and the store's `daemon.json` mounted read-only. The host
daemon only ran these two containers, which were stopped and removed at the
end; every command under test ran against the inner daemons through
`docker exec`. Both report Engine 29.8.1, containerd v2.3.5 and runc 1.5.1,
`linux/arm64` from `docker version`, and `aarch64` from
`docker info --format '{{.Architecture}}'`.

- **graphdriver store:** `daemon.json`
  `{"features":{"containerd-snapshotter":false}}`; `docker info` reported
  the driver `overlay2`.
- **containerd store:** `daemon.json`
  `{"features":{"containerd-snapshotter":true}}`; `docker info` reported
  the driver `overlayfs` with driver type `io.containerd.snapshotter.v1`.

**Samples.** `write` produced `sample-amd64` and `sample-arm64`, each tagged
`registry.example/interop/sample-<arch>:1.0`, and `many-amd64` and
`many-arm64`, each tagged `registry.example/interop/many-<arch>:1.0` and
`:latest`. The checked-in `explicit-variant` fixture (`arm64`/`v8`) was loaded
as well, since `write` only produces a null variant. Each was classified
`accepted` before it was loaded, loaded alone, checked, and removed.

| Sample | Declared `config_digest` | Manifest digest |
| --- | --- | --- |
| `sample-amd64`, `many-amd64` | `ef49718b…b9bf1d` | `a2200f9b…a0a607` |
| `sample-arm64`, `many-arm64` | `406c010d…6f3b6c` | `8b0b6a54…a7155d` |
| `explicit-variant` | `88996685…c9f283` | `3c35860a…a27fd8` |

Each digest is a `sha256:` value, abbreviated here; the transcripts carry
them in full.

**graphdriver: passed.** For every sample, `docker load` reported exactly the
declared tags, the listing and `RepoTags` held exactly those tags with no
`<none>` entry, `.Id` printed the declared `config_digest` for every declared
reference, and the platform printed `linux/amd64/`, `linux/arm64/` or
`linux/arm64/v8` as declared.

**containerd: failed, config ID.** Tags and platform matched as on the
graphdriver store. The mandatory config-ID check failed for every sample:
`.Id` printed the sample's manifest digest, not its declared
`config_digest` — for example `sha256:a2200f9b…a0a607` for
`registry.example/interop/sample-amd64:1.0`, declared
`sha256:ef49718b…b9bf1d`. As a supplemental diagnostic only, every `.Id`
equalled the `index.json` descriptor digest printed before the load. That
explains the mismatch and does not change the result. No re-save diagnostic
was run.

**Raw exports.** In each daemon, before any sample was loaded, the daemon
built `FROM scratch` with the six-byte file `hello.txt` and saved
`registry.example/interop/raw-<gd|cd>-run2:1.0`. The retained
`manifest.json` outputs were:

```json
[{"Config":"blobs/sha256/b26bb177eaa91ddfb9e281b108232849bb25942f6f18501194bff7a0b99003ee","RepoTags":["registry.example/interop/raw-gd-run2:1.0"],"Layers":["blobs/sha256/2b5d2cb60e88dee8d08cc6af83b83addbe7178774d8c985c5bfb828575241a02"],"LayerSources":{"sha256:2b5d2cb60e88dee8d08cc6af83b83addbe7178774d8c985c5bfb828575241a02":{"mediaType":"application/vnd.oci.image.layer.v1.tar","size":2048,"digest":"sha256:2b5d2cb60e88dee8d08cc6af83b83addbe7178774d8c985c5bfb828575241a02"}}}]
```

```json
[{"Config":"blobs/sha256/143ed2bacf3134effc4fec01dc3a32cc284e56e6e204953919f3d836a738f5fd","RepoTags":["registry.example/interop/raw-cd-run2:1.0"],"Layers":["blobs/sha256/739a881b1fc0e2ebe88d6256f9a3f5d6df70eedd3290bb32d5fb9a0d9054d69d"]}]
```

The declarations were derived from them with no fallback, and each is shown
in its transcript. The graphdriver `.Id` equalled the `Config` digest; the
containerd `.Id` was the image index digest
`sha256:8d7a672b0bb9df20685029ab74fbd01ad656790117982b7a8f94d5b8251550a7`,
and this disagreement was recorded. Neither export was loaded. `classify`
refused both with exit code 1:

- graphdriver:
  ``image archive `work/graphdriver/raw-gd-run2.tar` uses a legacy
  docker-save export file`` (`UnsupportedArchive`, `LegacyExportFile`);
- containerd:
  ``image archive `work/containerd/raw-cd-run2.tar` uses a nested image
  index`` (`UnsupportedArchive`, `NestedIndex`).

Both exports are checked in, bytes unchanged, as the `docker-capture`
fixtures `docker-graphdriver-scratch-run2` and
`docker-containerd-scratch-run2`.

### Run 1, 2026-09-25: Docker Engine 29.8.1, `arm64`, both stores

An earlier run on the same engine, recorded as a summary. **Its command
outputs were not retained**, so none of what follows is retained output: it
is historical observation, kept as the run reported it. It had reported both
stores as passed. Corrected under the rules above:

- graphdriver: **incomplete**. No failed check was reported, but the outputs
  a pass needs were not retained. It supports no claim; run 2 is the
  evidence for this combination.
- containerd: **failed, config ID**, and **incomplete**. The run observed
  that `.Id` was each loaded sample's manifest digest rather than its
  declared `config_digest`. The per-sample digests were not recorded. The run
  then substituted the manifest-digest and re-save checks for the config-ID
  check and reported a pass; those two checks are supplemental diagnostics
  only, and do not change the failure.

What the run reported, not retained as output:

- Two disposable daemons, each the same `docker:29-dind` image as run 2, run
  with `--privileged` and its own data root inside the container. Engine
  29.8.1, containerd v2.3.5, runc 1.5.1, all `linux/arm64`. The graphdriver
  store's `docker info` reported `overlay2`; the containerd store's reported
  `overlayfs` with driver type `io.containerd.snapshotter.v1`.
- `write` produced four samples, `sample-<arch>:1.0` and `many-<arch>:1.0`
  and `:latest` for `amd64` and `arm64`, each reported as classified
  `accepted` before loading, and the `explicit-variant` fixture was loaded as
  well. On both daemons every sample was reported as loaded with its
  declared tags and its declared platform. On the graphdriver store `.Id`
  was reported equal to the declared `config_digest` for every sample. On
  the containerd store it was reported as the manifest digest; saving
  `sample-arm64:1.0` and `many-amd64:latest` again was reported to give a
  `manifest.json` whose `Config` path is the declared `config_digest`.
- Each daemon built `FROM scratch` with one six-byte file and saved
  `registry.example/interop/raw-<gd|cd>:1.0`. The declarations were reported
  as derived from each archive's `manifest.json` with no fallback. For the
  containerd export the run recorded `.Id`
  `sha256:ca34fcd24e5149d0d0efb77248685d45e20d12d02a50a0dfe9d380d543f077ff`,
  the image index digest, against the `Config` digest
  `sha256:4d3513a55c81a90e8ade85146882cb40ea0480961be2105bfd5c3c74fd4ff237`
  that the declaration uses. `classify` was reported to refuse both with
  exit code 1: ``image archive `raw-gd.tar` uses a legacy docker-save
  export file`` (`LegacyExportFile`) for graphdriver and ``image archive
  `raw-cd.tar` uses a nested image index`` (`NestedIndex`) for containerd.
  Neither export was reported as loaded. With no transcript,
  the order of classification and loading is unverified.

What is retained: the two raw exports, checked in with their bytes unchanged
as `docker-graphdriver-scratch` and `docker-containerd-scratch`, their
declarations, their SHA-256 values, and the validator verdicts the inventory
tests check against those bytes.

**Later extraction.** To show what each declaration was derived from, the
`manifest.json` of each checked-in capture was read on 2026-09-25, after
run 1, and the captures were classified again.
[`image-archive-interop-runs/2026-09-25-engine-29.8.1-arm64-run-1/later-extraction.txt`](image-archive-interop-runs/2026-09-25-engine-29.8.1-arm64-run-1/later-extraction.txt)
holds that output. It is not run 1's output. The graphdriver capture's
`manifest.json`:

```json
[{"Config":"blobs/sha256/830c106a738a79799b9adf67a8a0caf84046d579a4faef8e2588595b93288182","RepoTags":["registry.example/interop/raw-gd:1.0"],"Layers":["blobs/sha256/8904da134fd4d9e9dcd17c59edac74028c5459d4abfc9db4ff4f62a2cafdcceb"],"LayerSources":{"sha256:8904da134fd4d9e9dcd17c59edac74028c5459d4abfc9db4ff4f62a2cafdcceb":{"mediaType":"application/vnd.oci.image.layer.v1.tar","size":2048,"digest":"sha256:8904da134fd4d9e9dcd17c59edac74028c5459d4abfc9db4ff4f62a2cafdcceb"}}}]
```

The containerd capture's `manifest.json`:

```json
[{"Config":"blobs/sha256/4d3513a55c81a90e8ade85146882cb40ea0480961be2105bfd5c3c74fd4ff237","RepoTags":["registry.example/interop/raw-cd:1.0"],"Layers":["blobs/sha256/9b343a86367942b345bb3453a8668b14bea0a9d50a436c6423bcda04344f7e70"]}]
```

Each declaration's `public_refs` is that record's `RepoTags`, and its
`config_digest` is `sha256:` plus the hex of its `Config` path.
