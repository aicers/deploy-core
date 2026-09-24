<!-- markdownlint-disable-file MD013 -->
<!-- Keep contract paragraphs and tables on semantic source lines. -->

# RFC 0001: Image evidence and detached package writing

Status: proposed deploy-core implementation design for human review; no runtime implementation is delivered by this RFC. Documentation preparation is tracked by [#96](https://github.com/aicers/deploy-core/issues/96). After human merge, the single AgentCoop RFC-to-issues input is `docs/rfcs/0001-image-evidence-and-package-writer.md`, relative to this repository's root on its default branch. Do not dispatch the entire implementation as the documentation issue.

## 1. Authority, inspected baseline and scope

The approved shared authority is [bootler RFC 0004](https://github.com/aicers/bootler/blob/5dc6b2ed8c9e9ae075a7d6bfbf89f9e1371739c5/docs/rfcs/0004-module-packaging-and-core-extraction.md) together with its [normative image package contract](https://github.com/aicers/bootler/blob/5dc6b2ed8c9e9ae075a7d6bfbf89f9e1371739c5/docs/rfcs/0004-image-package-contract.md), merged in [bootler #376](https://github.com/aicers/bootler/pull/376). [Bootler RFC 0001's producer contract](https://github.com/aicers/bootler/blob/5dc6b2ed8c9e9ae075a7d6bfbf89f9e1371739c5/docs/rfcs/0001-common-image-release.md) owns assembly, release selection and CI. References provide provenance; all requirements needed for this bounded deploy-core decomposition are stated here. This document does not supersede those owners or authorize foreign repository changes.

Inspected on 2026-09-24: deploy-core main `41111109977be66b8ced3bebed6634b81979ce3f`; bootler main `5dc6b2ed8c9e9ae075a7d6bfbf89f9e1371739c5`. [Deploy-core #95](https://github.com/aicers/deploy-core/issues/95), body updated `2026-09-24T07:12:09Z`, and [roxyd #119](https://github.com/aicers/roxyd/issues/119), body updated `2026-09-24T06:09:29Z`, are OPEN and the user has dispatched their implementation. They are existing work, not new leaves to create, edit or restart. Recheck landed code before decomposition; an open issue's proposed API is not a shipped API.

Current implemented foundations:

- [`manifest`](../../src/manifest.rs) writes v5 and reads v3–v5, with ordered signed `archive_members`, artifact hashes and full build commit validation.
- [`verify`](../../src/verify.rs) provides bounded envelope reads, exact raw-manifest Ed25519 verification, two-stage format/trust-floor decisions, completeness, identifier, withdrawal, target and reserved-target epoch checks. `verify_package` authenticates statements; it does not walk or hash archive members.
- [`payload`](../../src/payload.rs) extracts through strict outer tar path/order/count/length/hash checks and stages before publication. `ExtractedArtifact` has public artifact/path fields; it is not immutable evidence. `append_trailer_signed` uses a signing callback but hashes sources before reopening them to archive. `rewrap_trailer` copies trailer blocks verbatim while relocating offsets.
- Closed verifier/container/signing work remains complete. This RFC reuses it and does not reopen foundation issues or replace the existing extraction API's documented partial-publication behavior.

Objective: one product-neutral path from an authenticated complete component package to retained, fully checked image bytes, plus an unsigned preparation and detached finalization writer using exact retained bytes. New modules, types and method names below are **proposals to be reviewed with this RFC**, not current symbols. #95 owns the declarations, request context and semantic verifier; no duplicate schema implementation belongs here.

Excluded: bootler CLI or GitHub workflow implementation, recipe/Compose rewriting, registry resolution, product catalogs, consumer pin adoption, daemon operations, alias lifecycle, retirement, accepted-store orchestration, omitted members, recovery implementation, crypto migration, keys/Secrets, AgentCoop execution and human merges. Implementation leaves must not instruct agents to create sibling or foreign issues. The design workflow derives worthwhile one-PR units without a prescribed leaf count; it must include each unit's complete applicable contract and tests.

## 2. Package and prerequisite invariants

### Complete packages and compatibility

Baseline A is one complete signed component package. Every artifact, including dependencies, matches the requested component/version/commit; source origin belongs only in signed provenance. The mixed installer envelope and installer-only StaticAssets package carrier use their own caller paths and are not ordinary single-build `verify_package` requests. Never weaken `check_target` for them.

The signed `archive_members` and actual outer archive agree in path, order, count and uncompressed member length. Each member is claimed exactly once and every artifact passes its SHA-256 check. V6 has no `source_policy`, optional member, reduced archive, runtime registry acquisition or local substitute for missing/corrupt bytes. An identical loaded image does not excuse corrupt included content. Skipping a later unnecessary load requires both complete package validation and an independent complete runtime-state check; `diff_artifacts` and installed-build records prove neither daemon availability nor ownership.

Retain v3–v5 readers and floor 3 when #95 adds v6. Preserve signed trust-floor, acceptance/serve, old-journal recovery and supported legacy installer/native/trust behavior. New evidence APIs refuse legacy image artifacts explicitly; they never represent them as no images. An older reader rejects v6 at the format boundary. A v5-to-v6 repack that changes bytes cannot replace a previously accepted build key; the producer needs a real new consumer commit. This library does not implement the accepted store.

### Reuse #95's typed declarations and context

Issue #95 introduces `PayloadArtifact.image: Option<ImageDeclaration>` and producer input plumbing. V6 requires a schema-1 declaration on each `ContainerImage` and forbids the `image` key, including null, on other kinds. V3–v5 and the admitted unversioned baseline refuse any image key at #95's prescribed parse point; no legacy evidence is synthesized. Unrelated legacy unknown-field behavior remains unchanged.

The declaration contains signed owner namespace/component, logical dependency, nonempty literal tagged public references, Linux platform with `amd64` or `arm64` and an explicit variant string or null, full lowercase `sha256:` config digest, `managed_runtime` or `shared_external` lifecycle, and closed registry or product-build provenance. Owner segments are lowercase ASCII identifiers; references satisfy #95's pinned Docker syntax/normalization rules. Unknown critical fields/enums in the image object and nested objects refuse. Registry provenance distinguishes pinned index/manifest digest from selected platform manifest digest and config digest; product provenance carries the full 40-hex source commit. Outer build identity remains the consumer's build.

New normalized third-party refs are exactly `runtime.invalid/<namespace>/<component>/<dependency>:cfg-<64 lowercase config-hash hex>`, with managed lifecycle. Preserve existing declared app tags. #95 owns canonical alias construction and reserved-host checks, including case/port evasions, and normalized collision comparison while retaining literal spellings. Across artifacts, equal ref assignments may coexist; conflicting config/platform/owner/lifecycle assignments refuse. Different provenance/dependency alone is not a conflict.

Use #95's typed namespace-scoped request constructor and projection rather than new parallel context/descriptor types. The expected namespace is independently trusted caller configuration, compared verbatim; it is never inferred from package aliases, paths, uploads or Docker. Owner component equals the requested target. Managed refs alone confer teardown ownership; shared refs are still activation requirements. The metadata projection distinguishes no images, authenticated v6 declarations and legacy undeclared images; it is not byte evidence.

The current request does not include target architecture. The new full-content APIs take one explicit `TargetArch` alongside the existing `VerifyRequest`; every artifact must have that architecture. This supplements strict build matching without changing the old metadata-only API or inferring a platform from the host. Native/trust requests keep their existing constructors, including the reserved target/epoch restrictions. Do not invent namespace metadata for image-free packages.

### Preserve verdict ordering

Keep #95's pipeline: bounded framing/envelope reads; signature over raw manifest bytes; two-stage format/trust-floor decision; typed parse; signed completeness; safe identifiers; withdrawal; exact build target; reserved-target epoch. Typed parse enforces new declaration shape at the end of each artifact's existing validation (dispositions, safe/duplicate path, commit, spec, then image), before advancing to the next artifact. Defer image decode failures to that point; do not add a global image prepass or move malformed JSON/pre-existing serde failures. Direct manifest serde and parser doors retain their specified differences for an unversioned baseline.

Then perform #95's whole-manifest passes in order: declaration architecture versus artifact architecture; reserved alias/lifecycle; cross-artifact reference conflicts; missing namespace; namespace equality; owner component equality. Finish each pass before starting the next; within one pass use manifest/ref order. Preserve all fourteen pre-existing `VerifyError` arms and their mappings; #95 adds only `VerifyError::Image(ImageVerifyError)` for its semantic checks. Shape errors stay under `Payload(InvalidManifest(..))`, non-image decode under `Payload(ManifestParse(..))`, and old special path/format/hash mappings remain intact.

New full-content work starts after those checks: requested architecture agreement, explicit legacy-image refusal, complete outer extraction/hash/framing validation, then nested images in manifest order. No image success or callback escapes until every artifact succeeds. Resource/framing/I/O refusals needed to read safely may precede authentication, but no unauthenticated image semantics may do so. Existing `verify_package`/`extract_to` behavior and legacy verdict precedence remain unchanged.

## 3. Selected docker-save support profile

The initial profile is **classic single-image docker-save with uncompressed layers**. It is intentionally narrower than everything Docker can import. The [Moby image specification](https://github.com/moby/docker-image-spec/blob/main/spec.md) describes config identity, ordered uncompressed layer diff IDs and the classic manifest representation. The [Docker save interface](https://docs.docker.com/reference/cli/docker/image/save/) can select a platform; selecting a CLI argument is not proof of archive inventory. This section defines this library's acceptance, regardless of which store generated the bytes.

### Image archive entries

Accept one uncompressed POSIX ustar or GNU tar stream, fixed 512-byte headers, valid header checksums and checked nonnegative numeric fields. Regular type `0`/NUL and zero-length directory entries are allowed at this image-archive level. Accept nonnegative GNU base-256 size encoding subject to the same limits as octal. Ignore ownership/mode/timestamp header metadata because no entry is installed. Forbid symlinks, hardlinks, devices, FIFOs, sparse files, PAX headers, GNU long-name/link overrides and unknown entry types at this level. Do not let a high-level tar iterator silently consume forbidden extension headers.

Names are UTF-8 ASCII, relative, slash-separated canonical paths with no NUL/control byte, backslash, absolute prefix, empty segment, `.` or `..`. A directory's single trailing slash is removed for duplicate/name comparisons only. Reject duplicate canonical paths, conflicting directory/file names, unsupported prefix/name combinations and truncation. Ustar prefix plus name is allowed only when their single canonical join satisfies these same rules. Do not extract the image archive onto host paths.

The complete permitted inventory is:

| Entry | Rule |
| --- | --- |
| `manifest.json` | Exactly one; bounded JSON array containing exactly one image record |
| `<config-hex>.json` | Exactly one, with 64 lowercase hex filename matching the SHA-256 of actual config bytes and signed `config_digest` |
| `<layer-id>/layer.tar` | Exactly the unique paths listed in manifest `Layers`; layer IDs are 64 lowercase hex opaque export IDs, not assumed diff IDs |
| `<layer-id>/` | Optional directory, only for a referenced layer; no unrelated directories |
| `<layer-id>/VERSION` and `<layer-id>/json` | Optional legacy metadata pair for a referenced layer, validated as described below |
| `repositories` | Optional, validated against the same sole image and tag set below |

Reject all other files, even unreferenced config/layer content. Image entries may occur in any order; retain their bounded offsets and lengths in the private snapshot, never their advertised-size content in memory. End-of-archive requires at least two zero blocks; permit further zero padding only to a total trailing-zero allowance of 1 MiB, counted from the first zero header. Reject nonzero trailing bytes, concatenated tar streams, partial blocks and EOF without the marker. This allowance belongs only to the inner image/layer profile; the existing outer tar keeps its stricter exact end-marker rule.

`manifest.json` accepts exactly `Config`, `RepoTags`, `Layers`, optional `Parent`, and optional `LayerSources`. Required fields cannot be null. Parent must be absent or the empty string; LayerSources must be absent, null or an empty object. Nonempty values, unknown fields, duplicate JSON keys or a second image record refuse; there are no remote/foreign layers or additional parent-image imports. `RepoTags` is a nonempty duplicate-free list whose literal set equals the signed declaration's literal `public_refs` set. Order is irrelevant, but missing, extra or differently spelled normalized-equivalent tags refuse. Reuse #95's normalized collision validation too. Producers must declare the actual export spelling; runtime never rewrites M or A to make them agree.

`Layers` is an ordered, duplicate-free array, possibly empty for a scratch image. One layer is represented once; this profile refuses a repeated layer path even if its bytes would have the same diff ID. All listed files exist exactly once; every layer entry is listed. If optional legacy metadata is present for a layer, require both files: VERSION is exactly `1.0` with optional final LF; json is an object with `id` equal to its directory ID and `parent` absent/empty for the first layer or equal to the immediately preceding layer ID otherwise. Other legacy image-config fields are bounded opaque JSON and cannot provide tags, files, URLs or an alternate load plan. Reject duplicate keys. These entries confer no authority and cannot replace a missing modern manifest/config.

If `repositories` exists, parse the classic repository-to-tag-to-layer-ID object. Require its reconstructed literal reference set to equal RepoTags, and every value to name the last listed layer ID. Reject it for a zero-layer image, where that legacy representation has no matching top layer. Empty, duplicate, additional or inconsistent mappings refuse. Reject a legacy-only archive without manifest.json rather than attempting a second import path.

OCI layouts (`oci-layout`, `index.json`, `blobs/...`), containerd hybrid exports carrying such entries, multi-platform/index exports, attestations, compressed image tar streams and compressed layer blobs are **unsupported in this first profile**, even if a manifest.json accompanies them. Return `UnsupportedArchive` explicitly; never ignore their additional metadata to salvage one image. A modern store may produce accepted classic-profile bytes, but the store's name grants no exemption. Supporting another representation later requires a reviewed extension with the same completeness/identity guarantees, not a fallback parser in a consumer. No producer normalization or conversion implementation is included in this RFC.

### Config and layer consistency

Reject duplicate keys throughout parsed image JSON. Config requires `os: "linux"`, `architecture: "amd64" | "arm64"`, and `rootfs: {"type": "layers", "diff_ids": [...]}`. Diff IDs are full lowercase SHA-256 digests. Permit other bounded config fields; they remain authenticated execution configuration and are not instructions to this parser. If `history` is present it must be an array of objects; `empty_layer`, when present, is boolean, and the number of entries not marked true equals the diff-ID count. Absence of history is allowed. Do not derive layer order from history.

Hash the exact config bytes, not serialized JSON. Compare OS/architecture to the signed platform and architecture mapping (`X86_64` → `amd64`, `Aarch64` → `arm64`). A missing or JSON-null config variant maps to no variant and matches only signed null; a nonempty string must match the signed string byte-for-byte. Empty or non-string values refuse. In particular, absent variant is not silently upgraded to arm64/v8; neither registry declarations nor the local daemon may supply it. A producer unable to export matching evidence must refuse that output, not edit config bytes while keeping the old identity. This is a deliberate supported-profile restriction, not a new registry platform-selection policy.

Require Layers and diff_ids to have equal lengths. Stream each referenced **uncompressed** layer file in listed order and hash all its bytes, including tar headers/padding, against the corresponding diff ID. A reordered, missing or substituted layer refuses even when the outer archive hash is correct. Never compare compressed blob hashes, export layer directory IDs, archive hashes or upstream provenance digests as though they were diff IDs. Runtime trusts the release signer's upstream index/child/content binding; no registry request or RepoDigests check is made.

Validate each layer as a bounded tar changeset without installing it. The layer walker validates header checksums, checked sizes, entry boundaries and the same finite zero-tail rule, but has a **separate** entry policy: regular files, directories, symlinks, hardlinks, character/block devices and FIFOs are allowed, since these describe container filesystem changes. Whiteouts are ordinary named layer entries. GNU long-name/link and POSIX local PAX records are allowed only through bounded raw-record handling; reject sparse, global PAX and unknown type records. PAX keys are limited to path, linkpath, size, uid, gid, uname, gname, mtime, atime, ctime and `SCHILY.xattr.*`; reject unknown keys, duplicate keys, malformed lengths and conflicting path/link/size overrides for one entry. Apply one extension to the immediately following real entry; reject dangling extensions and multiple name/size authorities. Check effective sizes before streaming. Hash original bytes including extensions, never a rewritten layer.

Layer names are container filesystem data and are never joined to staging paths. Validate effective names as relative paths without `..`, NUL or control bytes, permitting a leading `./` and trailing directory slash after canonical comparison. Permit `.` or `./` only as a zero-length root directory entry. Bound link targets but do not dereference them; absolute symlink targets can be legitimate inside a container. Hardlink targets must satisfy the relative layer-path rule. Repeated layer filesystem names are permitted in sequence and do not alias image-archive entries. This is structural/content validation, not a general filesystem extraction sandbox or proof that starting the image is safe; Docker remains responsible for applying its filesystem semantics. No host filesystem inspection or mutation occurs.

## 4. Finite resource policy

New APIs use `ContentLimits` with private fields, a `Default` profile below, and checked constructors allowing callers to **lower** limits. Zero disables the corresponding nonempty resource, not the bound. No unlimited sentinel or caller-controlled upward override exists. Raising defaults or supporting a new format is a reviewed library change. These operational ceilings do not change manifest version/trust floors or the old API's acceptance behavior.

| Resource | Default ceiling |
| --- | --- |
| Raw manifest M | 16 MiB |
| Compressed archive A | 64 GiB |
| Complete standalone package | 64 GiB + 16 MiB + 201 bytes (64-byte signature, 64-byte key ID, 73-byte footer) |
| Outer artifacts/members | 1,024 |
| Sum of outer uncompressed member bytes | 128 GiB |
| One image archive / one layer stream | 32 GiB / 16 GiB |
| Image-level tar entries / path bytes | 4,096 / 255 |
| Layers per image / tags per image | 256 / 256 |
| Image manifest JSON / config JSON | 1 MiB / 4 MiB |
| One legacy JSON or repositories file | 1 MiB |
| All image JSON and VERSION bytes per image | 16 MiB |
| JSON nesting depth, all new parsers | 64 |
| Layer entries across one image | 1,000,000 (extension headers included) |
| Layer effective path / link target bytes | 4,096 / 4,096 |
| One layer extension / total layer extension bytes per image | 64 KiB / 64 MiB |
| Per-operation live private disk retention | 512 GiB |
| Copy/hash buffer / outer zstd window | 1 MiB / 64 MiB |
| Preparation record | 64 KiB |

MiB/GiB are powers of 1024; lengths and sums use checked u64 arithmetic, with checked conversion to allocation indexes. Enforce bounds on bytes actually read as well as advertised lengths, entry counts and parser nesting; cap zstd window before decoding and sum decoded bytes independently of compression ratio. Preserve the outer reader's existing frame/trailing-byte refusals. The new bounded manifest read must occur before allocation while sharing framing logic; do not tighten legacy metadata-only reads as an incidental refactor.

These finite, deliberately generous ceilings accommodate GB-scale streaming and the approved six-image fixture while bounding parser state, expansion, and disk usage. They are initial operational choices, not measured maxima for every future product. The implementation must report peak memory/private disk and time on representative fixtures. Disk exhaustion, insufficient caller budget or unsupported limits refuse; no fallback to unbounded RAM, truncation or weaker validation. Scratch capacity/free-space checks are advisory only; each write still enforces the budget and propagates ENOSPC. Count all simultaneously retained snapshots, output candidates and extraction files against one operation budget, including the temporary copy during publication/persistence.

Process images sequentially and release temporary parsed state/layer walkers before advancing. No collection contains all layer bytes or a package-sized Vec. Metadata allocations are charged against their byte limits before parsing, and bounded parser overhead is measured in acceptance tests. Scanning/hashing cost is bounded by byte/entry ceilings; no per-entry recursive rescans. APIs are synchronous streaming I/O; async consumers own their blocking-worker lifecycle and cancellation. A read/write failure or dropped operation closes its private snapshots and issues no partial evidence. This RFC adds no detached tasks or sleeps for synchronization.

## 5. Immutable retention and public evidence

### Ownership and threat boundary

Use private disk-backed snapshots on supported Unix hosts, with 0700 staging directories and 0600 files at creation. Copy each untrusted source once into a new library-owned regular file; after flushing buffered writes open a read-only descriptor, unlink the name, close **every** writable descriptor, and only then validate and construct evidence. Never use a hardlink to the original inode. Validation and later streams read that same private inode. Unlinking, closing writers and withholding all file/path/descriptor APIs establish the safe API's immutability; chmod alone or an open descriptor to a caller's file does not.

Use existing std/tempfile/durability facilities; do not introduce Linux-only memfd retention or package-sized memory maps as the default. The library does not expose a File, path, raw descriptor, writable handle, mutable slice, Deserialize implementation or public fields for a retained capability. A caller-supplied staging parent is storage placement, not authority; create the fresh private directory yourself and reject unsafe/non-directory parents. The caller must provide a trusted filesystem and process isolation. Arbitrary root/same-process memory access, hostile same-UID `/proc` descriptor access, malicious filesystems and hardware corruption are outside an in-process Rust API's protection; do not advertise protection from them. Normal caller writes, pathname replacement and source FD changes are in scope and cannot affect the retained snapshot.

Anonymous transient snapshots are not recovery records and need no fsync for crash survival; the OS reclaims them on process exit. Close-on-exec remains set and no descriptor is inherited by a child. Cleanup errors for named temporary state must retain path/operation context. A reader borrowing evidence cannot outlive it; private retained storage is reclaimed only after all owners/readers finish. Consumers stream into a controlled child's stdin and await/cancel/reap that child before releasing sources; this library does not spawn Docker. A remote copied path is untrusted again at its destination boundary.

### Proposed API surface

Add public `image` and `package` modules, backed by one crate-private retention/extraction implementation. Reuse #95's `ImageDeclaration`, request constructor and declaration projection under their actual landed names; do not create duplicate public schema types. The names in this table are selected proposal names for the new surface; record final signatures in the implementation PR and consumer migration notes before any pin adoption.

| Proposed API | Contract |
| --- | --- |
| `package::verify_contents(source, trust, request, target_arch, limits, staging_parent)` | Accepts a `Read + Seek` package source, existing `TrustSet`/`VerifyRequest`, explicit `TargetArch`, and local resource/storage policy; returns `VerifiedContents` only after the full ordered pipeline |
| `VerifiedContents::manifest()` / `artifacts()` / `images()` / `package_bytes()` | Read-only projections of the authenticated manifest, all retained artifacts, `VerifiedImages`, and retained exact canonical package bytes |
| `VerifiedImages::None` / `Present` | Explicit image-free success or a nonempty slice of `VerifiedImage`; legacy-image input is an error, never None |
| `VerifiedImage::declaration()` / `member_length()` / `archive()` | Signed declaration, authenticated outer member length and immutable retained image bytes |
| `VerifiedArtifact::artifact()` / `member_length()` / `bytes()` | Read-only manifest artifact, verified length and retained bytes for every kind; an artifact reference is not itself image evidence |
| `RetainedBytes::len()` / `sha256()` / `reader()` | Read-only length/digest; reader implements `Read + Seek`, borrows the capability, and exposes no underlying file/descriptor/path; each reader has an independent cursor |
| `VerifiedContents::publish_package(destination)` | Durable no-clobber publication of the exact retained canonical package; returns a receipt, not an immutable capability to the resulting mutable path |

All evidence constructors/fields are private. The Present arm holds an opaque borrowed `VerifiedImageSet` with read-only `len()`/`iter()` accessors and private construction, so callers cannot construct or empty that collection. Do not implement `Default` or Deserialize for evidence. Internal cloning may share a private immutable backing owner; no public constructor accepts a claimed hash, `ExtractedArtifact`, arbitrary path or diagnostic JSON. Retain native/Compose bytes too so the canonical verified source can feed installation; do not unpack nested Compose archives or discover ownership by parsing YAML.

`verify_contents` first takes a bounded snapshot of the full input, so subsequent mutation of the original cannot change its manifest/footer/archive during use. Authenticate the snapshot through existing verification, then reuse a refactored private outer extraction walker for all artifact checks. New and old extraction callers must share path/order/count/length/hash enforcement without the old API acquiring a new success guarantee. Close write descriptors for extracted snapshots, finish **all** outer checks, and validate each image before returning. Do not return callbacks or partial handles for earlier artifacts while a later artifact remains unchecked.

Retaining a package plus extracted artifacts costs disk; this is deliberate and budgeted, not global deduplication. Caller deletion/replacement of the original package or sources cannot alter canonical bytes, metadata or image streams. Publication copies those canonical bytes, not a reconstructed package. Existing `VerifiedPackage` and path-based extraction remain metadata/legacy interfaces with their current documentation; they cannot be promoted by casting or wrapping arbitrary caller values.

## 6. Exact preparation, persistence and detached finalization

### Preparation APIs and data

Propose `package::prepare_package(inputs, pinset, trust_set_bytes, request, target_arch, limits, staging_parent) -> PreparedPackage`. Inputs use #95's extended `payload::ArtifactInput`; pinset/trust-set options preserve existing writer meanings. Preparation emits new-format standalone packages only (no mixed installer carrier or executable prefix), and has no private key or trust bypass. Reserved trust packages still require the appropriate request/epoch and existing trust-set content checks.

Snapshot all inputs into private files first. Calculate member lengths/hashes from those snapshots and build M and A from the same snapshots, never reopened original paths. A source changing during copy may cause refusal or produce one snapshot whose bytes are consistently declared/validated; it cannot claim the original file was an atomic historical snapshot. Exact source-revision/build provenance remains the producer's responsibility. A second source read must never turn old hashes into a success containing new bytes.

M is the exact once-serialized bounded manifest; A is the existing zstd-compressed strict outer tar. Validate the generated archive's complete shape/length/hash and nested images against M, using the same unsigned-content core as final validation. Run applicable parse, completeness, safe identity, target/epoch, namespace/semantic and architecture checks without fabricating a signature success, withdrawal decision or accepted build. `PreparedPackage` is explicitly **unsigned, untrusted for installation**, with private constructors and immutable M/A retention. Its existence does not promise the signer/trust will later accept it.

Expose `PreparedPackage::manifest_bytes()` as bounded `&[u8]`, `archive()` as `&RetainedBytes`, and `binding()` as read-only `PreparationBinding`. The binding contains record schema 1, raw M SHA-256/length, raw compressed A SHA-256/length, requested component/version/commit, target architecture, namespace context or explicit null, and requested trust epoch or explicit null. Digests use lowercase `sha256:<64 hex>`; architecture uses `x86_64 | aarch64`; no field is inferred from source path or host. Native packages need no namespace in their manifest; a binding may record caller-supplied namespace context without adding image ownership metadata.

Propose `PreparedPackage::persist(destination_directory)` and `package::reopen_prepared(directory, expected_binding, request, target_arch, limits, staging_parent) -> PreparedPackage`. Persist exactly three files: `manifest.json` (M), `archive.tar.zst` (A), `preparation.json` (the binding). The record has no arbitrary file paths, executables, signatures, trust roots or source-file names. Unknown fields, duplicate keys, unsupported schema, invalid target identifiers/digests and missing explicit nullable fields refuse. A public copy of a binding is matching data, never a capability or independent authorization.

An illustrative preparation record follows. Hashes/lengths are synthetic, not a valid package fixture:

```json
{
  "schema": 1,
  "manifest_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "manifest_length": 4096,
  "archive_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "archive_length": 1048576,
  "target": "example-app",
  "version": "1.0.0",
  "commit": "1111111111111111111111111111111111111111",
  "target_arch": "x86_64",
  "namespace": "example-product",
  "trust_epoch": null
}
```

Persist in a new private sibling directory on the same filesystem. Write files with 0600 modes, sync all files, sync that staging directory, publish the complete directory without replacing an existing destination under a trusted caller-serialized parent, then sync the parent. These syncs protect M/A/record across a job boundary. Refuse existing destinations, symlinks, extra members, wrong modes/owners and non-regular files on reopen. Open only those exact paths, copy them to fresh private snapshots with the same limits, and validate the copied bytes. No public path is ever adopted as retained evidence.

`expected_binding` comes from the caller's saved request correlation, not merely the record found alongside A. Compare every field and recompute both byte digests/lengths, then reparse M and repeat all preparation content checks; a mutually changed record/M/A still has no independent authorization. Validate request/context/architecture against M through the same core. Reopen does not regenerate M/A and does not mark them signed. A process/job boundary always loses capability status; successful revalidation constructs a new private handle.

### Signer boundary and complete local fixtures

External signing uses `M` itself, not `SHA256(M)` and not a JSON reserialization. Keep Ed25519, the current 64-byte signature and 64-lowercase-hex key-ID framing. Accept existing `payload::Signed` as detached response data and keep the current callback/SignerError convention usable. No signer service, algorithm selection, signature bypass or new footer/trust root is added.

Provide `package::prepare_sign_finalize(...) -> FinalizedPackage` as a convenience over the exact preparation API, one `FnOnce(&[u8]) -> Result<Signed, SignerError>` callback, and the finalization API below with independently supplied public trust. It has identical validation semantics; it is not a fixture-only unsigned shortcut. This gives consumers a **complete signed v6 fixture construction API**, including image metadata, actual config/layer archives and all final checks, without operational detached signing or bootler CLI adoption. Test helpers, if exposed, are under `test-support` and enabled only in dependent dev-dependencies. Isolated test signers are allowed in tests, never production defaults or accepted trust anchors.

Bootler separately authorizes repository, workflow run/attempt, protected tooling/recipe revisions and the expected target set. Its protected standard hosted `ubuntu-24.04` signing job receives only bounded M and small request/authorization records, never A, a package/carrier or preparation-produced executable/cache. It signs raw M after independent authorization; builder-supplied target lists do not authorize themselves. The public response binds request ID, run/attempt, exact request-record hash/artifact identity, M digest/length, key ID and signature. Bootler checks missing/duplicate/unrequested/cross-run/wrong-record responses and exact authorized artifact provenance. The library exposes M/A bindings for those checks but does not verify GitHub workflow provenance or treat response metadata as a new trust root.

### Finalization and publication

Propose `package::finalize_package(prepared, expected_binding, signed, trust, request, target_arch, limits, staging_parent) -> FinalizedPackage`. It is keyless and accepts no original build/source paths. First match the complete expected binding and rehash retained M/A lengths/digests. Refuse altered manifest whitespace/bytes, same-length archive substitution, missing files, wrong context and mismatched response binding. Validate signature/key-ID framing and assemble a private standalone container with the exact M and A, signature, key ID and current footer. Neither M serialization nor A recompression occurs. Checked offsets/lengths must obey the existing adjacent-block/footer rules; no arithmetic wraparound or partial envelope.

Then run the **full** `verify_contents` pipeline on the assembled private container under independently supplied trust, exact request/namespace and target architecture. Preserve existing key-hint/fallback verification behavior, revoked-key/withdrawn-build and trust-floor semantics; a prior preparation, signer response or matching digest does not skip any check. A digest signature cannot authenticate M. A signature from another key is accepted only if the caller's independent trust and intended signer correlation permit it; key ID alone is never trust. Where the caller requires an exact signer, it must supply the matching trust policy and verify its authorized response before this call, using the existing signature verifier's hint semantics rather than silently redefining them.

`FinalizedPackage::contents()` exposes the resulting `VerifiedContents`, including the same immutable canonical container; `bytes()` and `binding()` expose exact output bytes and matching metadata. `publish(destination)` copies only that validated snapshot to a private sibling 0600 file, verifies the copied length/hash, syncs it, atomically publishes without clobbering an existing file, and syncs the parent. Use the same publication core as `VerifiedContents::publish_package`. A `PublishedPackage` receipt reports destination, digest and length; a subsequently mutable filesystem path is not immutable evidence, and an independent store must verify its own acceptance input.

Publication/persistence failure before the publish point removes the candidate and leaves an existing destination unchanged. After a rename/link makes the complete output visible, a directory-sync failure may leave that complete output present but durability uncertain: return a typed `PublishDurability` error identifying the destination, never success or a false claim of rollback. An output name is published only after complete validation; temporary/unsigned names are never final package results. Directory publication requires the documented single-writer parent lock/serialization; this library does not invent a cross-process coordination service. A crash may leave private preparation staging; the caller owns exact-path stale cleanup, never adoption without reopen validation.

Preserve existing signed/unsigned low-level writer and rewrap callers. Low-level assembled bytes are not a `FinalizedPackage`; documentation must keep that distinction. Shared internals may remove duplicate code, but no formerly unsigned input gains an acceptance bypass. Rewrap remains a verbatim trailer-block copy with offset relocation, no format migration/signing pass. Direct installation and store publication consume the identical finalized package; consumers independently recheck trust/context at each boundary. If an outer installer signature is needed, its M is prepared after child signatures/bytes/hashes exist and signed in a separately authorized pass. No new outer-signature requirement or signature cycle is introduced.

## 7. Error ownership and deterministic failure

Extend #95's nested `ImageVerifyError`, without adding another top-level VerifyError arm, for `LegacyImageEvidence`, `UnsupportedArchive`, `InvalidArchive`, `UndeclaredReference`, `MissingReference`, `ConfigDigestMismatch`, `PlatformMismatch` and `LayerMismatch`. Include bounded artifact/member context and structured expected/actual details where useful; do not echo raw config/environment/secret contents. `InvalidArchive` has a typed reason for malformed JSON/tar, unsafe or duplicate path, missing/unreferenced entry and inconsistent legacy metadata. `UnsupportedArchive` names a supported-profile exclusion; it is not an empty-success case.

New `package::ContentError` wraps `Verify(VerifyError)` without remapping existing variants and adds `ArchitectureMismatch`, `LimitExceeded { resource, limit }`, and contextual `Io { operation, path, source }`. Resource/operation discriminators are enums. Outer hash mismatch remains `Verify(ManifestHashMismatch)` and nested failures remain `Verify(Image(...))`. Preparation/finalization use `PackageWriteError` wrapping `Content`, existing `Payload`/`Signer` sources where appropriate, plus typed `BindingMismatch { field }`, `InvalidPreparation`, `DestinationExists` and `PublishDurability`. Fields naming a mismatch are enums, not free-form control strings. Specify new variants and match migrations in rustdoc/PR notes before consumers pin them; do not rewrite #95 to introduce speculative cases early.

Within one image: bounded raw tar structure/inventory pass first; bounded JSON shape and sole-image selection; exact tag set; config hash; config platform; ordered layer linkage/digest/structural checks; legacy metadata consistency. Structural/limit/I/O faults necessary to scan safely win immediately; semantic checks otherwise follow this order independently of archive entry order. Walk Layers in manifest order, and choose the first sorted missing/extra literal tag for deterministic diagnostics. Validate all outer artifact hashes and archive termination before nested image semantic checks, so a bad later non-image artifact cannot be hidden by an earlier nested failure. Tests must pin representative paired-fault cases, not only one-fault success/failure.

## 8. Acceptance and test plan

All unit tests use local generated or checked-in fixtures, tempfile directories, injected limits and isolated test public trust/signing callbacks. They do not use the network, production keys, host Docker or process-environment mutation. No sleep-based race synchronization or fixed ports. Include consumer-visible integration tests outside the library module boundary to prove private construction and public ergonomics.

| Boundary | Required evidence |
| --- | --- |
| Prerequisite/legacy | Retain #95's shape, key-presence and semantic pass ordering; supported v3–v5 native/trust behavior; legacy images produce typed refusal only at the new evidence boundary; no silent empty image set; v6 old-reader format refusal baseline remains documented |
| Strict package | Six image artifacts plus deployment files with one requested build, both architectures/provenance/lifecycle arms, same-version/new-commit request; wrong build/namespace/architecture/epoch refuses; canonical package bytes retained; no omitted member or source_policy bypass |
| Outer content | Unsafe/duplicate/unlisted/missing/reordered members; wrong count/length/hash; unsupported tar features, zstd bombs/window, overflow, truncation and nonzero/extra trailing bytes; a corrupt non-image artifact prevents every image handle |
| Classic image positives | One/multiple declared tags on one image, scratch image without repositories, both explicit/null variants, nonempty history with empty-layer records, optional consistent legacy metadata/repositories, accepted ustar/GNU numeric/header cases and bounded zero padding |
| Archive negatives | Multiple image records/platforms/configs, hidden/unreferenced layers/files/tags, duplicate JSON keys, extra repositories mappings, wrong legacy IDs/parents, unsafe/duplicate/overridden paths, links/devices/PAX at image level, dangling layer extensions, unsupported sparse/global-PAX/type/keys, malformed/truncated JSON/tar and trailing concatenation |
| Identity/content | Actual config hash differs despite plausible filename, config platform/variant disagreement, absent versus v8 refusal, malformed rootfs/history, missing/reordered/substituted layers, diff-ID mismatch, compressed layers, undeclared equivalent-spelling tags and missing signed refs; no registry/RepoDigests dependency |
| Resource | Each numeric limit at boundary and boundary+1 using small injected limits or counting readers; excessive metadata depth/entries/paths/extensions, huge declared lengths, checked arithmetic, capped zstd window/expansion, read failure/ENOSPC; record peak memory/disk on a streamed large fixture |
| Evidence/TOCTOU | Mutate/replace/delete original files after snapshot; use a retained original writable FD; race source copy through deterministic barriers; repeated readers retain independent cursors and identical bytes; dropped owners/readers, early/late failures and close-on-exec cleanup; no named writable alias remains when validation starts |
| Capability API | External compile-fail examples cannot build evidence from paths, hashes, `ExtractedArtifact`, serde or public fields, obtain raw descriptors, or retain a borrowed reader past its owner; image-free success differs from legacy-image refusal |
| Prepare/reopen | Exact M/A persist/reopen across a child process with injected environment; arbitrary order/whitespace in externally altered M refuses expected binding; wrong record schema/fields, extra files, links, modes, lengths, same-length changes, substituted complete preparations and changed request/context refuse |
| Signed fixtures | Complete v6 `prepare_sign_finalize` fixture with actual config/layers through the public API, image-free native and reserved-trust cases, no production signer or bootler binary; wrong key/revoked key/withdrawn build/trust floor/epoch and digest-only signature refuse |
| Finalize | Signature validates exact M; wrong binding, source edits after preparation, changed A/M, corrupted final framing and late content failure yield no finalized handle; instrumentation proves no original source read, reserialization or recompression; output blocks equal retained M/A exactly |
| Publication/durability | No-clobber existing destination; failures during copy/hash/file-sync/publication/directory-sync; honest present-but-durability-uncertain error; persist directory complete before publish; final bytes identical across install/store uses; destination mutation cannot change retained evidence |
| Compatibility | Existing low-level signed/unsigned writers, versioned footer framing, key-hint behavior, raw-byte signatures and rewrap unchanged; old extraction path keeps documented behavior and shares rule implementation |
| Error ordering | Signature versus image shape, format versus typed image fault, target/epoch versus image semantics, #95 whole-pass ordering, requested architecture/legacy refusal, outer hash before nested semantics, and nested tag/config/platform/layer ordering |

Deliberately check in small synthetic classic and modern/OCI/hybrid export fixtures with their expected accepted/unsupported result and generation provenance (Docker engine version, store mode, architecture, command and fixture hash). Parser unit tests consume bytes only. A disposable local integration procedure must generate/load accepted profile samples on documented classic and containerd stores, assert restored refs/config ID/platform and reject unsupported export samples through this library **before** any load. Load only a sample already admitted by the validator; ensure extra tags were not silently restored. This compatibility evidence is a release gate for claiming support for those store/version combinations, not permission for tests to touch a user's daemon or for runtime validation to invoke Docker. Lack of Docker infrastructure is reported as unrun evidence, never substituted with a mocked compatibility claim.

The supported/rejected fixture inventory and public fixture-construction API must land with the associated implementation, not be postponed until operational signing exists. Native consumers may continue using existing APIs; image consumers wait for the complete full-byte/evidence surface and signed fixture construction, not the entire producer workflow.

Each implementation PR runs the repository CI matrix, currently:

```sh
cargo fmt -- --check --config group_imports=StdExternalCrate
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features test-support -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --document-private-items --features test-support
cargo test
cargo test --features test-support
markdownlint-cli2
```

Preserve shared instruction drift checks. New dependencies need a stated requirement not supplied by std or existing tar/zstd/serde/tempfile/hash/signature facilities. Every implementation issue includes its relevant positive, negative, compatibility and failure-cleanup cases, exact API prerequisites, test ownership and full CI commands. The documentation PR validates Markdown, links/anchors, illustrative record syntax and source consistency; its green CI does not claim these future runtime tests have been implemented.

## 9. Sequencing, backend coordination and owner actions

Issue #95's landed declarations/context are the existing prerequisite for typed image validation/evidence integration. Independent private retention/preparation mechanics can be separate worthwhile PRs when their tests do not fake those capabilities. Final validated image-package output depends on shared full-content validation. The convenience signed-fixture path must be available with the usable image-evidence surface; no downstream fixture developer is made to wait for production detached-signing operations or bootler adoption. Derive dependency edges from callable interfaces, not a fixed issue count or a production activation schedule.

Roxyd #119 establishes initial deploy-core integration and configured namespace independently. Its later adoption work selects the exact landed compatible pin and consumes the validated namespace, full evidence and complete signed fixture API. Bootler and REview own their explicit adoption too. The receiving namespace comes from one trusted existing configuration accessor; no second verifier-only value or network install field is introduced. Producer and consumer fixture development may proceed in parallel after their actual APIs land. Production activation/full E2E additionally requires completed consumers, genuine full signed supply, public production trust and the independently authorized signing workflow; green legacy E2E and fixture-only operation are not those gates.

[Bootler #379](https://github.com/aicers/bootler/pull/379) merged the [recovery contract and aws-lc-rs decision](https://github.com/aicers/bootler/blob/5dc6b2ed8c9e9ae075a7d6bfbf89f9e1371739c5/docs/rfcs/0001-install-attempt-recovery.md#cryptographic-provider-transition). Its separately owned sequence is deploy-core crypto/certificate transition, explicit bootler adoption/use-site transition, then recovery foundation crypto integration. Current deploy-core still uses ring and ring-backed webpki. This RFC neither migrates it nor adds aws-lc-rs alongside it, and adds no transition prerequisite to #95 or generic image validation/writer work. Keep new APIs backend-neutral: raw byte bindings, existing trust abstractions and signing callbacks, no ring/aws-lc key type in a new public contract. If the separate migration lands first, consume its actual shared verifier without creating a second backend path. That owner must preserve Ed25519 raw-byte/seed/key-ID compatibility, revoked/withdrawn/trust behavior and certificate policy, and owns cross-provider fixture/graph tests. Do not regenerate keys, re-sign accepted builds or move certificate verification outside `src/roxyd_trust.rs` here.

The recovery owner also needs validated raw container blocks for its relocation-invariant payload fingerprint. Reuse bounded framing and private retention internals where the eventual interfaces overlap, but do not substitute this RFC's whole-package SHA-256 for that separately specified domain-separated block fingerprint: a rewrap changes absolute offsets. This RFC exports canonical package streams and exact prepared M/A, not a new recovery fingerprint or session-executor API. Any additional raw-block accessor required by that owner must preserve signature/framing policy and be scoped in its own implementation; it is neither hidden work here nor a prerequisite of #95.

The proposed profile, numeric limits, retained capability and preparation-record format are deploy-core engineering decisions within the approved shared guarantees. **No shared-policy delta is proposed by this RFC.** Unsupported modern exports and strict absent-versus-explicit variant matching can require the producer to select a supported export path; this RFC makes no claim that all current release outputs already fit. Before production adoption the bootler owner must validate its exact selected archives against this profile and collect the interoperability evidence above. If that requires weakening exact tags, complete membership, config/layer/platform binding, immutable evidence, raw signatures or one-image/platform scope, stop: the exact affected obligation is bootler RFC 0004 image contract §§2–5/5B, and its owner must review/merge that specific amendment before a conflicting implementation proceeds. Prefer extending representation support without weakening those invariants. Do not silently edit another repository or ask a leaf agent to file its owner's issues.

Managed-reference retention until Remove stays the baseline; retirement is later lifecycle work. Transfer omission B requires a later manifest version and separate approval; precise cross-consumer dependency advice remains outside scope. Recovery's approved refusal/replay choices stay with bootler #379 and its implementation; this RFC does not repeat historical claims that those policy choices are unresolved or claim #373 is implemented/ready.

A human reviews and merges this documentation PR, then separately authorizes RFC-to-issues using this **one committed default-branch file**. A local note, this open PR or an issue linking companion documents is not a substitute for that input. No implementation leaf creates sibling/foreign issues, performs production signing setup, silently changes foreign pins or merges its own result.
