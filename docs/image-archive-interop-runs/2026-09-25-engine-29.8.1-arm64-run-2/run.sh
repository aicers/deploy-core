#!/usr/bin/env bash
# Manual Docker interoperability run: one disposable docker:29-dind daemon
# per image store. Every command is printed verbatim before it is evaluated,
# followed by its combined stdout/stderr and its exit code.
set -u
export LC_ALL=C
REPO=../..
cd "$(dirname "$0")" || exit 2
WORK="$PWD/work"
DIND='docker@sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0'

run() {
  printf '$ %s\n' "$1"
  eval "$1" 2>&1
  printf '[exit %d]\n\n' "$?"
}

section() { printf '## %s\n\n' "$1"; }

samples() {
  section "Host and build"
  run "date -u '+%Y-%m-%dT%H:%M:%SZ'"
  run "git -C $REPO rev-parse HEAD"
  run "git -C $REPO status --porcelain"
  run "cargo build --manifest-path $REPO/Cargo.toml --example write_synthetic_image --features test-support --quiet"
  run "EXAMPLE=$REPO/target/debug/examples/write_synthetic_image; echo \$EXAMPLE"
  section "Step 1: write samples"
  run "mkdir -p work/samples"
  for arch in amd64 arm64; do
    run "\$EXAMPLE write work/samples/sample-$arch.tar work/samples/sample-$arch.declaration.json $arch registry.example/interop/sample-$arch:1.0"
    run "\$EXAMPLE write work/samples/many-$arch.tar work/samples/many-$arch.declaration.json $arch registry.example/interop/many-$arch:1.0 registry.example/interop/many-$arch:latest"
  done
  run "cp $REPO/assets/test-fixtures/images/explicit-variant.tar $REPO/assets/test-fixtures/images/explicit-variant.declaration.json work/samples/"
  for s in sample-amd64 many-amd64 sample-arm64 many-arm64 explicit-variant; do
    run "cat work/samples/$s.declaration.json"
    run "shasum -a 256 work/samples/$s.tar"
    run "tar -xOf work/samples/$s.tar index.json; echo"
  done
}

daemon() {
  local store=$1 snapshotter=$2 short=$3
  local name="interop-117-$store"
  local D="docker exec $name docker"
  section "Daemon: $store store"
  run "date -u '+%Y-%m-%dT%H:%M:%SZ'"
  run "EXAMPLE=$REPO/target/debug/examples/write_synthetic_image; echo \$EXAMPLE"
  run "mkdir -p work/$store && printf '{\"features\":{\"containerd-snapshotter\":$snapshotter}}\n' > work/$store/daemon.json && cat work/$store/daemon.json"
  run "docker run -d --rm --privileged --name $name -v $WORK:/work -v $WORK/$store/daemon.json:/etc/docker/daemon.json:ro $DIND"
  printf '# waiting for the daemon in %s to answer\n' "$name"
  for _ in $(seq 1 120); do
    docker exec "$name" docker info >/dev/null 2>&1 && break
    sleep 1
  done
  printf '\n'
  run "$D version"
  run "$D version --format '{{.Server.Version}}'"
  run "$D info --format '{{.Driver}}'"
  run "$D info --format '{{json .DriverStatus}}'"
  run "$D info --format '{{.Architecture}}'"
  run "$D info --format '{{.OSType}} {{.OperatingSystem}} {{.KernelVersion}}'"
  run "$D image ls -a --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}'"

  section "Step 4 ($store): raw export, classified before anything is loaded"
  run "mkdir -p work/$store/raw-ctx && printf 'hello\n' > work/$store/raw-ctx/hello.txt && printf 'FROM scratch\nCOPY hello.txt /hello.txt\n' > work/$store/raw-ctx/Dockerfile && cat work/$store/raw-ctx/Dockerfile work/$store/raw-ctx/hello.txt"
  local ref="registry.example/interop/raw-$short-run2:1.0"
  run "$D build -t $ref /work/$store/raw-ctx"
  run "$D save -o /work/$store/raw-$short-run2.tar $ref"
  run "shasum -a 256 work/$store/raw-$short-run2.tar"
  run "tar -tvf work/$store/raw-$short-run2.tar"
  run "tar -xOf work/$store/raw-$short-run2.tar manifest.json; echo"
  run "tar -xOf work/$store/raw-$short-run2.tar index.json; echo"
  run "$D image inspect $ref --format '{{.Id}}'"
  run "$D image inspect $ref --format '{{.Os}}/{{.Architecture}}/{{with index . \"Variant\"}}{{.}}{{end}}'"
  run "tar -xOf work/$store/raw-$short-run2.tar manifest.json | jq --arg platform \"\$($D image inspect $ref --format '{{.Architecture}}/{{with index . \"Variant\"}}{{.}}{{end}}')\" 'if length != 1 then error(\"expected one manifest.json record\") else .[0] end | (\$platform | split(\"/\")) as [\$arch, \$variant] | {schema: 1, owner: {namespace: \"example-product\", component: \"example-app\"}, dependency: \"app\", public_refs: .RepoTags, platform: {os: \"linux\", architecture: \$arch, variant: (if \$variant == \"\" then null else \$variant end)}, config_digest: (\"sha256:\" + (.Config | ltrimstr(\"blobs/sha256/\") | rtrimstr(\".json\"))), reference_lifecycle: \"shared_external\", provenance: {kind: \"product_build\", repository: \"https://example.com/synthetic-images.git\", commit: \"0123456789abcdef0123456789abcdef01234567\"}}' > work/$store/raw-$short-run2.declaration.json"
  run "cat work/$store/raw-$short-run2.declaration.json"
  run "\$EXAMPLE classify work/$store/raw-$short-run2.tar work/$store/raw-$short-run2.declaration.json"
  run "$D image ls -a --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}'"

  section "Steps 2-3 ($store): classify, load and check samples"
  for s in sample-amd64 many-amd64 sample-arm64 many-arm64 explicit-variant; do
    printf '### %s\n\n' "$s"
    run "\$EXAMPLE classify work/samples/$s.tar work/samples/$s.declaration.json"
    run "jq -c '{public_refs, config_digest, platform}' work/samples/$s.declaration.json"
    run "tar -xOf work/samples/$s.tar index.json | jq -r '.manifests[].digest'"
    run "$D load -i /work/samples/$s.tar"
    run "$D image ls -a --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}'"
    for r in $(jq -r '.public_refs[]' "work/samples/$s.declaration.json"); do
      run "$D image inspect $r --format '{{.Id}}'"
      run "$D image inspect $r --format '{{json .RepoTags}}'"
      run "$D image inspect $r --format '{{.Os}}/{{.Architecture}}/{{with index . \"Variant\"}}{{.}}{{end}}'"
    done
    run "$D image rm $(jq -r '.public_refs | join(" ")' "work/samples/$s.declaration.json")"
    run "$D image ls -a --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}'"
  done

  section "Teardown ($store)"
  run "date -u '+%Y-%m-%dT%H:%M:%SZ'"
  run "docker stop $name"
}

export -f run section
case "${1:-}" in
  samples) samples ;;
  graphdriver) daemon graphdriver false gd ;;
  containerd) daemon containerd true cd ;;
  *) echo "usage: run.sh samples|graphdriver|containerd" >&2; exit 2 ;;
esac
