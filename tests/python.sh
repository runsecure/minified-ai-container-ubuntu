#!/usr/bin/env bash
# Tests for the chiseled Python images.
#   docker buildx bake --load python-images guard-testbin
#   bash tests/python.sh [24.04 26.04 ...]          (defaults to both)
#
# For each release:
#   1. image layout: no shell/pip, CMD, uid, precompiled stdlib, chisel manifest
#   2. stdlib self-test, run the way the k8s examples run pods (read-only root,
#      tmpfs /tmp, all capabilities dropped, no-new-privileges)
#   3. the same self-test under container-guard's real seccomp filter, via the
#      test-only guard (tests/guarded.Dockerfile). Once with the runtime's seccomp
#      off (the guard's filter alone), once stacked with the runtime default.
#   4. -selinux / -apparmor variants: guard is the entrypoint and refuses to run
#      on a host without that LSM (exit 126)
#   5. examples/python-app (numpy from PyPI, so needs network): plain and under
#      the guard's filter. SKIP_EXAMPLE=1 skips it.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # stop Git Bash on Windows from rewriting /paths

REGISTRY="${REGISTRY:-minified}"
RELEASES=("${@:-24.04 26.04}")
# shellcheck disable=SC2206
RELEASES=(${RELEASES[*]})
here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
repo="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"
fail=0
HARDENED=(--read-only --tmpfs /tmp:mode=1777 --cap-drop ALL --security-opt no-new-privileges)

check() { # name, command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  PASS  $name"; else echo "  FAIL  $name"; fail=1; fi
}

# run_logged <name> <command...>: like check, but shows the command's output on failure
# and its last line on success.
run_logged() {
  local name="$1" out; shift
  if out="$("$@" 2>&1)"; then
    echo "  PASS  $name: $(tail -1 <<<"$out")"
  else
    echo "  FAIL  $name"; sed 's/^/        /' <<<"$out"; fail=1
  fi
}

testbin="${REGISTRY}/guard-testbin:latest"
docker image inspect "$testbin" >/dev/null 2>&1 || {
  echo "missing $testbin: run  docker buildx bake --load guard-testbin"; exit 1; }

for rel in "${RELEASES[@]}"; do
  img="${REGISTRY}/ubuntu-python:${rel}"
  echo "== ${img}"
  docker image inspect "$img" >/dev/null 2>&1 || { echo "  FAIL  image not built"; fail=1; continue; }

  c="$(docker create "$img")"
  listing="$(docker export "$c" | tar -t)"
  docker rm "$c" >/dev/null
  py="$(docker image inspect -f '{{index .Config.Labels "dev.minified.python.version"}}' "$img")"

  check "runs as uid 65532 by default"   test "$(docker image inspect -f '{{.Config.User}}' "$img")" = "65532:65532"
  check "CMD is python3, no ENTRYPOINT"  test "$(docker image inspect -f '{{json .Config.Cmd}}{{json .Config.Entrypoint}}' "$img")" = '["python3"]null'
  check "no shell present"               bash -c "! grep -qxE '(usr/)?bin/(ba|da)?sh' <<<\"\$0\"" "$listing"
  check "no apt/dpkg/pip/ensurepip"      bash -c "! grep -qE '(bin/apt|bin/dpkg|var/lib/dpkg|bin/pip|/ensurepip/)' <<<\"\$0\"" "$listing"
  check "python${py} stdlib precompiled" grep -qx "usr/lib/python${py}/__pycache__/os.cpython-${py/./}.pyc" <<<"$listing"
  check "libstdc++ present (AI wheels)"  grep -qE '^usr/lib/[^/]+-linux-gnu/libstdc\+\+\.so\.6$' <<<"$listing"
  check "chisel manifest present (SBOM)" grep -qx 'var/lib/chisel/manifest.wall' <<<"$listing"

  run_logged "stdlib self-test (hardened pod settings)" \
    docker run -i --rm "${HARDENED[@]}" "$img" python3 - < "$here/python-selftest.py"

  gimg="python-guarded-test:${rel}"
  docker build -q -t "$gimg" --build-arg IMAGE="$img" --build-arg TESTBIN="$testbin" \
    -f "$here/guarded.Dockerfile" "$here" >/dev/null
  run_logged "self-test under guard filter only (runtime seccomp off)" \
    docker run -i --rm "${HARDENED[@]}" --security-opt seccomp=unconfined "$gimg" python3 - guarded < "$here/python-selftest.py"
  run_logged "self-test under guard filter + runtime default seccomp" \
    docker run -i --rm "${HARDENED[@]}" "$gimg" python3 - guarded < "$here/python-selftest.py"
  docker rmi "$gimg" >/dev/null

  echo "  size: $(docker image inspect -f '{{.Size}}' "$img" | awk '{printf "%.1f MB", $1/1000/1000}') (docker); rootfs $(c=$(docker create "$img"); docker export "$c" | wc -c | awk '{printf "%.1f MB", $1/1e6}'; docker rm "$c" >/dev/null)"

  for lsm in selinux apparmor; do
    v="${img}-${lsm}"
    docker image inspect "$v" >/dev/null 2>&1 || continue
    echo "== ${v}"
    check "entrypoint is container-guard, CMD python3" \
      test "$(docker image inspect -f '{{json .Config.Entrypoint}}{{json .Config.Cmd}}' "$v")" = '["/usr/local/bin/container-guard","--"]["python3"]'
    check "runs as uid 65532 by default" test "$(docker image inspect -f '{{.Config.User}}' "$v")" = "65532:65532"
    if docker info -f '{{json .SecurityOptions}}' | grep -q "name=${lsm}"; then
      echo "  SKIP  deny-on-unconfined check (this Docker host has ${lsm} enabled)"
    else
      check "refuses to run without ${lsm} (exit 126)" \
        bash -c 'docker run --rm "$0" python3 -c 1 >/dev/null 2>&1; test $? -eq 126' "$v"
    fi
  done

  if [ "${SKIP_EXAMPLE:-0}" != 1 ]; then
    app="python-app-test:${rel}"
    echo "== examples/python-app on ${img}"
    if docker build -q -t "$app" --build-arg UBUNTU_RELEASE="$rel" --build-arg BASE="$img" \
         "$repo/examples/python-app" >/dev/null; then
      run_logged "numpy app (hardened pod settings)" docker run --rm "${HARDENED[@]}" "$app"
      docker build -q -t "$app-guarded" --build-arg IMAGE="$app" --build-arg TESTBIN="$testbin" \
        -f "$here/guarded.Dockerfile" "$here" >/dev/null
      run_logged "numpy app under guard filter only (runtime seccomp off)" \
        docker run --rm "${HARDENED[@]}" --security-opt seccomp=unconfined "$app-guarded" python3 /opt/app/app.py
      docker rmi "$app" "$app-guarded" >/dev/null
    else
      echo "  FAIL  example build"; fail=1
    fi
  fi
done

exit "$fail"
