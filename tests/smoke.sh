#!/usr/bin/env bash
# Smoke tests for the chiseled core images.
# Usage: tests/smoke.sh [24.04 26.04 ...]   (defaults to both)
set -euo pipefail
export MSYS_NO_PATHCONV=1   # stop Git Bash on Windows from rewriting /paths

REGISTRY="${REGISTRY:-minified}"
RELEASES=("${@:-24.04 26.04}")
# shellcheck disable=SC2206
RELEASES=(${RELEASES[*]})
here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"  # -W: native path on Git Bash
fail=0

check() { # name, command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  PASS  $name"; else echo "  FAIL  $name"; fail=1; fi
}

for rel in "${RELEASES[@]}"; do
  img="${REGISTRY}/ubuntu-core:${rel}"
  probe="smoke-probe:${rel}"
  echo "== ${img}"

  docker build -q -t "$probe" --build-arg UBUNTU_RELEASE="$rel" --build-arg CORE_IMAGE="$img" \
    -f "$here/smoke.Dockerfile" "$here" >/dev/null

  files="$(docker create "$img" /none)"
  listing="$(docker export "$files" | tar -t)"
  docker rm "$files" >/dev/null

  check "glibc binary runs (getent)"        docker run --rm "$probe" passwd root
  check "nonroot user resolvable via NSS"   docker run --rm "$probe" passwd nonroot
  check "runs as uid 65532 by default"      test "$(docker image inspect -f '{{.Config.User}}' "$img")" = "65532:65532"
  check "no shell present"                  bash -c "! grep -qxE '(usr/)?bin/(ba|da)?sh' <<<\"\$0\"" "$listing"
  check "no apt/dpkg present"               bash -c "! grep -qE '(bin/apt|bin/dpkg|var/lib/dpkg)' <<<\"\$0\"" "$listing"
  check "CA bundle present"                 grep -qx 'etc/ssl/certs/ca-certificates.crt' <<<"$listing"
  check "chisel manifest present (SBOM)"    grep -qx 'var/lib/chisel/manifest.wall' <<<"$listing"
  check "os-release present"                grep -qE '^(usr/lib|etc)/os-release$' <<<"$listing"

  echo "  size: $(docker image inspect -f '{{.Size}}' "$img" | awk '{printf "%.1f MB", $1/1000/1000}')"
  docker rmi "$probe" >/dev/null

  for lsm in selinux apparmor; do
    sel="${img}-${lsm}"
    docker image inspect "$sel" >/dev/null 2>&1 || continue
    echo "== ${sel}"
    check "entrypoint is container-guard" \
      test "$(docker image inspect -f '{{json .Config.Entrypoint}}' "$sel")" = '["/usr/local/bin/container-guard","--"]'
    check "runs as uid 65532 by default" test "$(docker image inspect -f '{{.Config.User}}' "$sel")" = "65532:65532"
    if docker info -f '{{json .SecurityOptions}}' | grep -q "name=${lsm}"; then
      echo "  SKIP  deny-on-unconfined check (this Docker host has ${lsm} enabled)"
    else
      # This host doesn't have this LSM, so the guard must refuse with exit 126.
      check "refuses to run without ${lsm} (exit 126)" \
        bash -c 'docker run --rm "$0" /usr/bin/true >/dev/null 2>&1; test $? -eq 126' "$sel"
    fi
    echo "  size: $(docker image inspect -f '{{.Size}}' "$sel" | awk '{printf "%.1f MB", $1/1000/1000}')"
  done

  gt="${REGISTRY}/guard-test:${rel}"
  if docker image inspect "$gt" >/dev/null 2>&1; then
    echo "== ${gt} (strict seccomp tests, runtime seccomp disabled)"
    if docker run --rm --security-opt seccomp=unconfined "$gt" > /tmp/guard-test.$$ 2>&1; then
      echo "  PASS  $(tail -1 /tmp/guard-test.$$)"
    else
      echo "  FAIL  guard-test:"; sed 's/^/        /' /tmp/guard-test.$$; fail=1
    fi
    rm -f /tmp/guard-test.$$
  fi
done

exit "$fail"
