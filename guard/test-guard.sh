#!/bin/sh
# Unit tests for container-guard (both the SELinux and AppArmor variants). Compiles
# test builds whose /proc and /sys paths point at a scratch directory, then checks
# each scenario. Runs at image build time, and in the guard-test image (STRICT=1).
#   usage: test-guard.sh <container-guard.c> <syscall-probe.c>
set -eu

CC="${CC:-gcc}"
SRC="${1:?usage: test-guard.sh <container-guard.c> <syscall-probe.c>}"
PROBE_SRC="${2:?usage: test-guard.sh <container-guard.c> <syscall-probe.c>}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

for v in SELINUX APPARMOR; do
  "$CC" -O2 -Wall -Wextra -Werror -DGUARD_LSM_$v \
    -DATTR_PATH_STACKED="\"$T/stacked\"" \
    -DATTR_PATH_LEGACY="\"$T/legacy\"" \
    -DENFORCE_PATH="\"$T/enforce\"" \
    -o "$T/guard-$v" "$SRC"
done
"$CC" -O2 -Wall -Wextra -Werror -o "$T/probe" "$PROBE_SRC"

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }

set_ctx() { # <stacked|-> <legacy|-> <enforce|->
  rm -f "$T/stacked" "$T/legacy" "$T/enforce"
  [ "$1" = - ] || printf '%s\n' "$1" > "$T/stacked"
  [ "$2" = - ] || printf '%s\n' "$2" > "$T/legacy"
  [ "$3" = - ] || printf '%s\n' "$3" > "$T/enforce"
}

# case <name> <expected-exit> <stacked|-> <legacy|-> <enforce|-> [cmd...]   (uses $GUARD)
case_() {
  name="$1" want="$2"; shift 2
  set_ctx "$1" "$2" "$3"; shift 3
  [ $# -gt 0 ] || set -- true
  set +e; "$GUARD" -- "$@" 2>"$T/err"; got=$?; set -e
  if [ "$got" = "$want" ]; then ok "$name"; else bad "$name (want $want, got $got): $(cat "$T/err")"; fi
}

C=system_u:system_r:container_t:s0:c123,c456
A="cri-containerd.apparmor.d (enforce)"

echo "-- SELinux variant"
GUARD="$T/guard-SELINUX"
case_ "no context readable"             126 - - -
case_ "kernel (no LSM label)"           126 - kernel -
case_ "AppArmor label rejected"         126 - "$A" -
case_ "spc_t (privileged) rejected"     126 - system_u:system_r:spc_t:s0 1
case_ "unconfined_t rejected"           126 - unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 1
case_ "empty level rejected"            126 - system_u:system_r:container_t: 1
case_ "bare .process type rejected"     126 - system_u:system_r:.process:s0 1
case_ "container_t + enforcing"         0   - "$C" 1
case_ "container_t + permissive"        126 - "$C" 0
case_ "container_t + selinuxfs hidden"  0   - "$C" -
case_ "container_init_t allowed"        0   - system_u:system_r:container_init_t:s0 1
case_ "udica *.process allowed"         0   - system_u:system_r:myapp.process:s0:c1,c2 1
case_ "stacked attr preferred"          0   "$C" "$A" 1
case_ "stacked label checked too"       126 system_u:system_r:spc_t:s0 "$C" 1
case_ "args and exit code pass through" 7   - "$C" 1 sh -c 'exit "$0"' 7
case_ "missing program"                 127 - "$C" 1 /nonexistent

echo "-- AppArmor variant"
GUARD="$T/guard-APPARMOR"
case_ "no label readable"               126 - - -
case_ "kernel (no LSM label)"           126 - kernel -
case_ "unconfined rejected"             126 - unconfined Y
case_ "SELinux context rejected"        126 - "$C" -
case_ "complain mode rejected"          126 - "cri-containerd.apparmor.d (complain)" Y
case_ "mixed mode rejected"             126 - "a//&b (mixed)" Y
case_ "unconfined-mode profile rejected" 126 - "unconfined (unconfined)" Y
case_ "profile named unconfined, enforce rejected" 126 - "unconfined (enforce)" Y
case_ "empty profile name rejected"     126 - " (enforce)" Y
case_ "missing mode rejected"           126 - "cri-containerd.apparmor.d" Y
case_ "runtime default + enforce"       0   - "$A" Y
case_ "docker-default + enforce"        0   - "docker-default (enforce)" Y
case_ "kill mode allowed"               0   - "my-app (kill)" Y
case_ "localhost profile w/ spaces/hat" 0   - "k8s app profile//hat (enforce)" Y
case_ "namespaced stacked profile"      0   - ":ns:outer//&inner (enforce)" Y
case_ "trailing ' (enforce)' spoof rejected" 126 - "x (enforce) (complain)" Y
case_ "AppArmor disabled on node"       126 - "$A" N
case_ "enabled param hidden"            0   - "$A" -
case_ "stacked attr preferred"          0   "$A" "$C" Y
case_ "stacked label checked too"       126 unconfined "$A" Y
case_ "args and exit code pass through" 7   - "$A" Y sh -c 'exit "$0"' 7

# Seccomp is identical in both variants; exercise it through each.
res() { awk -v k="$2" '$1==k {print $2}' "$T/$1"; }
EPERM=1 ENOSYS=38
expect() { # <name> <want>
  got="$(res guarded "$1")"
  if [ "$got" = "$2" ]; then ok "$1 -> $2 (unguarded: $(res base "$1"))"
  else bad "$1: want $2, got '${got}' (unguarded: $(res base "$1"))"; fi
}

"$T/probe" > "$T/base"
for v in SELINUX APPARMOR; do
  echo "-- seccomp ($v variant)"
  if [ $v = SELINUX ]; then set_ctx - "$C" 1; else set_ctx - "$A" Y; fi
  "$T/guard-$v" -- "$T/probe" > "$T/guarded" 2>"$T/err" || bad "probe under guard ran: $(cat "$T/err")"

  base_f="$(res base seccomp_filters)"; g_f="$(res guarded seccomp_filters)"
  if [ "$g_f" -eq $((base_f + 1)) ]; then ok "filter installed (Seccomp_filters $base_f -> $g_f)"
  else bad "filter installed (Seccomp_filters $base_f -> $g_f)"; fi
  expect nnp 1

  for s in ptrace process_vm_readv bpf io_uring_setup keyctl perf_event_open mount setns \
           unshare_newuser unshare_newnet personality_no_aslr; do
    expect "$s" "$EPERM"
  done
  expect clone3 "$ENOSYS"

  # Allowed operations: the guard must not change the result (the baseline may already
  # be restricted by the outer runtime's seccomp profile, e.g. during docker build).
  for s in getpid open unshare_fs personality_query spawn fork pthread; do
    b="$(res base "$s")"; g="$(res guarded "$s")"
    if [ "$g" = "$b" ]; then ok "$s unaffected by guard ($g)"; else bad "$s: guard changed $b -> $g"; fi
  done
  for s in getpid open spawn fork pthread; do expect "$s" 0; done

  # STRICT=1: run with the runtime's seccomp disabled
  # (docker run --security-opt seccomp=unconfined), so the baseline is unfiltered and
  # these denials provably come from container-guard.
  if [ "${STRICT:-0}" = 1 ]; then
    for s in ptrace process_vm_readv unshare_newuser personality_no_aslr clone3; do
      b="$(res base "$s")"; g="$(res guarded "$s")"
      if [ "$b" != "$g" ]; then ok "strict: $s blocked by guard ($b -> $g)"
      else bad "strict: $s same with and without guard ($b); baseline not unconfined?"; fi
    done
    expect unshare_fs 0
  fi
done

echo "container-guard tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
