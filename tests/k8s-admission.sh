#!/usr/bin/env bash
# Integration tests for the SELinux and AppArmor ValidatingAdmissionPolicies.
# Needs a cluster (>= 1.30) reachable via kubectl. Pods are sent with
# --dry-run=server, so admission runs for real but nothing is persisted.
# Creates two labelled test namespaces and removes them (and the policies, unless
# KEEP_POLICIES=1) on exit.
#
# Usage: bash tests/k8s-admission.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1

repo="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"
NS_SE=minified-test-selinux NS_AA=minified-test-apparmor NS_OFF=minified-test-unlabelled
pass=0; fail=0

cleanup() {
  kubectl delete ns "$NS_SE" "$NS_AA" "$NS_OFF" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  if [ "${KEEP_POLICIES:-0}" != 1 ]; then
    kubectl delete -f "$repo/k8s/selinux-admission-policy.yaml" -f "$repo/k8s/apparmor-admission-policy.yaml" \
      --ignore-not-found >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

kubectl apply -f "$repo/k8s/selinux-admission-policy.yaml" -f "$repo/k8s/apparmor-admission-policy.yaml" >/dev/null
for ns in "$NS_SE" "$NS_AA" "$NS_OFF"; do kubectl create ns "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; done
kubectl label ns "$NS_SE"  minified.dev/selinux-required=true  --overwrite >/dev/null
kubectl label ns "$NS_AA"  minified.dev/apparmor-required=true --overwrite >/dev/null

# Surface CEL type-check problems the API server found in the policies.
for p in minified-require-selinux minified-require-apparmor; do
  for _ in $(seq 1 20); do
    tc="$(kubectl get validatingadmissionpolicy "$p" -o jsonpath='{.status.typeChecking}' 2>/dev/null || true)"
    [ -n "$tc" ] && break; sleep 0.5
  done
  if [ "$tc" = "{}" ] || [ -z "$(kubectl get validatingadmissionpolicy "$p" -o jsonpath='{.status.typeChecking.expressionWarnings}')" ]; then
    pass=$((pass+1)); echo "ok   $p: CEL type-checks clean"
  else
    fail=$((fail+1)); echo "FAIL $p: type-check warnings: $tc"
  fi
done

# pod <namespace> <spec-yaml (indented 2 spaces, under "spec:")>
pod() {
  cat <<EOF
apiVersion: v1
kind: Pod
metadata: { name: t, namespace: $1 }
spec:
$2
EOF
}

# expect <allow|deny> <name> <namespace> <spec-yaml> [expected-message-substring]
expect() {
  local want="$1" name="$2" ns="$3" spec="$4" msg="${5:-}" out rc
  set +e; out="$(pod "$ns" "$spec" | kubectl apply --dry-run=server -f - 2>&1)"; rc=$?; set -e
  local got=allow; [ $rc -ne 0 ] && got=deny
  if [ "$got" = "$want" ] && { [ -z "$msg" ] || grep -qF -- "$msg" <<<"$out"; }; then
    pass=$((pass+1)); echo "ok   [$want] $name"
  else
    fail=$((fail+1)); echo "FAIL [$want, got $got] $name"; sed 's/^/       /' <<<"$out"
  fi
}

# Wait until the bindings are live (policy propagation is asynchronous).
for _ in $(seq 1 60); do
  if ! pod "$NS_SE" "  containers: [{ name: app, image: x }]" | kubectl apply --dry-run=server -f - >/dev/null 2>&1 &&
     ! pod "$NS_AA" "  containers: [{ name: app, image: x }]" | kubectl apply --dry-run=server -f - >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

C='  containers: [{ name: app, image: registry.k8s.io/pause:3.10 }]'
SEL='  nodeSelector: { minified.dev/selinux: enforcing }'
AAN='  nodeSelector: { minified.dev/apparmor: enforcing }'

echo "-- SELinux policy ($NS_SE)"
expect allow "pod-level container_t" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: container_t } }
$C"
expect allow "pod-level container_t with explicit MCS level" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: container_t, level: 's0:c123,c456' } }
$C"
expect allow "container-level only, container_t" "$NS_SE" "$SEL
  containers: [{ name: app, image: x, securityContext: { seLinuxOptions: { type: container_t } } }]"
expect allow "udica *.process type" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: myapp.process } }
$C"
expect allow "container_init_t" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: container_init_t } }
$C"
expect deny  "no seLinuxOptions at all" "$NS_SE" "$SEL
$C" "offending containers: app"
expect deny  "seLinuxOptions without type" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { level: 's0:c1,c2' } }
$C" "offending containers: app"
expect deny  "spc_t (privileged)" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: spc_t } }
$C"
expect deny  "container override drops type (level only)" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: container_t } }
  containers: [{ name: app, image: x, securityContext: { seLinuxOptions: { level: 's0:c1' } } }]" "offending containers: app"
expect deny  "init container overrides to unconfined_t" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: container_t } }
  initContainers: [{ name: init, image: x, securityContext: { seLinuxOptions: { type: unconfined_t } } }]
$C" "offending containers: init"
expect deny  "only the bad container is named" "$NS_SE" "$SEL
  securityContext: { seLinuxOptions: { type: container_t } }
  containers:
    - { name: good, image: x }
    - { name: bad, image: x, securityContext: { seLinuxOptions: { type: spc_t } } }" "offending containers: bad"
expect deny  "missing nodeSelector" "$NS_SE" "  securityContext: { seLinuxOptions: { type: container_t } }
$C" "minified.dev/selinux: enforcing"
expect deny  "nodeSelector wrong value" "$NS_SE" "  nodeSelector: { minified.dev/selinux: permissive }
  securityContext: { seLinuxOptions: { type: container_t } }
$C" "minified.dev/selinux: enforcing"
expect deny  "AppArmor-only pod in SELinux namespace" "$NS_SE" "$AAN
  securityContext: { appArmorProfile: { type: RuntimeDefault } }
$C"

echo "-- AppArmor policy ($NS_AA)"
expect allow "pod-level RuntimeDefault" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: RuntimeDefault } }
$C"
expect allow "Localhost minified-* profile" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: Localhost, localhostProfile: minified-app } }
$C"
expect allow "container-level only, RuntimeDefault" "$NS_AA" "$AAN
  containers: [{ name: app, image: x, securityContext: { appArmorProfile: { type: RuntimeDefault } } }]"
expect deny  "no appArmorProfile at all" "$NS_AA" "$AAN
$C" "offending containers: app"
expect deny  "Unconfined" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: Unconfined } }
$C" "offending containers: app"
expect deny  "Localhost profile not in allowlist" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: Localhost, localhostProfile: other-profile } }
$C" "offending containers: app"
expect deny  "Localhost prefix must be a prefix (x-minified-app)" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: Localhost, localhostProfile: x-minified-app } }
$C"
expect deny  "container overrides to Unconfined" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: RuntimeDefault } }
  containers: [{ name: app, image: x, securityContext: { appArmorProfile: { type: Unconfined } } }]" "offending containers: app"
expect deny  "init container overrides to Unconfined" "$NS_AA" "$AAN
  securityContext: { appArmorProfile: { type: RuntimeDefault } }
  initContainers: [{ name: init, image: x, securityContext: { appArmorProfile: { type: Unconfined } } }]
$C" "offending containers: init"
expect deny  "missing nodeSelector" "$NS_AA" "  securityContext: { appArmorProfile: { type: RuntimeDefault } }
$C" "minified.dev/apparmor: enforcing"
expect deny  "SELinux-only pod in AppArmor namespace" "$NS_AA" "$SEL
  securityContext: { seLinuxOptions: { type: container_t } }
$C"

echo "-- Scope ($NS_OFF, no opt-in label)"
expect allow "unlabelled namespace is not affected" "$NS_OFF" "$C"

echo "k8s admission tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
