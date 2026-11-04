# minified-ai-container-ubuntu
Minified and Locked down container work for ubuntu

## Core image

A distroless-style Ubuntu base built with [Canonical Chisel](https://github.com/canonical/chisel)
and `FROM scratch`. Built for **Ubuntu 24.04 (Noble)** and **26.04 (Resolute)**.

| Image | Size | Contents |
|---|---|---|
| `ubuntu:24.04` (stock) | ~78 MB | full minimized userland, bash, apt, dpkg |
| `minified/ubuntu-core:24.04` | ~8 MB | glibc, libgcc_s, CA certs, os-release |
| `minified/ubuntu-core:26.04` | ~9 MB | same, from 26.04 |
| `minified/ubuntu-core:{24.04,26.04}-selinux` | +37 KB | core + `container-guard` entrypoint: SELinux check + seccomp (see below) |
| `minified/ubuntu-core:{24.04,26.04}-apparmor` | +37 KB | core + `container-guard` entrypoint: AppArmor check + seccomp (see below) |

What's in it: `base-files` skeleton, `os-release`, glibc, `libgcc_s`, the CA bundle,
a chisel manifest at `/var/lib/chisel/manifest.wall` (used by scanners as an SBOM),
and a minimal `/etc/passwd`/`/etc/group` with a `nonroot` user (uid/gid 65532).

What's **not** in it: no shell, no coreutils, no apt/dpkg, no tzdata, no locales.
Runs as `65532:65532` by default.

### Build

```sh
docker buildx bake --load                 # both releases, all images (core + python, plain/-selinux/-apparmor)
docker buildx bake --load core-24-04      # just one
docker buildx bake --load python-images   # just the python images
docker buildx bake --push all-platforms   # amd64 + arm64, needs a registry
REGISTRY=myregistry.io/me docker buildx bake --load
```

The Chisel version is pinned (`CHISEL_VERSION` in `docker-bake.hcl`), and the download is
checked against the SHA384 published with the release.

### Test

```sh
bash tests/smoke.sh            # both releases
bash tests/smoke.sh 26.04      # one release
```

The tests copy a glibc-linked binary (`getent`) into the image and check that the
dynamic loader, glibc and NSS user lookup work. They also check that there's no
shell or package manager, and that the CA bundle and chisel manifest are present.

## Python image (AI runtime base)

Core plus the distro CPython, built from the same Chisel slices. Each Ubuntu release
ships one Python, so the version follows the release:

| Image | Python | Rootfs (uncompressed / gzip) |
|---|---|---|
| `minified/ubuntu-python:24.04` (also `:3.12-24.04`) | 3.12 | ~54 MB / ~19 MB |
| `minified/ubuntu-python:26.04` (also `:3.14-26.04`) | 3.14 | ~62 MB / ~22 MB |
| `…:{24.04,26.04}-selinux`, `…-apparmor` | same | + `container-guard` entrypoint, as for core |

Slices on top of core: `python3.X_standard` (the full stdlib), `python3-minimal_python3`
(`/usr/bin/python3`), `libstdc++6_libs` (needed by nearly every AI/ML wheel: numpy,
torch, onnxruntime, …) and `tzdata_zoneinfo`.

- **No pip, venv or ensurepip** in the runtime. Install dependencies in a build stage
  and copy them in (below).
- **Stdlib precompiled** at build time (`--invalidation-mode unchecked-hash`), since
  Chisel ships only `.py` files and the root filesystem is read-only at runtime.
  `PYTHONDONTWRITEBYTECODE=1` stops attempts to write `.pyc` files.
- `CMD ["python3"]`, `LANG=C.UTF-8`, `PYTHONUNBUFFERED=1`, uid 65532, no shell.

**Adding dependencies:** see [examples/python-app/](examples/python-app/). In an
`ubuntu:<same release>` stage, create a venv with the distro `python3-venv` (same
CPython minor and glibc as the runtime), `pip install --only-binary=:all:`, remove pip,
precompile, then copy `/opt/venv` and the app into the Python image and set `CMD`:

```dockerfile
FROM minified/ubuntu-python:24.04-selinux
COPY --from=deps /opt/venv /opt/venv
COPY --from=deps /opt/app /opt/app
ENV PATH=/opt/venv/bin:${PATH}
CMD ["python3", "/opt/app/app.py"]    # CMD only: keeps container-guard in front
```

Wheels that need extra system libraries (e.g. `libgomp1` for some OpenMP builds, or
`libgl1` for OpenCV) need their slices added to `PYTHON_SLICES` in the
[Dockerfile](Dockerfile). Most manylinux wheels bundle their own copies.

## LSM (SELinux or AppArmor) + seccomp enforcement (Kubernetes)

Containers share the node's kernel, so the **node OS decides** which Linux Security
Module (LSM) confines them and whether it's enforcing. Nodes run SELinux or AppArmor,
not both, and the image can't switch either on. So there are two guarded variants.
Pick the one that matches each node pool:

| Node OS | LSM | Image variant | Pod field | Node / namespace labels |
|---|---|---|---|---|
| EKS Bottlerocket, RHEL/Fedora/OpenShift | SELinux | `-selinux` | `seLinuxOptions.type: container_t` | `minified.dev/selinux=enforcing` / `minified.dev/selinux-required=true` |
| Ubuntu node pools (EKS/AKS/GKE), GKE COS | AppArmor | `-apparmor` | `appArmorProfile.type: RuntimeDefault` | `minified.dev/apparmor=enforcing` / `minified.dev/apparmor-required=true` |

For AKS Azure Linux, check which LSM your node image runs.

Seccomp is different: a process can lock down its own syscalls, and that lock can't
be undone, so it really is built into the image. **Both variants install the same
seccomp filter.** Enforcement works in three layers:

| Layer | What | Where |
|---|---|---|
| Image | `container-guard` entrypoint: (1) refuses to start (exit 126) unless the container is confined by the variant's LSM (details below); (2) sets `no_new_privs` and installs a seccomp filter before exec'ing the workload | `*-selinux` / `*-apparmor` tags, [guard/](guard/) |
| Pod | LSM field above, non-root, no privilege escalation, drop ALL capabilities, read-only root filesystem, seccomp `RuntimeDefault` | [k8s/example-deployment-selinux.yaml](k8s/example-deployment-selinux.yaml), [k8s/example-deployment-apparmor.yaml](k8s/example-deployment-apparmor.yaml) |
| Cluster | ValidatingAdmissionPolicy per LSM: rejects pods without an allowed SELinux type / AppArmor profile, or without the node selector. Pod Security Admission `restricted` covers the rest | [k8s/selinux-admission-policy.yaml](k8s/selinux-admission-policy.yaml), [k8s/apparmor-admission-policy.yaml](k8s/apparmor-admission-policy.yaml) |

**What the guard accepts:**

- **SELinux variant:** context type `container_t`, `container_init_t` or `container_kvm_t`
  (the Pod Security "restricted" set), or a udica-generated `*.process` type. `spc_t`
  (privileged) and unconfined types are rejected, and so is a visible selinuxfs
  that reports permissive.
- **AppArmor variant:** a label of the form `<profile> (enforce)` or `<profile> (kill)`,
  e.g. `cri-containerd.apparmor.d (enforce)`. `unconfined`, `complain`, `mixed` and
  other modes are rejected, and so is `/sys/module/apparmor/parameters/enabled` ≠ `Y`.
  The guard can't see what a profile allows. That's why the admission policy only
  accepts `RuntimeDefault` or `Localhost` profiles named `minified-*`, i.e. profiles
  you've vetted and loaded on the nodes.

### Built-in seccomp filter

The guard's filter **stacks** with the runtime's profile (`RuntimeDefault`, which Pod
Security `restricted` requires). The kernel applies the strictest result. Nothing
inside the container can remove the filter, and it carries over to every child process.

| Rule | Action |
|---|---|
| Wrong architecture (e.g. i386 `int 0x80` on x86_64) or x32 ABI | kill process |
| `ptrace`, `process_vm_readv/writev`, `process_madvise`, `pidfd_getfd`, `kcmp` | EPERM |
| `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_*`, `keyctl`/`add_key`/`request_key` | EPERM |
| `mount` family, `pivot_root`, `chroot`, `setns`, `*_by_handle_at`, `fanotify_init`, `quotactl*`, `swapon/off` | EPERM |
| kernel modules, `kexec_*`, `reboot`, time setting, `syslog`, `acct`, `iopl/ioperm`, `lsm_set_self_attr`, legacy syscalls | EPERM |
| `clone` / `unshare` with namespace flags | EPERM (`unshare(CLONE_FS)` etc. still allowed) |
| `clone3` | ENOSYS: its flags can't be inspected, and glibc falls back to `clone` |
| `personality` | only `0x0`, `0x8`, `0x20000`, `0x20008`, query: no turning off ASLR |

The policy is a denylist, so it works with any workload without per-app tuning.
**Watch for these compatibility issues:** profilers and debuggers (`py-spy`, `perf`,
`gdb`, `strace`) won't work inside the container, and libraries that prefer `io_uring`
must fall back to epoll or threads. For an app-specific allowlist on top, record one
with the [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
and set `seccompProfile: { type: Localhost, ... }` in the pod spec. It stacks with the guard.

**Using the guarded images:** build `FROM minified/ubuntu-core:24.04-selinux` (or
`-apparmor`) and set `CMD`, not `ENTRYPOINT`. Overriding `ENTRYPOINT` (or `command:`
in a pod spec) removes the guard. The admission policy and Pod Security still
apply, though. If one app has to run on both kinds of node pool, publish both
variants of the app image and deploy each to its matching pool.

**Node pools:** label each pool with the LSM it enforces (table above), then label
namespaces to turn on the matching policy.

**Check on a real node:** a guarded pod that's refused logs a `container-guard: DENY`
line with the label it saw. An SELinux pod also logs its context when selinuxfs is hidden.

```sh
kubectl -n minified-apps logs deploy/example | grep container-guard
kubectl -n minified-apparmor-apps logs deploy/example | grep container-guard
```

### Tests

- **Build time:** [guard/test-guard.sh](guard/test-guard.sh) runs on every image build:
  16 SELinux and 21 AppArmor label scenarios, plus seccomp checks through both
  variants using [guard/syscall-probe.c](guard/syscall-probe.c).
  BuildKit's own seccomp profile already blocks many syscalls, so here the tests
  only check that blocked calls fail and allowed calls are unaffected.
- **Strict:** `docker buildx bake --load test` builds `guard-test` images.
  [tests/smoke.sh](tests/smoke.sh) runs them with `--security-opt seccomp=unconfined`,
  so the baseline is unfiltered. That proves the guard's own filter is what blocks
  `ptrace`, `unshare(CLONE_NEWUSER)`, `personality(ADDR_NO_RANDOMIZE)`, `clone3`, etc.
- **Smoke:** on a host without the variant's LSM (Docker Desktop has neither), the
  `-selinux` and `-apparmor` images must refuse to start (exit 126).
- **Python:** `docker buildx bake --load python-images guard-testbin && bash tests/python.sh`.
  It checks the image layout, then runs [tests/python-selftest.py](tests/python-selftest.py)
  (TLS/CA bundle, OpenSSL, sqlite, ctypes, threads, subprocess, every multiprocessing
  start method, asyncio, NSS, zoneinfo) with the pod settings from the examples:
  read-only root, tmpfs `/tmp`, all capabilities dropped. It runs the same self-test
  **under the guard's seccomp filter**, using a test-only guard build
  (`guard-testbin`, [tests/guarded.Dockerfile](tests/guarded.Dockerfile)): the
  production filter code, but it reads a fake SELinux label from a file, so it runs
  on Docker Desktop. **Never publish that binary or any image built from that file.**
  It also builds [examples/python-app](examples/python-app) (numpy from PyPI, so it needs
  network; `SKIP_EXAMPLE=1` to skip) and runs it plain and under the filter.
- **Kubernetes admission:** `bash tests/k8s-admission.sh` (any cluster ≥ 1.30, e.g.
  Docker Desktop) applies both policies and checks that the API server reports no
  CEL type errors. It then sends 26 pods as server-side dry runs, admitted or rejected
  as expected: missing or wrong SELinux types, `spc_t`, container settings overriding
  pod-level ones, init containers, `Unconfined` and unapproved `Localhost` AppArmor
  profiles, missing node selectors, and namespace scoping. It removes everything it
  created on exit (set `KEEP_POLICIES=1` to leave the policies installed).

### Customizing

Add slices to the `SLICES` build arg in the [Dockerfile](Dockerfile) (core and every
image built on it) or to `PYTHON_SLICES` (Python images only), for example
`libssl3t64_libs` or `libgomp1_libs`. To shrink the Python image, swap
`python3.X_standard` for `python3.X_core` plus only the `libpython3.X-stdlib_*`
slices you need. Browse the available slices
for a release in [chisel-releases](https://github.com/canonical/chisel-releases)
(`ubuntu-24.04` / `ubuntu-26.04` branches).

Note: in 26.04, coreutils binaries come from Rust uutils and link `libsystemd`,
`libselinux` and `libpcre2`. You can't drop a 26.04 `/usr/bin/*` tool into this image
unless you also add those libraries' slices.
