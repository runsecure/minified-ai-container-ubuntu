# syntax=docker/dockerfile:1.7
#
# Minimal "core" and "python" Ubuntu images built with Canonical Chisel, each
# with -selinux / -apparmor variants that put container-guard in front.
# The final images are FROM scratch and contain only the selected slices:
# no shell, no package manager, no apt/dpkg metadata.
#
# Build:  docker buildx bake            (both releases)
#         docker buildx bake core-24-04 (one release)

ARG UBUNTU_RELEASE=24.04

# ---------------------------------------------------------------------------
# Builder: fetch + verify chisel, then cut the root filesystem.
# ---------------------------------------------------------------------------
FROM ubuntu:${UBUNTU_RELEASE} AS builder

ARG UBUNTU_RELEASE
ARG CHISEL_VERSION=v1.5.1
ARG TARGETARCH

# Slices that make up the core rootfs. Keep this list small; higher layers
# (python, openssl, etc.) should add their own slices on top.
ARG SLICES="\
    base-files_base \
    base-files_release-info \
    base-files_chisel \
    ca-certificates_data \
    libc6_libs \
    libgcc-s1_libs"

# Non-root runtime identity (distroless convention).
ARG APP_UID=65532
ARG APP_GID=65532
ARG APP_USER=nonroot

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ADD https://github.com/canonical/chisel/releases/download/${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${TARGETARCH}.tar.gz \
    /tmp/chisel.tar.gz
ADD https://github.com/canonical/chisel/releases/download/${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${TARGETARCH}.tar.gz.sha384 \
    /tmp/chisel.tar.gz.sha384

RUN set -eu; \
    expected="$(cut -d' ' -f1 /tmp/chisel.tar.gz.sha384)"; \
    echo "${expected}  /tmp/chisel.tar.gz" | sha384sum -c -; \
    tar -xzf /tmp/chisel.tar.gz -C /usr/local/bin chisel; \
    chisel version

# mkroot <dir> <slice>...: cut slices into <dir>, then add a minimal user database
# (so the image can run as non-root by name) and /tmp. Shared by the core and
# python rootfs so both get the same identity.
COPY <<'EOF' /usr/local/bin/mkroot
#!/bin/sh
set -eu
. /etc/mkroot.env
root="$1"; shift
mkdir -p "$root"
chisel cut --release "ubuntu-${UBUNTU_RELEASE}" --root "$root" "$@"
mkdir -p "$root/etc" "$root/home/${APP_USER}" "$root/tmp"
printf 'root:x:0:0:root:/root:/sbin/nologin\n%s:x:%s:%s:%s:/home/%s:/sbin/nologin\n' \
    "${APP_USER}" "${APP_UID}" "${APP_GID}" "${APP_USER}" "${APP_USER}" > "$root/etc/passwd"
printf 'root:x:0:\n%s:x:%s:\n' "${APP_USER}" "${APP_GID}" > "$root/etc/group"
chown "${APP_UID}:${APP_GID}" "$root/home/${APP_USER}"
chmod 1777 "$root/tmp"
EOF

RUN set -eu; \
    printf 'UBUNTU_RELEASE=%s\nAPP_USER=%s\nAPP_UID=%s\nAPP_GID=%s\nCORE_SLICES="%s"\n' \
        "${UBUNTU_RELEASE}" "${APP_USER}" "${APP_UID}" "${APP_GID}" "$(echo ${SLICES})" > /etc/mkroot.env; \
    chmod 0755 /usr/local/bin/mkroot; \
    mkroot /rootfs ${SLICES}

# ---------------------------------------------------------------------------
# Python rootfs: core slices + CPython (full stdlib), libstdc++ (needed by most
# AI/ML wheels: numpy, torch, onnxruntime, ...) and tzdata for zoneinfo.
# No pip/venv/ensurepip: install dependencies in a build stage and copy them in
# (see examples/python-app).
# ---------------------------------------------------------------------------
FROM builder AS python-builder

ARG PYTHON_VERSION=3.12
ARG PYTHON_SLICES="\
    python${PYTHON_VERSION}_standard \
    python3-minimal_python3 \
    libstdc++6_libs \
    tzdata_zoneinfo"

RUN set -eu; \
    . /etc/mkroot.env; \
    mkroot /rootfs-python ${CORE_SLICES} ${PYTHON_SLICES}; \
    # Chisel ships .py sources only (Ubuntu builds .pyc in postinst). Precompile the
    # stdlib so imports don't recompile on every start (the root filesystem is
    # read-only at runtime). unchecked-hash: the .pyc is used as is, whatever the
    # source mtimes are after COPY.
    chroot /rootfs-python /usr/bin/python3 -m compileall -q \
        --invalidation-mode unchecked-hash "/usr/lib/python${PYTHON_VERSION}"; \
    chroot /rootfs-python /usr/bin/python3 -c \
        "import sys; assert sys.version.startswith('${PYTHON_VERSION}.'), sys.version"

# ---------------------------------------------------------------------------
# container-guard (SELinux check + seccomp filter): compile, unit-test, then
# build the hardened release binary.
# ---------------------------------------------------------------------------
FROM ubuntu:${UBUNTU_RELEASE} AS guard

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*

COPY guard/ /src/
RUN sh /src/test-guard.sh /src/container-guard.c /src/syscall-probe.c
RUN set -eu; for v in selinux apparmor; do \
      gcc -O2 -Wall -Wextra -Werror -s -DGUARD_LSM_$(echo $v | tr a-z A-Z) \
        -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection \
        $([ "$(uname -m)" = x86_64 ] && echo -fcf-protection=full) \
        -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack \
        -o /container-guard-$v /src/container-guard.c; \
    done

# Test-only image: reruns the guard tests at container runtime. tests/smoke.sh runs it
# with the runtime's seccomp disabled to prove the guard's own filter does the blocking.
FROM guard AS guard-test
ENV STRICT=1
ENTRYPOINT ["sh", "/src/test-guard.sh", "/src/container-guard.c", "/src/syscall-probe.c"]

# Test-only guard binary: the real SELinux guard and seccomp filter, but it reads its
# "confinement" from files under /guard-test/ instead of /proc and /sys. That lets
# tests run workloads under the exact production filter on hosts with no LSM
# (e.g. Docker Desktop). Static, so it runs in any image. NEVER ship it: anyone who
# can write /guard-test/attr passes the LSM check.
FROM guard AS guard-testbin-build
RUN gcc -O2 -Wall -Wextra -Werror -s -static -DGUARD_LSM_SELINUX \
      -DATTR_PATH_STACKED='"/guard-test/attr"' -DATTR_PATH_LEGACY='"/guard-test/attr"' \
      -DENFORCE_PATH='"/guard-test/enforce"' \
      -o /container-guard-test /src/container-guard.c

FROM scratch AS guard-testbin
COPY --from=guard-testbin-build /container-guard-test /container-guard-test

# ---------------------------------------------------------------------------
# Final image: core (no guard)
# ---------------------------------------------------------------------------
FROM scratch AS core

ARG UBUNTU_RELEASE
ARG CHISEL_VERSION=v1.5.1

COPY --from=builder /rootfs /

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

LABEL org.opencontainers.image.title="minified-ubuntu-core" \
      org.opencontainers.image.description="Chiseled Ubuntu ${UBUNTU_RELEASE} core (no shell, no package manager)" \
      org.opencontainers.image.base.name="scratch" \
      org.opencontainers.image.version="${UBUNTU_RELEASE}" \
      io.chisel.version="${CHISEL_VERSION}"

USER 65532:65532
WORKDIR /home/nonroot

# ---------------------------------------------------------------------------
# Final images: core-selinux / core-apparmor
# The entrypoint refuses to run unless the container is confined by the named LSM,
# then installs a seccomp filter before exec'ing the workload. Downstream images
# set CMD, not ENTRYPOINT, so the guard stays in front.
# ---------------------------------------------------------------------------
FROM core AS core-selinux

ARG UBUNTU_RELEASE

COPY --from=guard --chown=0:0 --chmod=0555 /container-guard-selinux /usr/local/bin/container-guard

LABEL org.opencontainers.image.title="minified-ubuntu-core-selinux" \
      org.opencontainers.image.description="Chiseled Ubuntu ${UBUNTU_RELEASE} core; SELinux-confinement check + built-in seccomp filter"

ENTRYPOINT ["/usr/local/bin/container-guard", "--"]

FROM core AS core-apparmor

ARG UBUNTU_RELEASE

COPY --from=guard --chown=0:0 --chmod=0555 /container-guard-apparmor /usr/local/bin/container-guard

LABEL org.opencontainers.image.title="minified-ubuntu-core-apparmor" \
      org.opencontainers.image.description="Chiseled Ubuntu ${UBUNTU_RELEASE} core; AppArmor-confinement check + built-in seccomp filter"

ENTRYPOINT ["/usr/local/bin/container-guard", "--"]

# ---------------------------------------------------------------------------
# Final images: python / python-selinux / python-apparmor
# CMD is python3, so a downstream image only needs CMD ["python3", "app.py"].
# ---------------------------------------------------------------------------
FROM scratch AS python

ARG UBUNTU_RELEASE
ARG PYTHON_VERSION=3.12
ARG CHISEL_VERSION=v1.5.1

COPY --from=python-builder /rootfs-python /

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.title="minified-ubuntu-python" \
      org.opencontainers.image.description="Chiseled Ubuntu ${UBUNTU_RELEASE} + Python ${PYTHON_VERSION} (no shell, no package manager, no pip)" \
      org.opencontainers.image.base.name="scratch" \
      org.opencontainers.image.version="${UBUNTU_RELEASE}" \
      io.chisel.version="${CHISEL_VERSION}" \
      dev.minified.python.version="${PYTHON_VERSION}"

USER 65532:65532
WORKDIR /home/nonroot
CMD ["python3"]

# Setting ENTRYPOINT clears the inherited CMD, so both are set again below.
FROM python AS python-selinux

ARG UBUNTU_RELEASE
ARG PYTHON_VERSION=3.12

COPY --from=guard --chown=0:0 --chmod=0555 /container-guard-selinux /usr/local/bin/container-guard

LABEL org.opencontainers.image.title="minified-ubuntu-python-selinux" \
      org.opencontainers.image.description="Chiseled Ubuntu ${UBUNTU_RELEASE} + Python ${PYTHON_VERSION}; SELinux-confinement check + built-in seccomp filter"

ENTRYPOINT ["/usr/local/bin/container-guard", "--"]
CMD ["python3"]

FROM python AS python-apparmor

ARG UBUNTU_RELEASE
ARG PYTHON_VERSION=3.12

COPY --from=guard --chown=0:0 --chmod=0555 /container-guard-apparmor /usr/local/bin/container-guard

LABEL org.opencontainers.image.title="minified-ubuntu-python-apparmor" \
      org.opencontainers.image.description="Chiseled Ubuntu ${UBUNTU_RELEASE} + Python ${PYTHON_VERSION}; AppArmor-confinement check + built-in seccomp filter"

ENTRYPOINT ["/usr/local/bin/container-guard", "--"]
CMD ["python3"]
