# syntax=docker/dockerfile:1.7
#
# Minimal "core" Ubuntu image built with Canonical Chisel.
# The final image is FROM scratch and contains only the selected slices:
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

RUN set -eu; \
    mkdir -p /rootfs; \
    chisel cut --release "ubuntu-${UBUNTU_RELEASE}" --root /rootfs ${SLICES}; \
    # Minimal user database so the image can run as non-root by name.
    mkdir -p /rootfs/etc /rootfs/home/${APP_USER} /rootfs/tmp; \
    printf 'root:x:0:0:root:/root:/sbin/nologin\n%s:x:%s:%s:%s:/home/%s:/sbin/nologin\n' \
        "${APP_USER}" "${APP_UID}" "${APP_GID}" "${APP_USER}" "${APP_USER}" > /rootfs/etc/passwd; \
    printf 'root:x:0:\n%s:x:%s:\n' "${APP_USER}" "${APP_GID}" > /rootfs/etc/group; \
    chown "${APP_UID}:${APP_GID}" /rootfs/home/${APP_USER}; \
    chmod 1777 /rootfs/tmp

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
