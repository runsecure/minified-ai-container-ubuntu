# Probe image: drops a single libc-only binary (getent) into the core image
# so we can prove the dynamic loader, glibc, and NSS user lookups work.
ARG UBUNTU_RELEASE=24.04
ARG CORE_IMAGE=minified/ubuntu-core:${UBUNTU_RELEASE}

FROM ubuntu:${UBUNTU_RELEASE} AS src

FROM ${CORE_IMAGE}
COPY --from=src /usr/bin/getent /usr/bin/getent
ENTRYPOINT ["/usr/bin/getent"]
