# syntax=docker/dockerfile:1.7
# Example: a Python app with third-party wheels on the chiseled Python image.
#
# The runtime image has no pip, so dependencies are installed into a venv in a
# full Ubuntu stage of the SAME release (same CPython minor and glibc as the
# runtime), and only the venv and the app are copied over.
#
#   docker build -t my-app examples/python-app                                 # 24.04, SELinux guard
#   docker build -t my-app --build-arg UBUNTU_RELEASE=26.04 \
#       --build-arg BASE=minified/ubuntu-python:26.04-apparmor examples/python-app
ARG UBUNTU_RELEASE=24.04
ARG BASE=minified/ubuntu-python:${UBUNTU_RELEASE}-selinux

FROM ubuntu:${UBUNTU_RELEASE} AS deps

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
# --only-binary: no compilers in this stage, and no sdist build scripts run at build time.
# For production, pin hashes too (pip-compile --generate-hashes, then --require-hashes).
RUN set -eu; \
    python3 -m venv /opt/venv; \
    /opt/venv/bin/pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt; \
    /opt/venv/bin/pip uninstall -y -q pip; \
    rm -f /opt/venv/bin/activate* /opt/venv/bin/Activate.ps1

COPY app.py /opt/app/app.py
# Precompile: the runtime root filesystem is read-only, so .pyc can't be written there.
RUN python3 -m compileall -q --invalidation-mode unchecked-hash /opt/venv/lib /opt/app

FROM ${BASE}
COPY --from=deps /opt/venv /opt/venv
COPY --from=deps /opt/app /opt/app
ENV PATH=/opt/venv/bin:${PATH}
# CMD only: the base image's ENTRYPOINT (container-guard) stays in front.
CMD ["python3", "/opt/app/app.py"]
