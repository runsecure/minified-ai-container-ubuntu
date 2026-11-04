# syntax=docker/dockerfile:1.7
# TEST ONLY. Wraps IMAGE in the test guard (Dockerfile stage "guard-testbin"): the
# production guard code and seccomp filter, but the SELinux "confinement" it checks
# is the fake label below. That lets tests run a workload under the real filter on a
# host with no LSM (Docker Desktop). Never push an image built from this file.
ARG IMAGE
ARG TESTBIN=minified/guard-testbin:latest

FROM ${TESTBIN} AS testbin

FROM ${IMAGE}
COPY --from=testbin /container-guard-test /guard-test/container-guard
COPY <<EOF /guard-test/attr
system_u:system_r:container_t:s0:c1,c2
EOF
COPY <<EOF /guard-test/enforce
1
EOF
ENTRYPOINT ["/guard-test/container-guard", "--"]
