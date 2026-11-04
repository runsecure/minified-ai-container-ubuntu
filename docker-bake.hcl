variable "REGISTRY" {
  default = "minified"
}

variable "CHISEL_VERSION" {
  default = "v1.5.1"
}

# Ubuntu release -> the CPython its archive ships (and chisel-releases slices).
PYTHONS = [
  { rel = "24.04", py = "3.12" },
  { rel = "26.04", py = "3.14" },
]

group "default" {
  targets = [
    "core-24-04", "core-26-04",
    "core-selinux-24-04", "core-selinux-26-04",
    "core-apparmor-24-04", "core-apparmor-26-04",
    "python-images",
  ]
}

target "_core" {
  dockerfile = "Dockerfile"
  target     = "core"
  args = {
    CHISEL_VERSION = CHISEL_VERSION
  }
}

target "core-24-04" {
  inherits = ["_core"]
  args     = { UBUNTU_RELEASE = "24.04" }
  tags     = ["${REGISTRY}/ubuntu-core:24.04"]
}

target "core-26-04" {
  inherits = ["_core"]
  args     = { UBUNTU_RELEASE = "26.04" }
  tags     = ["${REGISTRY}/ubuntu-core:26.04"]
}

target "core-selinux-24-04" {
  inherits = ["core-24-04"]
  target   = "core-selinux"
  tags     = ["${REGISTRY}/ubuntu-core:24.04-selinux"]
}

target "core-selinux-26-04" {
  inherits = ["core-26-04"]
  target   = "core-selinux"
  tags     = ["${REGISTRY}/ubuntu-core:26.04-selinux"]
}

target "core-apparmor-24-04" {
  inherits = ["core-24-04"]
  target   = "core-apparmor"
  tags     = ["${REGISTRY}/ubuntu-core:24.04-apparmor"]
}

target "core-apparmor-26-04" {
  inherits = ["core-26-04"]
  target   = "core-apparmor"
  tags     = ["${REGISTRY}/ubuntu-core:26.04-apparmor"]
}

# Python runtime: python-24-04, python-selinux-24-04, python-apparmor-26-04, ...
# Tagged by Ubuntu release, and by python+release (e.g. ubuntu-python:3.12-24.04-selinux).
target "python-images" {
  name     = "${variant}-${replace(p.rel, ".", "-")}"
  inherits = ["_core"]
  matrix   = { p = PYTHONS, variant = ["python", "python-selinux", "python-apparmor"] }
  target   = variant
  args     = { UBUNTU_RELEASE = p.rel, PYTHON_VERSION = p.py }
  tags = [
    "${REGISTRY}/ubuntu-python:${p.rel}${trimprefix(variant, "python")}",
    "${REGISTRY}/ubuntu-python:${p.py}-${p.rel}${trimprefix(variant, "python")}",
  ]
}

# Test-only images used by tests/smoke.sh and tests/python.sh (not for publishing).
group "test" {
  targets = ["guard-test-24-04", "guard-test-26-04", "guard-testbin"]
}

target "guard-test-24-04" {
  inherits = ["core-24-04"]
  target   = "guard-test"
  tags     = ["${REGISTRY}/guard-test:24.04"]
}

target "guard-test-26-04" {
  inherits = ["core-26-04"]
  target   = "guard-test"
  tags     = ["${REGISTRY}/guard-test:26.04"]
}

# Static guard that reads a fake label from /guard-test/ (see Dockerfile). NEVER publish.
target "guard-testbin" {
  inherits = ["core-24-04"]
  target   = "guard-testbin"
  tags     = ["${REGISTRY}/guard-testbin:latest"]
}

# Multi-arch variants (push to a registry: docker buildx bake --push all-platforms)
group "all-platforms" {
  targets = ["core-all-platforms", "python-all-platforms"]
}

target "core-all-platforms" {
  name      = "${variant}-${replace(rel, ".", "-")}-multiarch"
  inherits  = ["_core"]
  matrix    = { rel = ["24.04", "26.04"], variant = ["core", "core-selinux", "core-apparmor"] }
  target    = variant
  args      = { UBUNTU_RELEASE = rel }
  platforms = ["linux/amd64", "linux/arm64"]
  tags      = ["${REGISTRY}/ubuntu-core:${rel}${trimprefix(variant, "core")}"]
}

target "python-all-platforms" {
  name      = "${variant}-${replace(p.rel, ".", "-")}-multiarch"
  inherits  = ["_core"]
  matrix    = { p = PYTHONS, variant = ["python", "python-selinux", "python-apparmor"] }
  target    = variant
  args      = { UBUNTU_RELEASE = p.rel, PYTHON_VERSION = p.py }
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${REGISTRY}/ubuntu-python:${p.rel}${trimprefix(variant, "python")}",
    "${REGISTRY}/ubuntu-python:${p.py}-${p.rel}${trimprefix(variant, "python")}",
  ]
}
