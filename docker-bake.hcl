variable "REGISTRY" {
  default = "minified"
}

variable "CHISEL_VERSION" {
  default = "v1.5.1"
}

group "default" {
  targets = [
    "core-24-04", "core-26-04",
    "core-selinux-24-04", "core-selinux-26-04",
    "core-apparmor-24-04", "core-apparmor-26-04",
  ]
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

# Test-only images used by tests/smoke.sh (not for publishing).
group "test" {
  targets = ["guard-test-24-04", "guard-test-26-04"]
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

# Multi-arch variants (push to a registry: docker buildx bake --push core-all-platforms)
target "core-all-platforms" {
  name      = "${variant}-${replace(rel, ".", "-")}-multiarch"
  inherits  = ["_core"]
  matrix    = { rel = ["24.04", "26.04"], variant = ["core", "core-selinux", "core-apparmor"] }
  target    = variant
  args      = { UBUNTU_RELEASE = rel }
  platforms = ["linux/amd64", "linux/arm64"]
  tags      = ["${REGISTRY}/ubuntu-core:${rel}${trimprefix(variant, "core")}"]
}
