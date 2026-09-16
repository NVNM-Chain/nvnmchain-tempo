variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

group "default" {
  targets = ["tempo", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
}

target "docker-metadata" {}

# Base image with all dependencies pre-compiled.
#
# `platforms` is intentionally left unset: the build workflow sets the target
# platform per architecture (`--set chef.platform=...`) so each variant is
# built natively. Leaving it unset also makes a bare `docker buildx bake`
# default to the host platform.
target "chef" {
  dockerfile = "Dockerfile.chef"
  context = "."
  args = {
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
  }
}

target "_common" {
  dockerfile = "Dockerfile"
  context = "."
  contexts = {
    chef = "target:chef"
  }
  args = {
    CHEF_IMAGE = "chef"
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
}

target "tempo" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo"
}

target "tempo-localnet" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-localnet"
}

target "tempo-sidecar" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-sidecar"
}

target "tempo-xtask" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-xtask"
}
