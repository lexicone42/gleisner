# Gleisner build declaration using Minimal Standard Types.
#
# This describes gleisner's build inputs, runtime dependencies,
# and environment attributes in the same format used by minimal.dev's
# package registry.

let { Attrs, BuildSpec, Local, Needs, OutputBin, Source, .. } = import "minimal.ncl" in

let version = "0.1.0" in
let repo = "https://github.com/lexicone42/gleisner" in

# Gleisner builds from source via cargo. In a real minimal environment,
# the rust toolchain and system deps would be BuildSpec references
# (like `import "../rust/build.ncl"`). Here we declare the source
# and note what the build needs.

{
  name = "gleisner",
  build_deps = [
    { file = "build.sh" } | Local,
    # Source from git — in practice this would be a tagged release tarball
    {
      url = "%{repo}/archive/refs/tags/v%{version}.tar.gz",
      sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
      extract = true,
      strip_prefix = "gleisner-%{version}",
    } | Source,
  ],

  # Runtime dependencies: the system tools gleisner shells out to.
  # In minimal's model these would be BuildSpec imports; we declare
  # them as comments + empty list for now since we don't have the
  # full transitive tree available locally.
  #
  # Actual runtime deps:
  #   pasta                  — user-namespace networking
  #   nftables (nft)         — firewall rules inside namespace
  #   nsenter                — entering namespaces for nft/pasta
  #   claude-code            — the inner process being sandboxed
  #   cosign (optional)      — Sigstore keyless signing
  runtime_deps = [],

  needs = {
    # gleisner itself doesn't need network at build time (cargo
    # fetch would, but in minimal's model deps are pre-fetched
    # as Source inputs). At runtime, the sandboxed process may
    # need network — but that's declared in the inner package's
    # Needs, not gleisner's own.
  } | Needs,

  cmd = "./build.sh",
  build_args = {
    include version,
  },

  outputs = {
    gleisner = { glob = "usr/bin/gleisner" } | OutputBin,
    gleisner_tui = { glob = "usr/bin/gleisner-tui" } | OutputBin,
    gleisner_sandbox_init = { glob = "usr/bin/gleisner-sandbox-init" } | OutputBin,
  },

  attrs = {
    upstream_version = version,
    repology_project = "gleisner",
    source_provenance = {
      category = 'GithubRepo,
      owner = "lexicone42",
      repo = "gleisner",
    },

    # ── Runtime environment contract ──
    # These declare what gleisner needs from the host filesystem
    # when running inside a minimal environment.

    # Gleisner's own state: attestation bundles, audit logs, learned profiles
    env_dir_mappings = [
      { read_only = false, path = "~/.gleisner", class = 'State },
      # Gleisner needs read access to the project's .gleisner/ dir
      # for attestation chaining (finding the previous bundle)
      { read_only = false, path = ".gleisner", class = 'State },
    ],

    # No credential files of its own — gleisner delegates credential
    # access to the inner sandboxed process (e.g., claude-code needs
    # ~/.claude.json). Gleisner's signing uses either:
    # - Local ECDSA key (~/.gleisner/signing-key.pem, covered by env_dir above)
    # - Sigstore keyless (OIDC browser flow, no persistent credential file)
    env_file_mappings = [],
  } | Attrs,
} | BuildSpec
