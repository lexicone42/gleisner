# Agent Coordination

How gleisner manages multi-agent workflows: declaring capabilities,
delegating work, verifying scoping, and tightening permissions over time.

## Overview

Gleisner's agent coordination solves a specific problem: when an AI agent
delegates work to another AI agent, how do you ensure the inner agent
has exactly the permissions it needs and nothing more?

The system has three layers:

1. **Task declaration** — describe what the agent needs, not how the sandbox works
2. **Delegation protocol** — structured handoff from outer agent to inner agent
3. **Feedback loop** — observe what was actually used, tighten the next run

Each layer builds on the one below it. The kernel (Landlock, seccomp,
namespaces) enforces the actual boundaries regardless of what any agent
believes about its permissions.

## Layer 1: Task Declaration

The `TaskSandbox` API encodes the principle of least privilege as the
default. You declare capabilities — the sandbox derives its own
configuration.

```rust
use gleisner_container::task::TaskSandbox;

let task = TaskSandbox::new("/workspace/myproject")
    .needs_tools(["cargo", "git"])
    .needs_network(["crates.io"])
    .needs_read(["/data/reference-docs"])
    .build()?;
```

### What `build()` derives

When you call `build()`, the task declaration is translated into
concrete sandbox infrastructure:

| Declaration | Infrastructure |
|---|---|
| `needs_tools(["cargo"])` | bind-mount `/usr/bin/cargo` (ro), auto-discover cargo home, add Baseline seccomp preset |
| `needs_tools(["node"])` | bind-mount node binary (ro), select Nodejs seccomp preset (V8-aware syscall allowlist) |
| `needs_tools(["claude"])` | bind-mount claude binary (ro), auto-mount `~/.claude/` (ro), select Nodejs seccomp preset |
| `needs_network(["crates.io"])` | enable net namespace, start pasta, configure nftables to allow only `crates.io` |
| `needs_read(["/data/ref"])` | bind-mount `/data/ref` as read-only inside the sandbox |
| `needs_write(["/output"])` | bind-mount `/output` as read-write |
| `state_key("dev")` | create `.gleisner/state/dev/` (rw, persists across runs) |
| `needs_packages(pkgs)` | bind-mount each package from the binary cache (ro) |

The caller never touches Landlock rules, mount flags, or namespace
configuration. The sandbox figures it out.

### Tool auto-discovery

Declaring a tool triggers cascading effects:

- **`claude`** → adds `node` (Claude Code is Node.js), mounts `~/.claude/`,
  mounts home directory (for `.gitconfig`, `.npmrc`, etc.)
- **`npm` / `npx`** → auto-adds `registry.npmjs.org` to allowed domains,
  mounts `~/.npm/` read-write
- **`pip` / `uv` / `uvx`** → auto-adds `pypi.org` and `files.pythonhosted.org`
- **`cargo`** → mounts cargo home (ro)
- **`git`** → mounts home directory (for `.gitconfig`)

This means a simple declaration like `.needs_tools(["claude"])` generates
a sandbox with 15+ bind mounts, a Nodejs seccomp preset, and home
directory access — all derived, not specified.

### Tool name validation

Tool names are validated to prevent injection attacks. The following
characters are rejected: `/`, `\`, `;`, `'`, `` ` ``, and null bytes.

## Layer 2: Delegation Protocol

The `Delegation` type provides a structured protocol for one Claude
instance to launch another inside a sandbox.

```rust
use gleisner_container::delegate::Delegation;
use std::time::Duration;

let result = Delegation::to("/workspace/project")
    .task("Fix the JWT expiry validation bug in src/auth.rs")
    .context("The bug is on line 42 — expiry check is skipped when iat is present")
    .context("Related issue: https://github.com/org/repo/issues/123")
    .allow_tools(["cargo", "git"])
    .allow_network(["api.anthropic.com"])
    .forward_api_key()
    .timeout(Duration::from_secs(300))
    .build()?
    .execute()?;

if result.success() {
    println!("Inner Claude response: {}", result.response());
}
```

### Delegation flow

```
Outer Claude
  │
  ├── 1. Delegation::to("/project")
  │       Describe task, context, tools, domains, timeout
  │
  ├── 2. .build()
  │       ├── Writes .gleisner/sandbox-context.md to project dir
  │       ├── Translates task → Sandbox (mounts, Landlock, seccomp, etc.)
  │       └── Returns PreparedDelegation
  │
  ├── 3. .execute()
  │       ├── Launches: claude --print "<task description>" [args...]
  │       ├── Inner Claude runs in sandboxed namespace
  │       ├── Kernel enforces Landlock + seccomp + namespace boundaries
  │       └── Returns DelegationResult { output, capabilities, prompt }
  │
  └── 4. Inspect result
          ├── result.success() — did it exit 0?
          ├── result.response() — stdout (Claude's answer)
          ├── result.errors() — stderr (warnings, diagnostics)
          ├── result.capabilities — what was granted (for audit)
          └── result.injected_prompt — the system prompt (for review)
```

### Security design decisions

**API key is NOT forwarded by default.** Call `.forward_api_key()`
explicitly. Rationale: a compromised inner Claude could exfiltrate
the key via allowed network domains. Requiring opt-in forces the
delegator to consider this risk.

**System prompt describes allowed capabilities only.** The inner
Claude sees "you can access crates.io" but NOT "Landlock is
blocking /etc." This is intentional:

- An honest agent benefits: it knows what will work, avoids wasted operations
- An adversarial agent gains nothing: no implementation details to probe
- The kernel enforces regardless: the prompt is informational, not authoritative

**Context file is inside the sandbox.** The `.gleisner/sandbox-context.md`
file is placed in the project directory (which is read-write). The inner
Claude can read it to understand its boundaries. It could also modify or
delete it — that doesn't affect enforcement.

**`--print` mode for non-interactive execution.** The inner Claude runs
in one-shot mode. It receives the task, produces output, and exits. No
interactive terminal is shared between outer and inner agents.

### What the inner Claude sees

The system prompt fragment generated by `system_prompt_fragment()`:

```
You are running in a sandboxed environment with restricted permissions.

Filesystem access:
  - Read/write: /workspace/project
  - Read-only: home directory (for tool configuration)
  - Other paths are not accessible

Network access:
  - Allowed: api.anthropic.com
  - All other domains are blocked

Available tools: cargo, git, claude

Operations outside these boundaries will fail silently or with permission errors.
Work within the project directory and use only the declared network endpoints.
```

## Layer 3: The Feedback Loop

Three methods create a closed loop that tightens permissions over time.

### `explain()` — Audit before running

Before launching, review what the sandbox will grant:

```rust
let task = TaskSandbox::new("/workspace")
    .needs_tools(["cargo", "git", "npm"])
    .needs_network(["crates.io", "registry.npmjs.org"]);

println!("{}", task.explain());
```

Output:

```
Sandbox capabilities (8 grants):

  [filesystem]
    /workspace (read-write) — project directory
    /home/user (read-only) — tool config (git, npm, cargo)

  [network]
    crates.io — declared dependency
    registry.npmjs.org — auto-added for npm

  [tools]
    cargo — declared tool
    git — declared tool
    npm — declared tool

  [isolation]
    Landlock: enabled — filesystem access control
```

The verbose variant (`explain_verbose()`) additionally shows
infrastructure grants: rootfs bind-mounts, /proc, /dev, /tmp.

### `narrow(observed)` — Tighten after running

After a sandbox run completes, compare what was declared against what
was actually used:

```rust
use gleisner_container::task::ObservedCapabilities;

// Collected from audit log or Landlock events:
let mut observed = ObservedCapabilities::default();
observed.executed_tools.insert("cargo".to_owned());
observed.contacted_domains.insert("crates.io".to_owned());
// npm was never used, git was never used, registry.npmjs.org was never contacted

let report = task.narrow(&observed);
println!("{}", report.summary);
// "Unused capabilities: tools: [git, npm], domains: [registry.npmjs.org]"

// The report includes a tighter config for next time:
let tighter_task = report.suggested_config;
// This sandbox only grants cargo + crates.io
```

The narrowing loop:

```
Run 1: Declare [cargo, git, npm] + [crates.io, registry.npmjs.org]
        Observe: only cargo + crates.io used
        narrow() → suggested: [cargo] + [crates.io]

Run 2: Declare [cargo] + [crates.io]
        Observe: cargo + crates.io used
        narrow() → "All declared capabilities were used — configuration is already minimal."
```

### `merge(other)` — Combine multi-agent needs

When multiple agents need to share a sandbox (or when an orchestrator
needs to build a sandbox that satisfies multiple sub-tasks):

```rust
let frontend = TaskSandbox::new("/workspace")
    .needs_tools(["node", "npm"])
    .needs_network(["registry.npmjs.org"]);

let backend = TaskSandbox::new("/workspace")
    .needs_tools(["cargo"])
    .needs_network(["crates.io"]);

let combined = frontend.merge(backend);
// Result: tools=[node, npm, cargo], domains=[registry.npmjs.org, crates.io]
```

Merge takes the union of all capabilities. If one task has
`needs_internet` (unrestricted) and the other has domain restrictions,
the merge escalates to unrestricted — and logs a warning, because this
is a security-significant decision.

## Verification

### Delegation scoping (`is_scoped_within`)

Prove that an inner sandbox is strictly more restrictive than the outer:

```rust
let outer = TaskSandbox::new("/workspace")
    .needs_tools(["claude", "cargo", "git"])
    .needs_network(["api.anthropic.com", "crates.io"]);

let inner = TaskSandbox::new("/workspace")
    .needs_tools(["cargo"])
    .needs_network(["crates.io"]);

let result = inner.is_scoped_within(&outer);
assert!(result.is_scoped);  // inner ⊆ outer
assert!(result.excess_capabilities.is_empty());
```

If the inner sandbox exceeds the outer:

```rust
let inner = TaskSandbox::new("/workspace")
    .needs_tools(["cargo", "docker"])  // docker not in outer
    .needs_network(["crates.io"]);

let result = inner.is_scoped_within(&outer);
assert!(!result.is_scoped);
// result.excess_capabilities: ["tool 'docker' not in outer scope"]
```

This check runs before execution. An orchestrating Claude can prove: "the
inner Claude I'm about to launch can't do anything I can't do."

### Z3 policy verification (feature: `lattice`)

For formal proofs, the `verify_against_policy()` method encodes sandbox
configurations as quantifier-free linear integer arithmetic (QF_LIA)
formulas and checks subsumption:

```rust
use gleisner_lacerta::policy::BuiltinPolicy;

let policy = BuiltinPolicy {
    require_sandbox: Some(true),
    max_denial_count: Some(0),
    ..Default::default()
};

let sandbox = task.build()?;
let result = sandbox.verify_against_policy(&policy);
assert!(result.satisfies);
```

This is a machine-checked proof — not a heuristic. Z3 either confirms
the configuration satisfies the policy or produces a counterexample.

## Concurrent Execution

The `SandboxPool` manages multiple sandboxes running simultaneously:

```rust
use gleisner_container::pool::SandboxPool;
use std::time::Duration;

let pool = SandboxPool::new(4)  // max 4 concurrent sandboxes
    .task_timeout(Duration::from_secs(600));

pool.submit("build-gcc", TaskSandbox::new("/workspace"), "make", &["-j4"]);
pool.submit("build-zlib", TaskSandbox::new("/workspace"), "make", &[]);
pool.submit("test-suite", TaskSandbox::new("/workspace"), "cargo", &["test"]);

let results = pool.run_all();
println!("{} succeeded, {} failed", results.succeeded, results.failed);

for (name, result) in &results.results {
    match result {
        Ok(output) => println!("{name}: exit {}", output.exit_code()),
        Err(e) => println!("{name}: error: {e} — {}", e.suggestion()),
    }
}
```

Each task gets its own isolated sandbox — no shared state between
concurrent tasks (unless they share a `state_key`). Thread panics in
one task don't crash the pool.

## minimal.toml Integration

The `MinimalConfig` parser translates minimal.dev's declarative task
format into `TaskSandbox` configurations:

```rust
use gleisner_container::minimal_toml::MinimalConfig;

let config = MinimalConfig::from_file("minimal.toml")?;
let sandbox = config.task_sandbox("build", "/workspace")?;

// Equivalent to manually calling:
//   TaskSandbox::new("/workspace")
//     .needs_tools([...from harness...])
//     .needs_network([...from task...])
//     .needs_read([...from patches...])
//     .state_key("dev")  // from [defaults]
```

This means gleisner can sandbox any minimal.toml task without workflow
changes — the sandbox configuration is derived from the config the
developer already wrote.

## Attestation Integration

Every delegation produces attestable artifacts. The `BuildEnvironment`
(in `gleisner-introdus`) captures what tool ran, in what sandbox, with
what enforcement:

```rust
use gleisner_introdus::provenance::BuildEnvironment;

// For a Claude Code delegation:
let env = BuildEnvironment::claude_code(
    Some("2.1.81".into()),       // tool version
    Some("claude-sonnet-4-6".into()), // model
    claude_md_hash,
    api_base_url,
    "developer".into(),          // profile
).with_enforcement(
    "FullyEnforced",             // Landlock level
    "Nodejs",                    // seccomp preset
    vec!["user", "mount", "pid", "ipc", "uts", "time", "net"],
);

// For a generic build tool:
let env = BuildEnvironment::build_tool("cargo", Some("1.93.0".into()), "konishi".into());

// For a minimal.toml task:
let env = BuildEnvironment::from_minimal_task("bash", None, "developer".into(), true);
```

The attestation chain links delegations together: each inner Claude's
session attestation references the outer Claude's attestation via
`gleisner:chain`, forming an auditable lineage.

## Security Properties

### Defense in depth

The agent coordination system uses four independent enforcement layers:

1. **System prompt** (Layer 0) — tells the agent what it can do.
   Purely advisory. An adversarial agent can ignore it.

2. **Landlock V7** (Layer 1) — kernel-enforced filesystem and network
   access control. Cannot be bypassed from userspace.

3. **Seccomp-BPF** (Layer 2) — syscall filtering. Blocks dangerous
   syscalls even if the agent finds a way to execute arbitrary code.

4. **Namespaces** (Layer 3) — process, mount, network, IPC, UTS, and
   time isolation. The agent can't see or interact with the host system.

Layers 1-3 are enforced by the kernel. The system prompt (Layer 0)
exists to make the agent more *efficient*, not more *contained*.

### Capability monotonicity

- `merge()` can only add capabilities, never remove them (union)
- `narrow()` can only remove capabilities, never add them (intersection with observed)
- `is_scoped_within()` verifies inner ⊆ outer (subset)
- `verify_against_policy()` proves config ⊆ policy (formal subsumption)

These operations form a lattice where permissions only flow in predictable
directions.

### What the inner agent cannot do

Assuming a delegation with `.allow_tools(["cargo"]).allow_network(["crates.io"])`:

| Action | Blocked by | Error seen by agent |
|---|---|---|
| Read `/etc/shadow` | Landlock | `EACCES` (permission denied) |
| Write outside project dir | Landlock | `EACCES` |
| Connect to `evil.com` | nftables | `ENETUNREACH` or `ECONNREFUSED` |
| Run `docker` | Not mounted | `ENOENT` (not found) |
| Call `ptrace` | Seccomp | `EPERM` or `SIGSYS` |
| See host processes | PID namespace | Only sees own process tree |
| Read host clock | Time namespace | Sees isolated clock |
| Access host network | Net namespace | Only sees sandbox network |

## System Capability Detection

Before creating sandboxes, probe the system to understand what's available:

```rust
use gleisner_container::probe::SandboxCapabilities;

let caps = SandboxCapabilities::probe();

if !caps.can_sandbox() {
    eprintln!("Cannot sandbox: {:?}", caps.blockers);
    // e.g., "user namespaces not supported"
}

if !caps.full_security() {
    eprintln!("Degraded security: {:?}", caps.warnings);
    // e.g., "Landlock ABI 3 (V7 recommended for full audit support)"
}

println!("{}", caps.summary());
// kernel=6.19.8-gentoo, status=full security, landlock=V7, seccomp=yes, pasta=yes
```

This enables graceful degradation: run with reduced isolation on systems
without full kernel support, rather than failing entirely.
