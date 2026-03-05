# Gleisner -- Sandbox Debugging Guide

**Document version:** 0.1.0
**Date:** 2026-03-04
**Status:** Living document

---

## Overview

When something goes wrong inside the gleisner sandbox, the standard tools
(`gleisner wrap`, `gleisner-tui --sandbox`) add layers of abstraction that
make it hard to isolate variables. This guide documents a direct debugging
pattern using `gleisner-sandbox-init` with hand-crafted spec files.

**Core principle:** Binary-search the parameter space. Write a minimal spec,
confirm it works, then add parameters one at a time until the failure appears.

---

## 1. The Direct sandbox-init Pattern

### Why not `gleisner wrap`?

`gleisner wrap` always wraps the inner command inside `claude`:

```
gleisner wrap --profile developer -- -p "hello"
# Actually runs: claude --output-format stream-json -p "hello"
```

You cannot run arbitrary diagnostic commands (e.g., `env`, `curl`,
`node -e "..."`) through `gleisner wrap`. For debugging, bypass it entirely.

### Running sandbox-init directly

`gleisner-sandbox-init` reads a JSON `SandboxSpec` from a file and executes
the sandbox setup + inner command directly:

```bash
./target/release/gleisner-sandbox-init /tmp/diag-spec.json
```

This gives you full control over what runs inside the sandbox.

---

## 2. Writing a SandboxSpec

A minimal spec that runs `sh -c` inside the sandbox:

```json
{
  "filesystem": {
    "readonly_bind": [
      "/usr", "/lib", "/lib64", "/bin", "/sbin",
      "/etc", "/run", "/var"
    ],
    "readwrite_bind": [],
    "deny_paths": [],
    "tmpfs": ["/tmp"]
  },
  "network": {
    "default": "allow",
    "allow_domains": [],
    "allow_ports": []
  },
  "process": {
    "max_pids": 0,
    "allow_fork": true,
    "clock_offset_secs": 0,
    "hostname": "gleisner-diag"
  },
  "project_dir": "/datar/workspace/your-project",
  "extra_rw_paths": [],
  "work_dir": "/datar/workspace/your-project",
  "inner_command": ["sh", "-c", "echo sandbox works && id && env"],
  "enable_landlock": false,
  "use_external_netns": false,
  "uid": 1000,
  "gid": 100
}
```

**Important fields:**

| Field | Notes |
|-------|-------|
| `uid` / `gid` | Must match your actual user. On Gentoo, default group is `users` (GID 100), not a per-user group (GID 1000). Check with `id`. |
| `inner_command` | The command to exec. Use `["sh", "-c", "..."]` for shell features. |
| `enable_landlock` | Set `false` to eliminate Landlock as a variable. |
| `use_external_netns` | Set `true` only when entering a pre-created namespace via nsenter. |
| `resource_limits` | Omit entirely to skip cgroup + rlimit setup. Add when testing resource constraints. |
| `extra_env` | Key-value pairs added to the environment after `env_clear()`. |

### Adding $HOME for Claude Code

Claude Code needs `~/.claude` (credentials, settings) and the home directory.
A spec that can run Claude:

```json
{
  "filesystem": {
    "readonly_bind": [
      "/usr", "/lib", "/lib64", "/bin", "/sbin",
      "/etc", "/run", "/var",
      "/home/you"
    ],
    "readwrite_bind": [
      "/home/you/.claude"
    ],
    "deny_paths": [],
    "tmpfs": ["/tmp"]
  },
  "network": {
    "default": "allow",
    "allow_domains": [],
    "allow_ports": []
  },
  "process": {
    "max_pids": 0,
    "allow_fork": true,
    "clock_offset_secs": 0,
    "hostname": "gleisner-diag"
  },
  "project_dir": "/datar/workspace/your-project",
  "extra_rw_paths": [],
  "work_dir": "/datar/workspace/your-project",
  "inner_command": ["claude", "--output-format", "stream-json", "-p", "Say: sandbox works"],
  "enable_landlock": false,
  "use_external_netns": false,
  "uid": 1000,
  "gid": 100
}
```

---

## 3. Binary Search Methodology

When the full sandbox fails but you don't know why:

### Step 1: Establish a baseline

Run with a minimal spec (no rlimits, no Landlock, host networking).
If this fails, the issue is in namespace/mount setup.

```bash
# Minimal — just namespaces + mounts
./target/release/gleisner-sandbox-init /tmp/diag-minimal.json
```

### Step 2: Add one variable at a time

Create copies of the working spec, each adding one feature:

```bash
# Test Landlock
cp /tmp/diag-minimal.json /tmp/diag-landlock.json
# Edit: set "enable_landlock": true, add appropriate rules

# Test resource limits
cp /tmp/diag-minimal.json /tmp/diag-rlimits.json
# Edit: add "resource_limits": { ... }

# Test network namespace
cp /tmp/diag-minimal.json /tmp/diag-netns.json
# Edit: set "network": { "default": "deny", ... }
```

### Step 3: When a variable fails, subdivide

Example from a real debugging session — resource limits caused a hang:

```bash
# All rlimits → hangs
# Test each individually:

# RLIMIT_NPROC only
"resource_limits": { "max_pids": 1024, "max_memory_mb": 0, ... }
# ✅ Works

# RLIMIT_NOFILE only
"resource_limits": { "max_file_descriptors": 4096, "max_memory_mb": 0, ... }
# ✅ Works

# RLIMIT_AS only (via max_memory_mb)
"resource_limits": { "max_memory_mb": 16384, "max_pids": 0, ... }
# ❌ Hangs — root cause found
```

This identified `RLIMIT_AS` as the culprit in under 90 seconds.

---

## 4. Common Diagnostic Commands

### Environment and credentials

```json
"inner_command": ["sh", "-c",
  "echo '=== ENV ===' && env | sort && echo '=== CREDS ===' && cat ~/.claude/.credentials.json 2>/dev/null | head -1 && echo '=== CERT ===' && ls -la /etc/ssl/certs/ | head -5"
]
```

### Network connectivity

```json
"inner_command": ["node", "-e",
  "const https = require('https'); https.get('https://api.anthropic.com/', r => { console.log('status:', r.statusCode); r.on('data', d => process.stdout.write(d)); r.on('end', () => process.exit(0)); }).on('error', e => { console.error('error:', e.message); process.exit(1); });"
]
```

### DNS resolution

```json
"inner_command": ["node", "-e",
  "require('dns').resolve4('api.anthropic.com', (err, addrs) => { console.log(err || addrs); });"
]
```

### Claude Code with debug output

```json
"inner_command": ["sh", "-c",
  "claude --output-format stream-json -p 'Say: hello' 2>/datar/workspace/your-project/claude-stderr.log; echo EXIT=$?"
],
"extra_env": [["NODE_DEBUG", "net,tls,http"]]
```

**Note:** Redirect output to the project directory, not `/tmp`. The sandbox
mounts `/tmp` as a fresh tmpfs, so files written there are lost when the
sandbox exits.

---

## 5. Inspecting What `gleisner wrap` Would Generate

To see the actual spec that `gleisner wrap` produces, look at the
`build_spec()` method in `sandbox.rs`. You can also add temporary logging:

```rust
// In DirectSandbox::start(), after serializing the spec:
eprintln!("SPEC: {}", serde_json::to_string_pretty(&spec).unwrap());
```

Or capture it from a debug build:

```bash
RUST_LOG=gleisner_polis=debug gleisner wrap --profile developer -- -p "test" 2>&1 | grep -i spec
```

---

## 6. Known Gotchas

### RLIMIT_AS breaks Node.js/V8

Node.js/V8 on 64-bit systems reserves far more virtual address space than
physical memory (for GC, JIT compilation). Setting `RLIMIT_AS` causes V8's
memory allocator to fail silently — Claude Code hangs with
`duration_api_ms: 0`. Use cgroup memory limits instead.

**Status:** Fixed. `RLIMIT_AS` is no longer set by gleisner.

### GID on Gentoo

Gentoo's default user group is `users` (GID 100), not a per-user group
(GID 1000). Spec files must use the correct GID. Check with `id -g`.

### IPv6 silent drop

If the sandbox has a network namespace with pasta, IPv6 is configured on
tap0. `api.anthropic.com` has AAAA records, and Node.js tries IPv6 first.
Without an explicit REJECT rule, IPv6 packets are silently dropped, causing
a 60-second timeout before IPv4 fallback.

**Status:** Fixed. The firewall setup script now adds an IPv6 REJECT rule.

### /tmp is sandbox-internal

The sandbox mounts `/tmp` as a fresh tmpfs. Files written to `/tmp` inside
the sandbox are lost on exit. Redirect diagnostic output to the project
directory (which is bind-mounted read-write).

### Claude Code stderr

As of Claude Code 2.1.63+, `--output-format stream-json` writes NDJSON
events to **stderr**, not stdout. When capturing output, check stderr.

### Mount ordering

The sandbox uses overlay-style mount ordering:
1. Phase 1: Read-only binds (including `$HOME`)
2. Phase 2: Read-write binds (e.g., `~/.claude` on top of `$HOME`)
3. Phase 3: Symlinks (`/dev/ptmx` → `pts/ptmx`)
4. Phase 4: Deny mounts + tmpfs

Subdirectory bind mounts in Phase 2 correctly override parent mounts
from Phase 1. This is standard Linux behavior.

---

## 7. Seccomp-BPF Debugging

### Learning mode: discover required syscalls

If a sandboxed command fails under seccomp and you don't know which syscall was blocked, switch to learning mode:

1. Edit the profile's `[process.seccomp]` section:

```toml
[process.seccomp]
preset = "nodejs"
default_action = "log"  # allow all, but log via kernel audit
```

2. Run your sandboxed session normally. Every filtered syscall is logged to the kernel audit subsystem (type 1326 / `SECCOMP`).

3. Read the audit log (requires root):

```bash
sudo grep SECCOMP /var/log/audit/audit.log | tail -20
# Example output:
# type=SECCOMP ... syscall=334 ... comm="node"
# type=SECCOMP ... syscall=345 ... comm="node"
```

4. Run `gleisner learn` to auto-generate a tightened custom profile:

```bash
gleisner learn --kernel-audit-log /var/log/audit/audit.log --base-profile developer
```

This parses the SECCOMP records, maps syscall numbers to names (e.g., 334 → `rseq`), and produces a `custom` seccomp preset with the exact allowlist observed during the session.

### Interpreting SECCOMP audit records

Audit records look like:

```
type=SECCOMP msg=audit(1709500000.123:456): auid=1000 uid=0 gid=0 ses=1 pid=12345 comm="node" exe="/usr/bin/node" sig=0 arch=c000003e syscall=334 compat=0 ip=0x7f... code=0x7ffc0000
```

Key fields:
- `syscall=NNN` — the syscall number (x86_64). Map to name via `ausyscall NNN` or the table in `seccomp.rs`
- `comm="..."` — the executable that attempted the call
- `code=0x7ffc0000` — `SECCOMP_RET_LOG` (allowed but logged)
- `sig=0` — no signal sent (vs. `sig=9` for SECCOMP_RET_KILL)

### Common missing syscalls

| Symptom | Missing syscall | Notes |
|---------|----------------|-------|
| DNS resolution fails (`EAI_AGAIN`) | `sendmmsg`, `recvmmsg` | glibc sends parallel A+AAAA queries |
| `rseq` warning on startup | `rseq` | glibc 2.35+ thread registration |
| Clone fails | `clone3` | Modern glibc prefers `clone3` over `clone` |
| Random number generation hangs | `getrandom` | V8 entropy source |

### SandboxSpec seccomp field

Add seccomp to a diagnostic spec:

```json
{
  "seccomp": {
    "preset": "nodejs",
    "default_action": "errno",
    "allow_syscalls": []
  }
}
```

Set `"default_action": "log"` to discover what's needed, then `"errno"` to enforce. For maximum strictness, use `"kill"` — the process dies on the first blocked syscall, making the failure unambiguous.
