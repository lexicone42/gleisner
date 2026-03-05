//! Seccomp-BPF syscall filtering.
//!
//! Compiles a seccomp profile into a BPF program and applies it to the
//! current thread. Uses `seccompiler` (Apache-2.0/BSD-3, pure Rust, from
//! the Firecracker/rust-vmm project) for BPF generation.
//!
//! # Preset: `nodejs`
//!
//! The `nodejs` preset is an allowlist tuned for Node.js / V8 (Claude Code's
//! runtime). It blocks dangerous syscalls (kernel modules, mount, ptrace, bpf,
//! `io_uring`, namespace manipulation) while allowing everything V8's JIT
//! compiler and Node.js networking need.
//!
//! # Integration point
//!
//! Applied after Landlock (which needs `landlock_*` syscalls to set up) and
//! before `fork_and_exec`. The filter is inherited by the forked child and
//! persists across `execve`.

use std::collections::BTreeMap;

use gleisner_polis::profile::{SeccompAction, SeccompPolicy, SeccompPreset};
use seccompiler::{BpfProgram, SeccompAction as ScAction, SeccompFilter, TargetArch};

/// Compile a seccomp policy into a BPF program ready for `apply_filter`.
///
/// Returns `None` if the preset is `Disabled`.
pub(crate) fn compile(policy: &SeccompPolicy) -> Result<Option<BpfProgram>, String> {
    if policy.preset == SeccompPreset::Disabled {
        return Ok(None);
    }

    let syscalls = match policy.preset {
        SeccompPreset::Nodejs => nodejs_allowlist(),
        SeccompPreset::Disabled => unreachable!(),
    };

    let default_action = match policy.default_action {
        SeccompAction::Errno => ScAction::Errno(1), // EPERM
        SeccompAction::Log => ScAction::Log,
        SeccompAction::Kill => ScAction::KillProcess,
    };

    // Build rules: each allowed syscall maps to an empty Vec (unconditional match).
    // An empty rule vector means "always match this syscall" — triggering match_action.
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        syscalls.into_iter().map(|nr| (nr, vec![])).collect();

    let arch = target_arch();

    // mismatch_action = block (for syscalls NOT in the allowlist)
    // match_action = Allow (for syscalls IN the allowlist)
    let filter = SeccompFilter::new(
        rules,
        default_action,  // mismatch_action: unlisted syscalls get blocked
        ScAction::Allow, // match_action: listed syscalls get allowed
        arch,
    )
    .map_err(|e| format!("seccomp filter creation failed: {e}"))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("seccomp BPF compilation failed: {e}"))?;

    Ok(Some(bpf))
}

/// Apply a compiled BPF program to the current thread.
pub(crate) fn apply(bpf: &BpfProgram) -> Result<(), String> {
    seccompiler::apply_filter(bpf).map_err(|e| format!("seccomp apply_filter failed: {e}"))
}

/// Return the target architecture for the current build.
const fn target_arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::aarch64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("seccomp: unsupported architecture")
    }
}

// ── Node.js / V8 syscall allowlist ─────────────────────────────────
//
// This is a default-deny allowlist. Syscalls not listed here return
// EPERM (or the configured default action). The list is derived from:
//
// 1. Docker/Podman default seccomp profile (~300 allowed syscalls)
// 2. Node.js runtime requirements (V8 JIT needs mmap+mprotect with PROT_EXEC)
// 3. Practical testing of Claude Code under strace
//
// The list is intentionally generous for the first iteration. Once we have
// seccomp audit logging (SECCOMP_RET_LOG), we can profile real sessions
// and tighten it.
//
// Syscall numbers are from nix::libc::SYS_* which are architecture-specific.

/// Syscalls allowed for Node.js / V8 workloads.
fn nodejs_allowlist() -> Vec<i64> {
    use nix::libc::{
        SYS_accept, SYS_accept4, SYS_access, SYS_arch_prctl, SYS_bind, SYS_brk, SYS_chdir,
        SYS_chmod, SYS_chown, SYS_clock_getres, SYS_clock_gettime, SYS_clock_nanosleep, SYS_clone,
        SYS_clone3, SYS_close, SYS_close_range, SYS_connect, SYS_copy_file_range, SYS_dup,
        SYS_dup2, SYS_dup3, SYS_epoll_create, SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_pwait,
        SYS_epoll_pwait2, SYS_epoll_wait, SYS_eventfd, SYS_eventfd2, SYS_execve, SYS_execveat,
        SYS_exit, SYS_exit_group, SYS_faccessat, SYS_faccessat2, SYS_fadvise64, SYS_fallocate,
        SYS_fchdir, SYS_fchmod, SYS_fchmodat, SYS_fchown, SYS_fchownat, SYS_fcntl, SYS_fdatasync,
        SYS_flock, SYS_fork, SYS_fstat, SYS_fstatfs, SYS_fsync, SYS_ftruncate, SYS_futex,
        SYS_futimesat, SYS_get_robust_list, SYS_getcwd, SYS_getdents, SYS_getdents64, SYS_getegid,
        SYS_geteuid, SYS_getgid, SYS_getgroups, SYS_getpeername, SYS_getpgid, SYS_getpgrp,
        SYS_getpid, SYS_getppid, SYS_getrandom, SYS_getresgid, SYS_getresuid, SYS_getrlimit,
        SYS_getrusage, SYS_getsockname, SYS_getsockopt, SYS_gettid, SYS_gettimeofday, SYS_getuid,
        SYS_inotify_add_watch, SYS_inotify_init, SYS_inotify_init1, SYS_inotify_rm_watch,
        SYS_ioctl, SYS_kill, SYS_lchown, SYS_link, SYS_linkat, SYS_listen, SYS_lseek, SYS_lstat,
        SYS_madvise, SYS_membarrier, SYS_mincore, SYS_mkdir, SYS_mkdirat, SYS_mlock, SYS_mlock2,
        SYS_mlockall, SYS_mmap, SYS_mprotect, SYS_mremap, SYS_msync, SYS_munlock, SYS_munlockall,
        SYS_munmap, SYS_nanosleep, SYS_newfstatat, SYS_open, SYS_openat, SYS_pipe, SYS_pipe2,
        SYS_poll, SYS_ppoll, SYS_prctl, SYS_pread64, SYS_prlimit64, SYS_pselect6, SYS_pwrite64,
        SYS_read, SYS_readlink, SYS_readlinkat, SYS_readv, SYS_recvfrom, SYS_recvmmsg, SYS_recvmsg,
        SYS_rename, SYS_renameat, SYS_renameat2, SYS_rmdir, SYS_rseq, SYS_rt_sigaction,
        SYS_rt_sigpending, SYS_rt_sigprocmask, SYS_rt_sigqueueinfo, SYS_rt_sigreturn,
        SYS_rt_sigsuspend, SYS_rt_sigtimedwait, SYS_rt_tgsigqueueinfo, SYS_sched_get_priority_max,
        SYS_sched_get_priority_min, SYS_sched_getaffinity, SYS_sched_getparam,
        SYS_sched_getscheduler, SYS_sched_setaffinity, SYS_sched_setscheduler, SYS_sched_yield,
        SYS_seccomp, SYS_select, SYS_sendfile, SYS_sendmmsg, SYS_sendmsg, SYS_sendto,
        SYS_set_robust_list, SYS_set_tid_address, SYS_setpgid, SYS_setrlimit, SYS_setsid,
        SYS_setsockopt, SYS_shutdown, SYS_sigaltstack, SYS_signalfd, SYS_signalfd4, SYS_socket,
        SYS_socketpair, SYS_stat, SYS_statfs, SYS_statx, SYS_symlink, SYS_symlinkat, SYS_sysinfo,
        SYS_tgkill, SYS_timer_create, SYS_timer_delete, SYS_timer_getoverrun, SYS_timer_gettime,
        SYS_timer_settime, SYS_timerfd_create, SYS_timerfd_gettime, SYS_timerfd_settime, SYS_tkill,
        SYS_truncate, SYS_umask, SYS_uname, SYS_unlink, SYS_unlinkat, SYS_utimensat, SYS_vfork,
        SYS_wait4, SYS_waitid, SYS_write, SYS_writev,
    };

    vec![
        // ── File I/O ──────────────────────────────────────────────
        SYS_read,
        SYS_write,
        SYS_open,
        SYS_close,
        SYS_stat,
        SYS_fstat,
        SYS_lstat,
        SYS_lseek,
        SYS_pread64,
        SYS_pwrite64,
        SYS_readv,
        SYS_writev,
        SYS_access,
        SYS_openat,
        SYS_readlinkat,
        SYS_faccessat,
        SYS_faccessat2,
        SYS_newfstatat,
        SYS_getdents64,
        SYS_getcwd,
        SYS_readlink,
        SYS_fcntl,
        SYS_flock,
        SYS_ioctl,
        SYS_dup,
        SYS_dup2,
        SYS_dup3,
        SYS_pipe,
        SYS_pipe2,
        SYS_truncate,
        SYS_ftruncate,
        SYS_fallocate,
        SYS_fsync,
        SYS_fdatasync,
        SYS_fadvise64,
        SYS_statfs,
        SYS_fstatfs,
        SYS_statx,
        SYS_copy_file_range,
        // ── File manipulation ─────────────────────────────────────
        SYS_rename,
        SYS_renameat,
        SYS_renameat2,
        SYS_mkdir,
        SYS_mkdirat,
        SYS_rmdir,
        SYS_unlink,
        SYS_unlinkat,
        SYS_symlink,
        SYS_symlinkat,
        SYS_link,
        SYS_linkat,
        SYS_chmod,
        SYS_fchmod,
        SYS_fchmodat,
        SYS_chown,
        SYS_fchown,
        SYS_fchownat,
        SYS_lchown,
        SYS_utimensat,
        SYS_futimesat,
        // ── Memory management (V8 JIT requires PROT_EXEC) ────────
        SYS_mmap,
        SYS_mprotect,
        SYS_munmap,
        SYS_brk,
        SYS_mremap,
        SYS_madvise,
        SYS_membarrier,
        SYS_mincore,
        SYS_msync,
        SYS_mlock,
        SYS_mlock2,
        SYS_munlock,
        SYS_mlockall,
        SYS_munlockall,
        // ── Process / thread ──────────────────────────────────────
        SYS_clone,
        SYS_clone3,
        SYS_fork,
        SYS_vfork,
        SYS_execve,
        SYS_execveat,
        SYS_exit,
        SYS_exit_group,
        SYS_wait4,
        SYS_waitid,
        SYS_getpid,
        SYS_getppid,
        SYS_gettid,
        SYS_getpgid,
        SYS_getpgrp,
        SYS_setpgid,
        SYS_setsid,
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_getgroups,
        SYS_getresuid,
        SYS_getresgid,
        SYS_set_tid_address,
        SYS_set_robust_list,
        SYS_get_robust_list,
        SYS_futex,
        SYS_sched_yield,
        SYS_sched_getaffinity,
        SYS_sched_setaffinity,
        SYS_sched_getparam,
        SYS_sched_setscheduler,
        SYS_sched_getscheduler,
        SYS_sched_get_priority_max,
        SYS_sched_get_priority_min,
        SYS_prlimit64,
        SYS_getrlimit,
        SYS_setrlimit,
        SYS_getrusage,
        SYS_kill,
        SYS_tgkill,
        SYS_tkill,
        SYS_prctl,
        SYS_arch_prctl,
        SYS_rseq,
        // ── Signals ───────────────────────────────────────────────
        SYS_rt_sigaction,
        SYS_rt_sigprocmask,
        SYS_rt_sigreturn,
        SYS_rt_sigsuspend,
        SYS_rt_sigpending,
        SYS_rt_sigtimedwait,
        SYS_rt_sigqueueinfo,
        SYS_rt_tgsigqueueinfo,
        SYS_sigaltstack,
        // ── Networking ────────────────────────────────────────────
        SYS_socket,
        SYS_socketpair,
        SYS_connect,
        SYS_accept,
        SYS_accept4,
        SYS_bind,
        SYS_listen,
        SYS_sendto,
        SYS_recvfrom,
        SYS_sendmsg,
        SYS_recvmsg,
        SYS_sendmmsg,
        SYS_recvmmsg,
        SYS_shutdown,
        SYS_setsockopt,
        SYS_getsockopt,
        SYS_getsockname,
        SYS_getpeername,
        SYS_sendfile,
        // ── Event / polling ───────────────────────────────────────
        SYS_poll,
        SYS_ppoll,
        SYS_select,
        SYS_pselect6,
        SYS_epoll_create,
        SYS_epoll_create1,
        SYS_epoll_ctl,
        SYS_epoll_wait,
        SYS_epoll_pwait,
        SYS_epoll_pwait2,
        SYS_eventfd,
        SYS_eventfd2,
        SYS_signalfd,
        SYS_signalfd4,
        SYS_timerfd_create,
        SYS_timerfd_settime,
        SYS_timerfd_gettime,
        SYS_inotify_init,
        SYS_inotify_init1,
        SYS_inotify_add_watch,
        SYS_inotify_rm_watch,
        // ── Time ──────────────────────────────────────────────────
        SYS_clock_gettime,
        SYS_clock_getres,
        SYS_clock_nanosleep,
        SYS_nanosleep,
        SYS_gettimeofday,
        SYS_timer_create,
        SYS_timer_settime,
        SYS_timer_gettime,
        SYS_timer_getoverrun,
        SYS_timer_delete,
        // ── Random ────────────────────────────────────────────────
        SYS_getrandom,
        // ── System info ───────────────────────────────────────────
        SYS_uname,
        SYS_sysinfo,
        SYS_getdents,
        // ── Misc ──────────────────────────────────────────────────
        SYS_umask,
        SYS_chdir,
        SYS_fchdir,
        SYS_seccomp, // Allow nested seccomp (for defense-in-depth)
        SYS_close_range,
    ]
}

// ── Explicitly blocked (NOT in the allowlist above) ─────────────────
//
// These are the security-critical syscalls that the allowlist omits:
//
// Kernel modules:     init_module, delete_module, finit_module, create_module
// Namespace escape:   setns, unshare (sandbox-init already did its unshare)
// Mount operations:   mount, umount, umount2, pivot_root
// System time:        clock_settime, clock_adjtime, settimeofday, adjtimex
// Ptrace:             ptrace, process_vm_readv, process_vm_writev, kcmp
// BPF:                bpf (eBPF program loading)
// io_uring:           io_uring_setup, io_uring_register, io_uring_enter
// Dangerous:          reboot, kexec_load, kexec_file_load, swapon, swapoff
// Keyring:            add_key, keyctl, request_key
// Accounting:         acct, quotactl
// Perf:               perf_event_open
// Legacy:             uselib, vm86, get_kernel_syms, nfsservctl
// Privilege:          setuid, setgid, setreuid, setregid (no_new_privs blocks anyway)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_disabled_returns_none() {
        let policy = SeccompPolicy::default();
        assert_eq!(policy.preset, SeccompPreset::Disabled);
        let result = compile(&policy).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn compile_nodejs_returns_bpf() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Nodejs,
            default_action: SeccompAction::Errno,
        };
        let result = compile(&policy).unwrap();
        assert!(result.is_some());
        let bpf = result.unwrap();
        // BPF program should have a reasonable number of instructions
        // (arch check + syscall allowlist + default action)
        assert!(
            bpf.len() > 10,
            "BPF program too short: {} instructions",
            bpf.len()
        );
        assert!(
            bpf.len() < 4096,
            "BPF program exceeds kernel limit: {} instructions",
            bpf.len()
        );
    }

    #[test]
    fn compile_nodejs_log_mode() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Nodejs,
            default_action: SeccompAction::Log,
        };
        let result = compile(&policy).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn compile_nodejs_kill_mode() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Nodejs,
            default_action: SeccompAction::Kill,
        };
        let result = compile(&policy).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn nodejs_allowlist_has_essential_syscalls() {
        let syscalls = nodejs_allowlist();

        // V8 JIT requires mmap and mprotect
        assert!(syscalls.contains(&nix::libc::SYS_mmap), "missing mmap");
        assert!(
            syscalls.contains(&nix::libc::SYS_mprotect),
            "missing mprotect"
        );

        // Basic I/O
        assert!(syscalls.contains(&nix::libc::SYS_read), "missing read");
        assert!(syscalls.contains(&nix::libc::SYS_write), "missing write");
        assert!(syscalls.contains(&nix::libc::SYS_openat), "missing openat");

        // Networking
        assert!(syscalls.contains(&nix::libc::SYS_socket), "missing socket");
        assert!(
            syscalls.contains(&nix::libc::SYS_connect),
            "missing connect"
        );

        // Process
        assert!(syscalls.contains(&nix::libc::SYS_clone), "missing clone");
        assert!(syscalls.contains(&nix::libc::SYS_execve), "missing execve");
        assert!(
            syscalls.contains(&nix::libc::SYS_exit_group),
            "missing exit_group"
        );
    }

    #[test]
    fn nodejs_allowlist_blocks_dangerous_syscalls() {
        let syscalls = nodejs_allowlist();

        // Kernel modules
        assert!(
            !syscalls.contains(&nix::libc::SYS_init_module),
            "init_module should be blocked"
        );
        assert!(
            !syscalls.contains(&nix::libc::SYS_finit_module),
            "finit_module should be blocked"
        );

        // Namespace escape
        assert!(
            !syscalls.contains(&nix::libc::SYS_setns),
            "setns should be blocked"
        );
        assert!(
            !syscalls.contains(&nix::libc::SYS_unshare),
            "unshare should be blocked"
        );

        // Mount operations
        assert!(
            !syscalls.contains(&nix::libc::SYS_mount),
            "mount should be blocked"
        );
        assert!(
            !syscalls.contains(&nix::libc::SYS_umount2),
            "umount2 should be blocked"
        );
        assert!(
            !syscalls.contains(&nix::libc::SYS_pivot_root),
            "pivot_root should be blocked"
        );

        // Ptrace
        assert!(
            !syscalls.contains(&nix::libc::SYS_ptrace),
            "ptrace should be blocked"
        );

        // BPF
        assert!(
            !syscalls.contains(&nix::libc::SYS_bpf),
            "bpf should be blocked"
        );

        // io_uring
        assert!(
            !syscalls.contains(&nix::libc::SYS_io_uring_setup),
            "io_uring_setup should be blocked"
        );

        // Reboot
        assert!(
            !syscalls.contains(&nix::libc::SYS_reboot),
            "reboot should be blocked"
        );
    }

    #[test]
    fn nodejs_allowlist_no_duplicates() {
        let syscalls = nodejs_allowlist();
        let mut sorted = syscalls.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            syscalls.len(),
            sorted.len(),
            "allowlist contains duplicate syscall numbers"
        );
    }
}
