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
        SeccompPreset::Custom => custom_allowlist(&policy.allow_syscalls)?,
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

/// Convert a list of syscall names to syscall numbers for a custom allowlist.
fn custom_allowlist(names: &[String]) -> Result<Vec<i64>, String> {
    let mut syscalls = Vec::with_capacity(names.len());
    let mut unknown = Vec::new();
    for name in names {
        if let Some(nr) = syscall_name_to_number(name) {
            syscalls.push(nr);
        } else {
            unknown.push(name.as_str());
        }
    }
    if !unknown.is_empty() {
        return Err(format!(
            "unknown syscall names in custom allowlist: {}",
            unknown.join(", ")
        ));
    }
    Ok(syscalls)
}

/// Map a syscall name to its number (`x86_64`).
///
/// Names match the kernel convention (lowercase, no `SYS_` prefix):
/// `"read"`, `"write"`, `"mmap"`, etc.
pub(crate) fn syscall_name_to_number(name: &str) -> Option<i64> {
    SYSCALL_TABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
}

/// Map a syscall number to its name (`x86_64`).
///
/// Returns `None` for unrecognized numbers.
#[allow(dead_code)] // Used by CLI via the name_resolver pattern
pub(crate) fn syscall_number_to_name(nr: i64) -> Option<&'static str> {
    SYSCALL_TABLE
        .iter()
        .find(|(_, n)| *n == nr)
        .map(|(name, _)| *name)
}

/// (name, number) pairs for `x86_64` syscalls.
///
/// This table covers the syscalls in the nodejs allowlist plus common ones
/// that may appear in seccomp audit logs. It does NOT need to be exhaustive —
/// unknown numbers get a fallback `"syscall_NNN"` name in the learner.
#[cfg(target_arch = "x86_64")]
static SYSCALL_TABLE: &[(&str, i64)] = {
    use nix::libc::{
        SYS_accept, SYS_accept4, SYS_access, SYS_acct, SYS_add_key, SYS_adjtimex, SYS_arch_prctl,
        SYS_bind, SYS_bpf, SYS_brk, SYS_chdir, SYS_chmod, SYS_chown, SYS_clock_getres,
        SYS_clock_gettime, SYS_clock_nanosleep, SYS_clock_settime, SYS_clone, SYS_clone3,
        SYS_close, SYS_close_range, SYS_connect, SYS_copy_file_range, SYS_delete_module, SYS_dup,
        SYS_dup2, SYS_dup3, SYS_epoll_create, SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_pwait,
        SYS_epoll_pwait2, SYS_epoll_wait, SYS_eventfd, SYS_eventfd2, SYS_execve, SYS_execveat,
        SYS_exit, SYS_exit_group, SYS_faccessat, SYS_faccessat2, SYS_fadvise64, SYS_fallocate,
        SYS_fchdir, SYS_fchmod, SYS_fchmodat, SYS_fchown, SYS_fchownat, SYS_fcntl, SYS_fdatasync,
        SYS_finit_module, SYS_flock, SYS_fork, SYS_fstat, SYS_fstatfs, SYS_fsync, SYS_ftruncate,
        SYS_futex, SYS_futimesat, SYS_get_robust_list, SYS_getcwd, SYS_getdents, SYS_getdents64,
        SYS_getegid, SYS_geteuid, SYS_getgid, SYS_getgroups, SYS_getpeername, SYS_getpgid,
        SYS_getpgrp, SYS_getpid, SYS_getppid, SYS_getrandom, SYS_getresgid, SYS_getresuid,
        SYS_getrlimit, SYS_getrusage, SYS_getsockname, SYS_getsockopt, SYS_gettid,
        SYS_gettimeofday, SYS_getuid, SYS_init_module, SYS_inotify_add_watch, SYS_inotify_init,
        SYS_inotify_init1, SYS_inotify_rm_watch, SYS_io_uring_enter, SYS_io_uring_register,
        SYS_io_uring_setup, SYS_ioctl, SYS_kexec_file_load, SYS_kexec_load, SYS_keyctl, SYS_kill,
        SYS_lchown, SYS_link, SYS_linkat, SYS_listen, SYS_lseek, SYS_lstat, SYS_madvise,
        SYS_membarrier, SYS_mincore, SYS_mkdir, SYS_mkdirat, SYS_mlock, SYS_mlock2, SYS_mlockall,
        SYS_mmap, SYS_mount, SYS_mprotect, SYS_mremap, SYS_msync, SYS_munlock, SYS_munlockall,
        SYS_munmap, SYS_nanosleep, SYS_newfstatat, SYS_open, SYS_openat, SYS_perf_event_open,
        SYS_pipe, SYS_pipe2, SYS_pivot_root, SYS_poll, SYS_ppoll, SYS_prctl, SYS_pread64,
        SYS_prlimit64, SYS_pselect6, SYS_ptrace, SYS_pwrite64, SYS_read, SYS_readlink,
        SYS_readlinkat, SYS_readv, SYS_reboot, SYS_recvfrom, SYS_recvmmsg, SYS_recvmsg, SYS_rename,
        SYS_renameat, SYS_renameat2, SYS_request_key, SYS_rmdir, SYS_rseq, SYS_rt_sigaction,
        SYS_rt_sigpending, SYS_rt_sigprocmask, SYS_rt_sigqueueinfo, SYS_rt_sigreturn,
        SYS_rt_sigsuspend, SYS_rt_sigtimedwait, SYS_rt_tgsigqueueinfo, SYS_sched_get_priority_max,
        SYS_sched_get_priority_min, SYS_sched_getaffinity, SYS_sched_getparam,
        SYS_sched_getscheduler, SYS_sched_setaffinity, SYS_sched_setscheduler, SYS_sched_yield,
        SYS_seccomp, SYS_select, SYS_sendfile, SYS_sendmmsg, SYS_sendmsg, SYS_sendto,
        SYS_set_robust_list, SYS_set_tid_address, SYS_setgid, SYS_setns, SYS_setpgid, SYS_setregid,
        SYS_setreuid, SYS_setrlimit, SYS_setsid, SYS_setsockopt, SYS_settimeofday, SYS_setuid,
        SYS_shutdown, SYS_sigaltstack, SYS_signalfd, SYS_signalfd4, SYS_socket, SYS_socketpair,
        SYS_stat, SYS_statfs, SYS_statx, SYS_swapoff, SYS_swapon, SYS_symlink, SYS_symlinkat,
        SYS_sysinfo, SYS_tgkill, SYS_timer_create, SYS_timer_delete, SYS_timer_getoverrun,
        SYS_timer_gettime, SYS_timer_settime, SYS_timerfd_create, SYS_timerfd_gettime,
        SYS_timerfd_settime, SYS_tkill, SYS_truncate, SYS_umask, SYS_umount2, SYS_uname,
        SYS_unlink, SYS_unlinkat, SYS_unshare, SYS_utimensat, SYS_vfork, SYS_wait4, SYS_waitid,
        SYS_write, SYS_writev,
    };
    &[
        // File I/O
        ("read", SYS_read),
        ("write", SYS_write),
        ("open", SYS_open),
        ("close", SYS_close),
        ("stat", SYS_stat),
        ("fstat", SYS_fstat),
        ("lstat", SYS_lstat),
        ("lseek", SYS_lseek),
        ("pread64", SYS_pread64),
        ("pwrite64", SYS_pwrite64),
        ("readv", SYS_readv),
        ("writev", SYS_writev),
        ("access", SYS_access),
        ("openat", SYS_openat),
        ("readlinkat", SYS_readlinkat),
        ("faccessat", SYS_faccessat),
        ("faccessat2", SYS_faccessat2),
        ("newfstatat", SYS_newfstatat),
        ("getdents64", SYS_getdents64),
        ("getcwd", SYS_getcwd),
        ("readlink", SYS_readlink),
        ("fcntl", SYS_fcntl),
        ("flock", SYS_flock),
        ("ioctl", SYS_ioctl),
        ("dup", SYS_dup),
        ("dup2", SYS_dup2),
        ("dup3", SYS_dup3),
        ("pipe", SYS_pipe),
        ("pipe2", SYS_pipe2),
        ("truncate", SYS_truncate),
        ("ftruncate", SYS_ftruncate),
        ("fallocate", SYS_fallocate),
        ("fsync", SYS_fsync),
        ("fdatasync", SYS_fdatasync),
        ("fadvise64", SYS_fadvise64),
        ("statfs", SYS_statfs),
        ("fstatfs", SYS_fstatfs),
        ("statx", SYS_statx),
        ("copy_file_range", SYS_copy_file_range),
        // File manipulation
        ("rename", SYS_rename),
        ("renameat", SYS_renameat),
        ("renameat2", SYS_renameat2),
        ("mkdir", SYS_mkdir),
        ("mkdirat", SYS_mkdirat),
        ("rmdir", SYS_rmdir),
        ("unlink", SYS_unlink),
        ("unlinkat", SYS_unlinkat),
        ("symlink", SYS_symlink),
        ("symlinkat", SYS_symlinkat),
        ("link", SYS_link),
        ("linkat", SYS_linkat),
        ("chmod", SYS_chmod),
        ("fchmod", SYS_fchmod),
        ("fchmodat", SYS_fchmodat),
        ("chown", SYS_chown),
        ("fchown", SYS_fchown),
        ("fchownat", SYS_fchownat),
        ("lchown", SYS_lchown),
        ("utimensat", SYS_utimensat),
        ("futimesat", SYS_futimesat),
        // Memory
        ("mmap", SYS_mmap),
        ("mprotect", SYS_mprotect),
        ("munmap", SYS_munmap),
        ("brk", SYS_brk),
        ("mremap", SYS_mremap),
        ("madvise", SYS_madvise),
        ("membarrier", SYS_membarrier),
        ("mincore", SYS_mincore),
        ("msync", SYS_msync),
        ("mlock", SYS_mlock),
        ("mlock2", SYS_mlock2),
        ("munlock", SYS_munlock),
        ("mlockall", SYS_mlockall),
        ("munlockall", SYS_munlockall),
        // Process / thread
        ("clone", SYS_clone),
        ("clone3", SYS_clone3),
        ("fork", SYS_fork),
        ("vfork", SYS_vfork),
        ("execve", SYS_execve),
        ("execveat", SYS_execveat),
        ("exit", SYS_exit),
        ("exit_group", SYS_exit_group),
        ("wait4", SYS_wait4),
        ("waitid", SYS_waitid),
        ("getpid", SYS_getpid),
        ("getppid", SYS_getppid),
        ("gettid", SYS_gettid),
        ("getpgid", SYS_getpgid),
        ("getpgrp", SYS_getpgrp),
        ("setpgid", SYS_setpgid),
        ("setsid", SYS_setsid),
        ("getuid", SYS_getuid),
        ("geteuid", SYS_geteuid),
        ("getgid", SYS_getgid),
        ("getegid", SYS_getegid),
        ("getgroups", SYS_getgroups),
        ("getresuid", SYS_getresuid),
        ("getresgid", SYS_getresgid),
        ("set_tid_address", SYS_set_tid_address),
        ("set_robust_list", SYS_set_robust_list),
        ("get_robust_list", SYS_get_robust_list),
        ("futex", SYS_futex),
        ("sched_yield", SYS_sched_yield),
        ("sched_getaffinity", SYS_sched_getaffinity),
        ("sched_setaffinity", SYS_sched_setaffinity),
        ("sched_getparam", SYS_sched_getparam),
        ("sched_setscheduler", SYS_sched_setscheduler),
        ("sched_getscheduler", SYS_sched_getscheduler),
        ("sched_get_priority_max", SYS_sched_get_priority_max),
        ("sched_get_priority_min", SYS_sched_get_priority_min),
        ("prlimit64", SYS_prlimit64),
        ("getrlimit", SYS_getrlimit),
        ("setrlimit", SYS_setrlimit),
        ("getrusage", SYS_getrusage),
        ("kill", SYS_kill),
        ("tgkill", SYS_tgkill),
        ("tkill", SYS_tkill),
        ("prctl", SYS_prctl),
        ("arch_prctl", SYS_arch_prctl),
        ("rseq", SYS_rseq),
        // Signals
        ("rt_sigaction", SYS_rt_sigaction),
        ("rt_sigprocmask", SYS_rt_sigprocmask),
        ("rt_sigreturn", SYS_rt_sigreturn),
        ("rt_sigsuspend", SYS_rt_sigsuspend),
        ("rt_sigpending", SYS_rt_sigpending),
        ("rt_sigtimedwait", SYS_rt_sigtimedwait),
        ("rt_sigqueueinfo", SYS_rt_sigqueueinfo),
        ("rt_tgsigqueueinfo", SYS_rt_tgsigqueueinfo),
        ("sigaltstack", SYS_sigaltstack),
        // Networking
        ("socket", SYS_socket),
        ("socketpair", SYS_socketpair),
        ("connect", SYS_connect),
        ("accept", SYS_accept),
        ("accept4", SYS_accept4),
        ("bind", SYS_bind),
        ("listen", SYS_listen),
        ("sendto", SYS_sendto),
        ("recvfrom", SYS_recvfrom),
        ("sendmsg", SYS_sendmsg),
        ("recvmsg", SYS_recvmsg),
        ("sendmmsg", SYS_sendmmsg),
        ("recvmmsg", SYS_recvmmsg),
        ("shutdown", SYS_shutdown),
        ("setsockopt", SYS_setsockopt),
        ("getsockopt", SYS_getsockopt),
        ("getsockname", SYS_getsockname),
        ("getpeername", SYS_getpeername),
        ("sendfile", SYS_sendfile),
        // Event / polling
        ("poll", SYS_poll),
        ("ppoll", SYS_ppoll),
        ("select", SYS_select),
        ("pselect6", SYS_pselect6),
        ("epoll_create", SYS_epoll_create),
        ("epoll_create1", SYS_epoll_create1),
        ("epoll_ctl", SYS_epoll_ctl),
        ("epoll_wait", SYS_epoll_wait),
        ("epoll_pwait", SYS_epoll_pwait),
        ("epoll_pwait2", SYS_epoll_pwait2),
        ("eventfd", SYS_eventfd),
        ("eventfd2", SYS_eventfd2),
        ("signalfd", SYS_signalfd),
        ("signalfd4", SYS_signalfd4),
        ("timerfd_create", SYS_timerfd_create),
        ("timerfd_settime", SYS_timerfd_settime),
        ("timerfd_gettime", SYS_timerfd_gettime),
        ("inotify_init", SYS_inotify_init),
        ("inotify_init1", SYS_inotify_init1),
        ("inotify_add_watch", SYS_inotify_add_watch),
        ("inotify_rm_watch", SYS_inotify_rm_watch),
        // Time
        ("clock_gettime", SYS_clock_gettime),
        ("clock_getres", SYS_clock_getres),
        ("clock_nanosleep", SYS_clock_nanosleep),
        ("nanosleep", SYS_nanosleep),
        ("gettimeofday", SYS_gettimeofday),
        ("timer_create", SYS_timer_create),
        ("timer_settime", SYS_timer_settime),
        ("timer_gettime", SYS_timer_gettime),
        ("timer_getoverrun", SYS_timer_getoverrun),
        ("timer_delete", SYS_timer_delete),
        // Random
        ("getrandom", SYS_getrandom),
        // System info
        ("uname", SYS_uname),
        ("sysinfo", SYS_sysinfo),
        ("getdents", SYS_getdents),
        // Misc
        ("umask", SYS_umask),
        ("chdir", SYS_chdir),
        ("fchdir", SYS_fchdir),
        ("seccomp", SYS_seccomp),
        ("close_range", SYS_close_range),
        // Dangerous (for name lookup only — NOT in nodejs allowlist)
        ("ptrace", SYS_ptrace),
        ("mount", SYS_mount),
        ("umount2", SYS_umount2),
        ("pivot_root", SYS_pivot_root),
        ("init_module", SYS_init_module),
        ("finit_module", SYS_finit_module),
        ("delete_module", SYS_delete_module),
        ("setns", SYS_setns),
        ("unshare", SYS_unshare),
        ("bpf", SYS_bpf),
        ("io_uring_setup", SYS_io_uring_setup),
        ("io_uring_enter", SYS_io_uring_enter),
        ("io_uring_register", SYS_io_uring_register),
        ("reboot", SYS_reboot),
        ("kexec_load", SYS_kexec_load),
        ("kexec_file_load", SYS_kexec_file_load),
        ("perf_event_open", SYS_perf_event_open),
        ("add_key", SYS_add_key),
        ("keyctl", SYS_keyctl),
        ("request_key", SYS_request_key),
        ("setuid", SYS_setuid),
        ("setgid", SYS_setgid),
        ("setreuid", SYS_setreuid),
        ("setregid", SYS_setregid),
        ("clock_settime", SYS_clock_settime),
        ("settimeofday", SYS_settimeofday),
        ("adjtimex", SYS_adjtimex),
        ("acct", SYS_acct),
        ("swapon", SYS_swapon),
        ("swapoff", SYS_swapoff),
    ]
};

#[cfg(target_arch = "aarch64")]
static SYSCALL_TABLE: &[(&str, i64)] = {
    use nix::libc::*;
    // aarch64 has a different numbering scheme but most names are the same.
    // Stub: only include the most common ones. Extend as needed.
    &[
        ("read", SYS_read),
        ("write", SYS_write),
        ("close", SYS_close),
        ("openat", SYS_openat),
        ("mmap", SYS_mmap),
        ("mprotect", SYS_mprotect),
        ("munmap", SYS_munmap),
        ("brk", SYS_brk),
        ("clone", SYS_clone),
        ("execve", SYS_execve),
        ("exit", SYS_exit),
        ("exit_group", SYS_exit_group),
    ]
};

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
            allow_syscalls: vec![],
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
            allow_syscalls: vec![],
        };
        let result = compile(&policy).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn compile_nodejs_kill_mode() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Nodejs,
            default_action: SeccompAction::Kill,
            allow_syscalls: vec![],
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

    #[test]
    fn compile_custom_allowlist() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Custom,
            default_action: SeccompAction::Errno,
            allow_syscalls: vec![
                "read".to_owned(),
                "write".to_owned(),
                "exit_group".to_owned(),
            ],
        };
        let result = compile(&policy).unwrap();
        assert!(result.is_some());
        let bpf = result.unwrap();
        assert!(bpf.len() > 5, "BPF program should have instructions");
    }

    #[test]
    fn compile_custom_empty_allowlist() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Custom,
            default_action: SeccompAction::Errno,
            allow_syscalls: vec![],
        };
        // Empty custom allowlist compiles to a filter that blocks everything
        let result = compile(&policy).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn compile_custom_unknown_syscall() {
        let policy = SeccompPolicy {
            preset: SeccompPreset::Custom,
            default_action: SeccompAction::Errno,
            allow_syscalls: vec!["read".to_owned(), "nonexistent_syscall_xyz".to_owned()],
        };
        let result = compile(&policy);
        assert!(result.is_err(), "unknown syscall name should produce error");
        let err = result.unwrap_err();
        assert!(err.contains("nonexistent_syscall_xyz"));
    }

    #[test]
    fn syscall_name_number_roundtrip() {
        // Known syscalls should roundtrip
        let nr = syscall_name_to_number("read").expect("read should be known");
        let name = syscall_number_to_name(nr).expect("should resolve back");
        assert_eq!(name, "read");

        let nr = syscall_name_to_number("mmap").expect("mmap should be known");
        let name = syscall_number_to_name(nr).expect("should resolve back");
        assert_eq!(name, "mmap");

        // Unknown
        assert!(syscall_name_to_number("totally_fake").is_none());
        assert!(syscall_number_to_name(999999).is_none());
    }

    #[test]
    fn syscall_table_no_duplicate_names() {
        let mut names: Vec<&str> = SYSCALL_TABLE.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "SYSCALL_TABLE has duplicate names");
    }

    #[test]
    fn syscall_table_no_duplicate_numbers() {
        let mut numbers: Vec<i64> = SYSCALL_TABLE.iter().map(|(_, n)| *n).collect();
        numbers.sort_unstable();
        let before = numbers.len();
        numbers.dedup();
        assert_eq!(before, numbers.len(), "SYSCALL_TABLE has duplicate numbers");
    }
}
