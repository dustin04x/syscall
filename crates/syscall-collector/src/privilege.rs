//! Privilege and kernel-feature inspection.
//!
//! Loading BPF programs requires CAP_BPF + CAP_PERFMON (Linux 5.8+) or
//! CAP_SYS_ADMIN, or effective UID 0 in the initial user namespace. SYSCALL
//! never escalates privileges on its own; `syscall record` must be launched
//! with the required privilege by the operator.

use std::fs;
use std::path::Path;

pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;

#[derive(Debug, Clone)]
pub struct PrivilegeStatus {
    pub effective_uid: u32,
    pub cap_effective: u64,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub cap_sys_admin: bool,
    pub unprivileged_bpf_disabled: Option<u8>,
    pub btf_path: &'static str,
    pub btf_available: bool,
    pub can_load_bpf: bool,
    pub reason: &'static str,
}

pub fn inspect() -> PrivilegeStatus {
    let effective_uid = effective_uid();
    let (cap_effective, cap_bpf, cap_perfmon, cap_sys_admin) = read_capabilities();
    let unprivileged_bpf_disabled = read_unprivileged_bpf_disabled();
    let btf_path = "/sys/kernel/btf/vmlinux";
    let btf_available = Path::new(btf_path).is_file();

    let (can_load_bpf, reason) = if effective_uid == 0 {
        (true, "effective UID 0")
    } else if cap_bpf && cap_perfmon {
        (true, "CAP_BPF + CAP_PERFMON")
    } else if cap_sys_admin {
        (true, "CAP_SYS_ADMIN")
    } else {
        (
            false,
            "run as root or grant CAP_BPF+CAP_PERFMON (for example via sudo)",
        )
    };

    PrivilegeStatus {
        effective_uid,
        cap_effective,
        cap_bpf,
        cap_perfmon,
        cap_sys_admin,
        unprivileged_bpf_disabled,
        btf_path,
        btf_available,
        can_load_bpf,
        reason,
    }
}

pub fn can_load_bpf() -> bool {
    inspect().can_load_bpf
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn read_capabilities() -> (u64, bool, bool, bool) {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or(0);
    let has = |cap: u32| mask & (1u64 << cap) != 0;
    (mask, has(CAP_BPF), has(CAP_PERFMON), has(CAP_SYS_ADMIN))
}

fn read_unprivileged_bpf_disabled() -> Option<u8> {
    fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_reports_consistent_flags() {
        let status = inspect();
        assert_eq!(status.effective_uid, effective_uid());
        assert_eq!(status.btf_available, Path::new(status.btf_path).is_file());
        if status.can_load_bpf {
            assert!(
                status.effective_uid == 0
                    || (status.cap_bpf && status.cap_perfmon)
                    || status.cap_sys_admin
            );
        }
    }

    #[test]
    fn unprivileged_bpf_setting_is_readable_on_linux() {
        let status = inspect();
        assert!(status.unprivileged_bpf_disabled.is_some());
    }
}
