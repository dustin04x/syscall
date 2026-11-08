//! Bounded `/proc` enrichment.
//!
//! Scheduler tracepoints provide PIDs and comm names, but not parentage,
//! credentials, or a PID-instance start time. Mission 01 reads those from
//! `/proc` immediately after the event. If the process has already disappeared,
//! callers fall back to values cached by the scope tracker.

use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub tgid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    /// Field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
    pub start_time_ticks: Option<u64>,
    pub comm: String,
    /// `NSpid:` values from `/proc/<pid>/status`, in file order.
    /// Per proc_pid_status(5), the leftmost entry is the PID in the PID
    /// namespace of the reading process (the /proc view), followed by the PID
    /// in successively nested *inner* namespaces. The rightmost entry is the
    /// PID in the innermost namespace the process is a member of.
    ///
    /// Important: the rightmost/last entry is NOT universally the initial PID
    /// namespace (level 0). A process in an inner namespace read from that same
    /// inner namespace may report only `[local_pid]`; outer/initial namespace
    /// IDs are not visible from that view. Therefore userspace cannot always
    /// discover the ID that BPF/tracepoints will emit from `NSpid` alone.
    pub nspid: Vec<i32>,
    /// `NStgid:` values from `/proc/<pid>/status`, same ordering as `NSpid`.
    pub nstgid: Vec<i32>,
}

impl ProcInfo {
    pub fn is_process_leader(&self) -> bool {
        self.tgid == self.pid
    }

    /// Leftmost NSpid: PID as seen by the reading process / proc mount.
    pub fn view_ns_pid(&self) -> i32 {
        self.nspid.first().copied().unwrap_or(self.pid)
    }

    /// Rightmost NSpid: PID in the innermost namespace the process belongs to.
    /// Not the same as the initial PID namespace in general.
    pub fn innermost_ns_pid(&self) -> i32 {
        self.nspid.last().copied().unwrap_or(self.pid)
    }

    pub fn view_ns_tgid(&self) -> i32 {
        self.nstgid.first().copied().unwrap_or(self.tgid)
    }

    pub fn innermost_ns_tgid(&self) -> i32 {
        self.nstgid.last().copied().unwrap_or(self.tgid)
    }

    /// All namespace-visible PIDs/TGID values from this proc view that may
    /// identify this process instance. This is a best-effort correlation set;
    /// it may not include namespace IDs invisible to the current /proc mount.
    pub fn id_aliases(&self) -> Vec<i32> {
        let mut aliases = Vec::new();
        for value in [self.pid, self.tgid]
            .into_iter()
            .chain(self.nspid.iter().copied())
            .chain(self.nstgid.iter().copied())
        {
            if value > 0 && !aliases.contains(&value) {
                aliases.push(value);
            }
        }
        aliases
    }
}

/// Read process metadata. Returns `None` if `/proc/<pid>/status` is not
/// readable, which normally means the process has already exited.
pub fn read(pid: i32) -> Option<ProcInfo> {
    if pid <= 0 {
        return None;
    }
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;

    let mut tgid = None;
    let mut ppid = None;
    let mut uid = None;
    let mut gid = None;
    let mut name = None;
    let mut nspid = Vec::new();
    let mut nstgid = Vec::new();

    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "Name" => name = Some(value.to_owned()),
            "Tgid" => tgid = value.parse::<i32>().ok(),
            "PPid" => ppid = value.parse::<i32>().ok(),
            "Uid" => {
                uid = value
                    .split_whitespace()
                    .next()
                    .and_then(|field| field.parse::<u32>().ok());
            }
            "Gid" => {
                gid = value
                    .split_whitespace()
                    .next()
                    .and_then(|field| field.parse::<u32>().ok());
            }
            "NSpid" => {
                nspid = value
                    .split_whitespace()
                    .filter_map(|field| field.parse::<i32>().ok())
                    .collect();
            }
            "NStgid" => {
                nstgid = value
                    .split_whitespace()
                    .filter_map(|field| field.parse::<i32>().ok())
                    .collect();
            }
            _ => {}
        }
    }

    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok();
    let stat_info = stat.as_deref().and_then(parse_stat);
    let start_time_ticks = stat_info.as_ref().and_then(|info| info.start_time_ticks);
    let ppid = ppid.or_else(|| stat_info.as_ref().map(|info| info.ppid));
    let comm = name
        .filter(|name| !name.is_empty())
        .or_else(|| stat_info.map(|info| info.comm))
        .unwrap_or_else(|| "unknown".to_owned());

    Some(ProcInfo {
        pid,
        tgid: tgid.unwrap_or(pid),
        ppid: ppid.unwrap_or(0),
        uid: uid.unwrap_or(0),
        gid: gid.unwrap_or(0),
        start_time_ticks,
        comm,
        nspid,
        nstgid,
    })
}

struct StatInfo {
    comm: String,
    ppid: i32,
    start_time_ticks: Option<u64>,
}

/// Parse the fields we need from `/proc/<pid>/stat`.
///
/// The comm field is wrapped in parentheses and may itself contain spaces or
/// parentheses, so parsing starts at the *last* `)`.
fn parse_stat(stat: &str) -> Option<StatInfo> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = stat.get(open + 1..close)?.to_owned();
    let rest = stat
        .get(close + 1..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    // rest[0] is field 3 (state), rest[1] is field 4 (ppid),
    // rest[19] is field 22 (starttime).
    let ppid = rest.get(1)?.parse::<i32>().ok()?;
    let start_time_ticks = rest.get(19).and_then(|value| value.parse::<u64>().ok());
    Some(StatInfo {
        comm,
        ppid,
        start_time_ticks,
    })
}

pub fn read_boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub fn read_kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub fn read_os_release() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"').to_owned())
        .filter(|value| !value.is_empty())
}

/// Read the PID namespace inode number for a process, if available.
/// This helps diagnose PID-namespace mismatches between BPF and userspace.
pub fn read_pidns_inode(pid: i32) -> Option<u64> {
    read_pidns_dev_ino(pid).map(|(_, ino)| ino)
}

/// Read the PID namespace `(st_dev, st_ino)` for a process. Required for
/// `bpf_get_ns_current_pid_tgid(dev, ino)` correlation.
pub fn read_pidns_dev_ino(pid: i32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(format!("/proc/{pid}/ns/pid")).ok()?;
    Some((meta.dev(), meta.ino()))
}

pub fn is_wsl() -> bool {
    read_kernel_release()
        .map(|release| release.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
        || fs::read_to_string("/proc/version")
            .map(|version| version.to_ascii_lowercase().contains("microsoft"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_self() {
        let pid = std::process::id() as i32;
        let info = read(pid).expect("reading /proc/self");
        assert_eq!(info.pid, pid);
        assert_eq!(info.tgid, pid);
        assert!(info.is_process_leader());
        assert!(info.ppid >= 0);
        assert!(!info.comm.is_empty());
        assert!(info.start_time_ticks.is_some());
    }

    #[test]
    fn missing_pid_returns_none() {
        assert!(read(0).is_none());
        assert!(read(i32::MAX - 1).is_none());
    }

    #[test]
    fn parses_stat_with_parentheses_in_comm() {
        let stat = "123 (weird ) comm) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20";
        let info = parse_stat(stat).unwrap();
        assert_eq!(info.comm, "weird ) comm");
        assert_eq!(info.ppid, 1);
        assert_eq!(info.start_time_ticks, Some(19));
    }

    #[test]
    fn parses_stat_without_starttime() {
        let stat = "123 (short) S 1 2";
        let info = parse_stat(stat).unwrap();
        assert_eq!(info.comm, "short");
        assert_eq!(info.ppid, 1);
        assert_eq!(info.start_time_ticks, None);
    }

    #[test]
    fn kernel_release_is_available() {
        assert!(read_kernel_release().is_some());
        assert!(read_boot_id().is_some());
    }
}
