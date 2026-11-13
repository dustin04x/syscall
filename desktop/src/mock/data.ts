import type {
  AnalysisReport,
  AnalysisRuleMetadata,
  AppInfo,
  EventPayload,
  EventType,
  EventView,
  ExportResult,
  FindingCounts,
  OverviewResponse,
  ProcessTreeResponse,
  ProcessView,
  SessionDetail,
  SessionVerificationReport,
  SessionView,
  VerificationSummary
} from "../types/contracts";

const BASE_ONE = Date.UTC(2026, 10, 10, 19, 18, 1, 508) * 1_000_000;
const BASE_TWO = Date.UTC(2026, 10, 10, 19, 18, 3, 138) * 1_000_000;

const emptyFindings: FindingCounts = {
  informational: 0,
  low: 0,
  medium: 0,
  high: 0,
  critical: 0,
  total: 0
};

function verification(
  assessment: VerificationSummary["assessment"],
  counts: VerificationSummary["counts"],
  limitations: string[]
): VerificationSummary {
  return {
    assessment,
    counts,
    totalFindings: counts.info + counts.warning + counts.error + counts.critical,
    limitations
  };
}

function provenance(sourceTracepoint: string): EventView["provenance"] {
  return {
    rawBpfPid: null,
    rawBpfTgid: null,
    observerPid: null,
    observerTgid: null,
    sourceTracepoint,
    wireSchemaVersion: 1,
    attributionMethod: "process_instance",
    timestampClockDomain: "realtime",
    monotonicClockDomain: "monotonic"
  };
}

function makeEvent(
  _sessionEvents: EventView[],
  args: {
    eventType: EventType;
    timestampNs: number;
    offsetNs: number;
    pid: number;
    comm: string;
    processInstanceId: string;
    ppid: number | null;
    payload: EventPayload;
    tracepoint: string;
  }
): EventView {
  return {
    id: 0,
    eventType: args.eventType,
    timestampNs: args.timestampNs + args.offsetNs,
    monotonicNs: 9_000_000_000 + args.offsetNs,
    pid: args.pid,
    tid: args.pid,
    uid: 1000,
    gid: 1000,
    ppid: args.ppid,
    comm: args.comm,
    processInstanceId: args.processInstanceId,
    payload: args.payload,
    provenance: provenance(args.tracepoint)
  };
}

function filePayload(path: string, index: number): EventPayload {
  const failed = index === 7;
  return {
    kind: "file_open",
    path,
    pathIsAbsolute: true,
    pathTruncated: false,
    dirfd: -100,
    flags: 524288,
    result: failed ? -1 : 3,
    success: !failed,
    errno: failed ? 2 : null
  };
}

const normalPaths = [
  "/etc/ld.so.cache",
  "/lib/x86_64-linux-gnu/libc.so.6",
  "/etc/ld.so.preload",
  "/usr/lib/locale/locale-archive",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache",
  "/proc/self/maps",
  "/proc/self/status",
  "/etc/host.conf",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/usr/share/locale/en/LC_MESSAGES/libc.mo",
  "/dev/null",
  "/proc/26440/cmdline",
  "/proc/26441/cmdline",
  "/proc/26442/cmdline",
  "/usr/lib/x86_64-linux-gnu/libm.so.6",
  "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
  "/usr/lib/x86_64-linux-gnu/libdl.so.2",
  "/usr/lib/x86_64-linux-gnu/librt.so.1",
  "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
  "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
  "/usr/lib/x86_64-linux-gnu/libz.so.1",
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/localtime",
  "/etc/timezone",
  "/sys/devices/system/cpu/online",
  "/proc/meminfo",
  "/proc/loadavg",
  "/etc/environment",
  "/etc/profile",
  "/etc/bash.bashrc",
  "/dev/tty"
];

const interruptedPaths = [
  "/etc/ld.so.cache",
  "/lib/x86_64-linux-gnu/libc.so.6",
  "/usr/lib/locale/locale-archive",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache",
  "/proc/self/maps",
  "/proc/self/status",
  "/etc/host.conf",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/dev/null",
  "/usr/lib/x86_64-linux-gnu/libm.so.6",
  "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
  "/usr/lib/x86_64-linux-gnu/libdl.so.2",
  "/usr/lib/x86_64-linux-gnu/librt.so.1",
  "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
  "/usr/lib/x86_64-linux-gnu/libz.so.1",
  "/etc/localtime",
  "/etc/timezone",
  "/sys/devices/system/cpu/online",
  "/proc/meminfo",
  "/proc/loadavg",
  "/etc/environment",
  "/proc/23944/cmdline",
  "/dev/tty",
  "/proc/self/stat",
  "/proc/self/mountinfo",
  "/usr/share/locale/en/LC_MESSAGES/libc.mo"
];

const normalEvents: EventView[] = [];
const sh = "mock-26440";
const sleep = "mock-26441";
const truth = "mock-26442";

normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exec",
    timestampNs: BASE_ONE,
    offsetNs: 0,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_exec",
      filename: "/bin/sh",
      ppid: 26439,
      startTimeTicks: 9182341,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_fork",
    timestampNs: BASE_ONE,
    offsetNs: 2_000_000,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_fork",
      parentPid: 26440,
      parentTgid: 26440,
      childPid: 26441,
      childComm: "sleep",
      childStartTimeTicks: 9182402
    },
    tracepoint: "sched_process_fork"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_fork",
    timestampNs: BASE_ONE,
    offsetNs: 2_400_000,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_fork",
      parentPid: 26440,
      parentTgid: 26440,
      childPid: 26442,
      childComm: "true",
      childStartTimeTicks: 9182403
    },
    tracepoint: "sched_process_fork"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exec",
    timestampNs: BASE_ONE,
    offsetNs: 3_000_000,
    pid: 26441,
    comm: "sleep",
    processInstanceId: sleep,
    ppid: 26440,
    payload: {
      kind: "process_exec",
      filename: "/bin/sleep",
      ppid: 26440,
      startTimeTicks: 9182402,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);
normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exec",
    timestampNs: BASE_ONE,
    offsetNs: 3_400_000,
    pid: 26442,
    comm: "true",
    processInstanceId: truth,
    ppid: 26440,
    payload: {
      kind: "process_exec",
      filename: "/bin/true",
      ppid: 26440,
      startTimeTicks: 9182403,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);

normalPaths.forEach((path, index) => {
  const owner = index % 3 === 1 ? sleep : index % 3 === 2 ? truth : sh;
  const pid = owner === sleep ? 26441 : owner === truth ? 26442 : 26440;
  const comm = owner === sleep ? "sleep" : owner === truth ? "true" : "sh";
  normalEvents.push(
    makeEvent(normalEvents, {
      eventType: "file_open",
      timestampNs: BASE_ONE,
      offsetNs: 4_000_000 + index * 12_000_000,
      pid,
      comm,
      processInstanceId: owner,
      ppid: owner === sh ? 26439 : 26440,
      payload: filePayload(path, index),
      tracepoint: "sys_enter_openat"
    })
  );
});

normalEvents.push(
  makeEvent(normalEvents, {
    eventType: "process_exit",
    timestampNs: BASE_ONE,
    offsetNs: 900_000_000,
    pid: 26441,
    comm: "sleep",
    processInstanceId: sleep,
    ppid: 26440,
    payload: {
      kind: "process_exit",
      ppid: 26440,
      startTimeTicks: 9182402,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  }),
  makeEvent(normalEvents, {
    eventType: "process_exit",
    timestampNs: BASE_ONE,
    offsetNs: 920_000_000,
    pid: 26442,
    comm: "true",
    processInstanceId: truth,
    ppid: 26440,
    payload: {
      kind: "process_exit",
      ppid: 26440,
      startTimeTicks: 9182403,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  }),
  makeEvent(normalEvents, {
    eventType: "process_exit",
    timestampNs: BASE_ONE,
    offsetNs: 1_066_000_000,
    pid: 26440,
    comm: "sh",
    processInstanceId: sh,
    ppid: 26439,
    payload: {
      kind: "process_exit",
      ppid: 26439,
      startTimeTicks: 9182341,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  })
);

const interruptedEvents: EventView[] = [];
const sleeper = "mock-23944";
interruptedEvents.push(
  makeEvent(interruptedEvents, {
    eventType: "process_exec",
    timestampNs: BASE_TWO,
    offsetNs: 0,
    pid: 23944,
    comm: "sleep",
    processInstanceId: sleeper,
    ppid: 23943,
    payload: {
      kind: "process_exec",
      filename: "/bin/sleep",
      ppid: 23943,
      startTimeTicks: 9184410,
      oldPid: null
    },
    tracepoint: "sched_process_exec"
  })
);

interruptedPaths.forEach((path, index) => {
  interruptedEvents.push(
    makeEvent(interruptedEvents, {
      eventType: "file_open",
      timestampNs: BASE_TWO,
      offsetNs: 3_000_000 + index * 20_000_000,
      pid: 23944,
      comm: "sleep",
      processInstanceId: sleeper,
      ppid: 23943,
      payload: filePayload(path, index),
      tracepoint: "sys_enter_openat"
    })
  );
});

interruptedEvents.push(
  makeEvent(interruptedEvents, {
    eventType: "process_exit",
    timestampNs: BASE_TWO,
    offsetNs: 33_500_000_000,
    pid: 23944,
    comm: "sleep",
    processInstanceId: sleeper,
    ppid: 23943,
    payload: {
      kind: "process_exit",
      ppid: 23943,
      startTimeTicks: 9184410,
      exitPriority: 0
    },
    tracepoint: "sched_process_exit"
  })
);


const BASE_THREE = Date.UTC(2026, 10, 10, 19, 19, 12, 44) * 1_000_000;
const launcher = "mock-28110";
const curlA = "mock-28111";
const curlB = "mock-28112";
const catp = "mock-28113";

const complexEvents: EventView[] = [];

function pushComplex(event: Omit<EventView, "id">): void {
  complexEvents.push({ id: complexEvents.length + 1, ...event });
}

function fileEv(
  offsetNs: number,
  pid: number,
  comm: string,
  processInstanceId: string,
  ppid: number | null,
  path: string,
  opts?: { success?: boolean; errno?: number | null; result?: number; flags?: number; dirfd?: number; absolute?: boolean }
): Omit<EventView, "id"> {
  const success = opts?.success ?? true;
  const failed = !success;
  return {
    eventType: "file_open",
    timestampNs: BASE_THREE + offsetNs,
    monotonicNs: 11_000_000_000 + offsetNs,
    pid,
    tid: pid,
    uid: 1000,
    gid: 1000,
    ppid,
    comm,
    processInstanceId,
    payload: {
      kind: "file_open",
      path,
      pathIsAbsolute: opts?.absolute ?? path.startsWith("/"),
      pathTruncated: false,
      dirfd: opts?.dirfd ?? -100,
      flags: opts?.flags ?? 524288,
      result: opts?.result ?? (failed ? -1 : 3),
      success,
      errno: failed ? (opts?.errno ?? 2) : null
    },
    provenance: provenance("sys_enter_openat")
  };
}

function netEv(
  offsetNs: number,
  pid: number,
  comm: string,
  processInstanceId: string,
  ppid: number | null,
  destinationAddress: string,
  destinationPort: number,
  family: "ipv4" | "ipv6",
  opts?: { success?: boolean; errno?: number | null; result?: number }
): Omit<EventView, "id"> {
  const success = opts?.success ?? false;
  const failed = !success;
  return {
    eventType: "network_connect",
    timestampNs: BASE_THREE + offsetNs,
    monotonicNs: 11_000_000_000 + offsetNs,
    pid,
    tid: pid,
    uid: 1000,
    gid: 1000,
    ppid,
    comm,
    processInstanceId,
    payload: {
      kind: "network_connect",
      family,
      sourceAddress: null,
      sourcePort: null,
      destinationAddress,
      destinationPort,
      result: opts?.result ?? (success ? 0 : -111),
      success,
      errno: failed ? (opts?.errno ?? 111) : null,
      established: success
    },
    provenance: provenance("sys_enter_connect")
  };
}

// launcher: shell orchestrating multiple children
pushComplex({
  eventType: "process_exec",
  timestampNs: BASE_THREE,
  monotonicNs: 11_000_000_000,
  pid: 28110,
  tid: 28110,
  uid: 1000,
  gid: 1000,
  ppid: 28109,
  comm: "sh",
  processInstanceId: launcher,
  payload: {
    kind: "process_exec",
    filename: "/bin/sh",
    ppid: 28109,
    startTimeTicks: 9281100,
    oldPid: null
  },
  provenance: provenance("sched_process_exec")
});
pushComplex(fileEv(1_000_000, 28110, "sh", launcher, 28109, "/etc/ld.so.cache"));
pushComplex(fileEv(2_000_000, 28110, "sh", launcher, 28109, "/lib/x86_64-linux-gnu/libc.so.6"));
pushComplex(fileEv(3_000_000, 28110, "sh", launcher, 28109, "/lib/x86_64-linux-gnu/libselinux.so.1"));
pushComplex(fileEv(4_000_000, 28110, "sh", launcher, 28109, "/lib/x86_64-linux-gnu/libpcre2-8.so.0"));
pushComplex(fileEv(5_000_000, 28110, "sh", launcher, 28109, "/etc/nsswitch.conf"));
pushComplex(fileEv(6_000_000, 28110, "sh", launcher, 28109, "/etc/passwd"));
pushComplex({
  eventType: "process_fork",
  timestampNs: BASE_THREE + 8_000_000,
  monotonicNs: 11_008_000_000,
  pid: 28110,
  tid: 28110,
  uid: 1000,
  gid: 1000,
  ppid: 28109,
  comm: "sh",
  processInstanceId: launcher,
  payload: { kind: "process_fork", parentPid: 28110, parentTgid: 28110, childPid: 28111, childComm: "sh", childStartTimeTicks: 9281110 },
  provenance: provenance("sched_process_fork")
});

// curlA: HTTP attempt over IPv4 (failed connect) + config/cert reads
pushComplex({
  eventType: "process_exec",
  timestampNs: BASE_THREE + 10_000_000,
  monotonicNs: 11_010_000_000,
  pid: 28111,
  tid: 28111,
  uid: 1000,
  gid: 1000,
  ppid: 28110,
  comm: "curl",
  processInstanceId: curlA,
  payload: {
    kind: "process_exec",
    filename: "/usr/bin/curl",
    ppid: 28110,
    startTimeTicks: 9281110,
    oldPid: null
  },
  provenance: provenance("sched_process_exec")
});
pushComplex(fileEv(11_000_000, 28111, "curl", curlA, 28110, "/etc/ld.so.cache"));
pushComplex(fileEv(12_000_000, 28111, "curl", curlA, 28110, "/lib/x86_64-linux-gnu/libcurl.so.4"));
pushComplex(fileEv(13_000_000, 28111, "curl", curlA, 28110, "/lib/x86_64-linux-gnu/libssl.so.3"));
pushComplex(fileEv(14_000_000, 28111, "curl", curlA, 28110, "/lib/x86_64-linux-gnu/libcrypto.so.3"));
pushComplex(fileEv(15_000_000, 28111, "curl", curlA, 28110, "/lib/x86_64-linux-gnu/libz.so.1"));
pushComplex(fileEv(16_000_000, 28111, "curl", curlA, 28110, "/etc/nsswitch.conf"));
pushComplex(fileEv(17_000_000, 28111, "curl", curlA, 28110, "/etc/resolv.conf"));
pushComplex(fileEv(18_000_000, 28111, "curl", curlA, 28110, "/etc/hosts"));
pushComplex(fileEv(19_000_000, 28111, "curl", curlA, 28110, "/etc/ssl/certs/ca-certificates.crt"));
pushComplex(fileEv(20_000_000, 28111, "curl", curlA, 28110, "/dev/urandom"));
pushComplex(netEv(22_000_000, 28111, "curl", curlA, 28110, "203.0.113.10", 8080, "ipv4", { success: false, errno: 111, result: -111 }));
pushComplex(netEv(24_000_000, 28111, "curl", curlA, 28110, "203.0.113.10", 8080, "ipv4", { success: false, errno: 110, result: -110 }));
pushComplex({
  eventType: "process_exit",
  timestampNs: BASE_THREE + 40_000_000,
  monotonicNs: 11_040_000_000,
  pid: 28111,
  tid: 28111,
  uid: 1000,
  gid: 1000,
  ppid: 28110,
  comm: "curl",
  processInstanceId: curlA,
  payload: { kind: "process_exit", ppid: 28110, startTimeTicks: 9281110, exitPriority: 28 },
  provenance: provenance("sched_process_exit")
});

// second child fork + curlB: IPv6 connect success attempt and localhost
pushComplex({
  eventType: "process_fork",
  timestampNs: BASE_THREE + 45_000_000,
  monotonicNs: 11_045_000_000,
  pid: 28110,
  tid: 28110,
  uid: 1000,
  gid: 1000,
  ppid: 28109,
  comm: "sh",
  processInstanceId: launcher,
  payload: { kind: "process_fork", parentPid: 28110, parentTgid: 28110, childPid: 28112, childComm: "sh", childStartTimeTicks: 9281120 },
  provenance: provenance("sched_process_fork")
});
pushComplex({
  eventType: "process_exec",
  timestampNs: BASE_THREE + 47_000_000,
  monotonicNs: 11_047_000_000,
  pid: 28112,
  tid: 28112,
  uid: 1000,
  gid: 1000,
  ppid: 28110,
  comm: "curl",
  processInstanceId: curlB,
  payload: {
    kind: "process_exec",
    filename: "/usr/bin/curl",
    ppid: 28110,
    startTimeTicks: 9281120,
    oldPid: null
  },
  provenance: provenance("sched_process_exec")
});
pushComplex(fileEv(48_000_000, 28112, "curl", curlB, 28110, "/etc/ld.so.cache"));
pushComplex(fileEv(49_000_000, 28112, "curl", curlB, 28110, "/lib/x86_64-linux-gnu/libcurl.so.4"));
pushComplex(fileEv(50_000_000, 28112, "curl", curlB, 28110, "/lib/x86_64-linux-gnu/libssl.so.3"));
pushComplex(fileEv(51_000_000, 28112, "curl", curlB, 28110, "/lib/x86_64-linux-gnu/libcrypto.so.3"));
pushComplex(fileEv(52_000_000, 28112, "curl", curlB, 28110, "/etc/resolv.conf"));
pushComplex(fileEv(53_000_000, 28112, "curl", curlB, 28110, "/etc/gai.conf"));
pushComplex(fileEv(54_000_000, 28112, "curl", curlB, 28110, "/etc/ssl/certs/ca-certificates.crt"));
pushComplex(netEv(56_000_000, 28112, "curl", curlB, 28110, "2001:db8::10", 443, "ipv6", { success: true, errno: null, result: 0 }));
pushComplex(netEv(58_000_000, 28112, "curl", curlB, 28110, "127.0.0.1", 9, "ipv4", { success: false, errno: 111, result: -111 }));
pushComplex({
  eventType: "process_exit",
  timestampNs: BASE_THREE + 70_000_000,
  monotonicNs: 11_070_000_000,
  pid: 28112,
  tid: 28112,
  uid: 1000,
  gid: 1000,
  ppid: 28110,
  comm: "curl",
  processInstanceId: curlB,
  payload: { kind: "process_exit", ppid: 28110, startTimeTicks: 9281120, exitPriority: 0 },
  provenance: provenance("sched_process_exit")
});

// third child: cat attempts sensitive file (failed open)
pushComplex({
  eventType: "process_fork",
  timestampNs: BASE_THREE + 72_000_000,
  monotonicNs: 11_072_000_000,
  pid: 28110,
  tid: 28110,
  uid: 1000,
  gid: 1000,
  ppid: 28109,
  comm: "sh",
  processInstanceId: launcher,
  payload: { kind: "process_fork", parentPid: 28110, parentTgid: 28110, childPid: 28113, childComm: "sh", childStartTimeTicks: 9281130 },
  provenance: provenance("sched_process_fork")
});
pushComplex({
  eventType: "process_exec",
  timestampNs: BASE_THREE + 74_000_000,
  monotonicNs: 11_074_000_000,
  pid: 28113,
  tid: 28113,
  uid: 1000,
  gid: 1000,
  ppid: 28110,
  comm: "cat",
  processInstanceId: catp,
  payload: {
    kind: "process_exec",
    filename: "/bin/cat",
    ppid: 28110,
    startTimeTicks: 9281130,
    oldPid: null
  },
  provenance: provenance("sched_process_exec")
});
pushComplex(fileEv(75_000_000, 28113, "cat", catp, 28110, "/etc/ld.so.cache"));
pushComplex(fileEv(76_000_000, 28113, "cat", catp, 28110, "/lib/x86_64-linux-gnu/libc.so.6"));
pushComplex(fileEv(77_000_000, 28113, "cat", catp, 28110, "/usr/lib/locale/locale-archive"));
pushComplex(fileEv(78_000_000, 28113, "cat", catp, 28110, "/etc/shadow", { success: false, errno: 13, result: -1 }));
pushComplex({
  eventType: "process_exit",
  timestampNs: BASE_THREE + 80_000_000,
  monotonicNs: 11_080_000_000,
  pid: 28113,
  tid: 28113,
  uid: 1000,
  gid: 1000,
  ppid: 28110,
  comm: "cat",
  processInstanceId: catp,
  payload: { kind: "process_exit", ppid: 28110, startTimeTicks: 9281130, exitPriority: 1 },
  provenance: provenance("sched_process_exit")
});

pushComplex({
  eventType: "process_exit",
  timestampNs: BASE_THREE + 90_000_000,
  monotonicNs: 11_090_000_000,
  pid: 28110,
  tid: 28110,
  uid: 1000,
  gid: 1000,
  ppid: 28109,
  comm: "sh",
  processInstanceId: launcher,
  payload: { kind: "process_exit", ppid: 28109, startTimeTicks: 9281100, exitPriority: 0 },
  provenance: provenance("sched_process_exit")
});


export const appInfo: AppInfo = {
  contractVersion: "ui-preview",
  appVersion: "0.1.0",
  databasePath: "/mock/evidence/workbench-preview.db",
  databaseExists: true,
  readOnly: true,
  exportDirectory: "/mock/evidence/exports",
  recordingSupported: false
};

export const sessions: SessionView[] = [
  {
    id: "mock-normal-001",
    status: "completed",
    command: "/bin/sh",
    arguments: ["-c", "/bin/sleep 0.2 && /bin/true; wait"],
    commandDisplay: "/bin/sh -c /bin/sleep 0.2 && /bin/true; wait",
    recordingScope: "target-tree",
    startedAtNs: BASE_ONE,
    endedAtNs: BASE_ONE + 1_066_000_000,
    durationNs: 1_066_000_000,
    processCount: 3,
    eventCount: normalEvents.length,
    droppedEvents: 0,
    ringbufLostEvents: 0,
    userspaceDroppedEvents: 0,
    malformedEvents: 0,
    filteredEvents: 14,
    persistFailedEvents: 0,
    evidenceIncomplete: false,
    targetExitCode: 0,
    targetExitSignal: null,
    terminationReason: "target_exit",
    error: null,
    kernelRelease: "6.6.87.2-microsoft-standard-WSL2",
    collectorVersion: "0.1.0",
    verification: verification("valid", { info: 0, warning: 0, error: 0, critical: 0 }, []),
    findingCounts: emptyFindings,
    intelligenceError: null
  },
  {
    id: "mock-interrupt-002",
    status: "interrupted",
    command: "/bin/sleep",
    arguments: ["30"],
    commandDisplay: "/bin/sleep 30",
    recordingScope: "target-tree",
    startedAtNs: BASE_TWO,
    endedAtNs: BASE_TWO + 33_500_000_000,
    durationNs: 33_500_000_000,
    processCount: 1,
    eventCount: interruptedEvents.length,
    droppedEvents: 0,
    ringbufLostEvents: 0,
    userspaceDroppedEvents: 0,
    malformedEvents: 0,
    filteredEvents: 7,
    persistFailedEvents: 0,
    evidenceIncomplete: false,
    targetExitCode: null,
    targetExitSignal: null,
    terminationReason: "interrupted",
    error: null,
    kernelRelease: "6.6.87.2-microsoft-standard-WSL2",
    collectorVersion: "0.1.0",
    verification: verification(
      "valid_but_incomplete",
      { info: 0, warning: 1, error: 0, critical: 0 },
      ["The session was interrupted before the target completed."]
    ),
    findingCounts: {
      informational: 0,
      low: 1,
      medium: 0,
      high: 0,
      critical: 0,
      total: 1
    },
    intelligenceError: null
  },
  {
    id: "mock-complex-003",
    status: "completed",
    command: "/bin/sh",
    arguments: ["-c", "curl --max-time 2 http://203.0.113.10:8080/health; curl -6 https://[2001:db8::10]/; cat /etc/shadow || true"],
    commandDisplay: "/bin/sh -c \"curl --max-time 2 http://203.0.113.10:8080/health; curl -6 https://[2001:db8::10]/; cat /etc/shadow || true\"",
    recordingScope: "target-tree",
    startedAtNs: BASE_THREE,
    endedAtNs: BASE_THREE + 90_000_000,
    durationNs: 90_000_000,
    processCount: 4,
    eventCount: complexEvents.length,
    droppedEvents: 0,
    ringbufLostEvents: 0,
    userspaceDroppedEvents: 0,
    malformedEvents: 0,
    filteredEvents: 23,
    persistFailedEvents: 0,
    evidenceIncomplete: false,
    targetExitCode: 0,
    targetExitSignal: null,
    terminationReason: "target_exit",
    error: null,
    kernelRelease: "6.6.87.2-microsoft-standard-WSL2",
    collectorVersion: "0.1.0",
    verification: verification("valid", { info: 1, warning: 0, error: 0, critical: 0 }, ["One failed connect attempt and one denied file open were recorded as evidence, not as collection failures."]),
    findingCounts: {
      informational: 2,
      low: 1,
      medium: 0,
      high: 0,
      critical: 0,
      total: 3
    },
    intelligenceError: null
  }
];

complexEvents.forEach((event, index) => {
  event.id = index + 1;
});

normalEvents.forEach((event, index) => {
  event.id = index + 1;
});
interruptedEvents.forEach((event, index) => {
  event.id = index + 1;
});

const eventsBySession: Record<string, EventView[]> = {
  "mock-normal-001": normalEvents,
  "mock-interrupt-002": interruptedEvents,
  "mock-complex-003": complexEvents
};

const trees: Record<string, ProcessTreeResponse> = {
  "mock-normal-001": {
    processes: [
      {
        processInstanceId: sh,
        pid: 26440,
        comm: "sh",
        executable: "/bin/sh",
        commandLine: "/bin/sh -c /bin/sleep 0.2 && /bin/true; wait",
        firstSeenNs: BASE_ONE,
        lastSeenNs: BASE_ONE + 1_066_000_000,
        eventCount: 15,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 26439,
        parentProcessInstanceId: null,
        identityUnresolved: false,
        ancestryUnresolved: true,
        notes: ["Parent pid 26439 was outside the recorded target tree."],
        childInstanceIds: [sleep, truth],
        relationship: "root"
      },
      {
        processInstanceId: sleep,
        pid: 26441,
        comm: "sleep",
        executable: "/bin/sleep",
        commandLine: "/bin/sleep 0.2",
        firstSeenNs: BASE_ONE + 2_000_000,
        lastSeenNs: BASE_ONE + 900_000_000,
        eventCount: 13,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 26440,
        parentProcessInstanceId: sh,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: [],
        childInstanceIds: [],
        relationship: "observed"
      },
      {
        processInstanceId: truth,
        pid: 26442,
        comm: "true",
        executable: "/bin/true",
        commandLine: "/bin/true",
        firstSeenNs: BASE_ONE + 2_400_000,
        lastSeenNs: BASE_ONE + 920_000_000,
        eventCount: 13,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 26440,
        parentProcessInstanceId: sh,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: [],
        childInstanceIds: [],
        relationship: "observed"
      }
    ],
    roots: [sh],
    unresolvedAncestryCount: 1,
    identityUnresolvedCount: 0,
    notes: ["One ancestry link terminates outside the recorded target tree."]
  },
  "mock-interrupt-002": {
    processes: [
      {
        processInstanceId: sleeper,
        pid: 23944,
        comm: "sleep",
        executable: "/bin/sleep",
        commandLine: "/bin/sleep 30",
        firstSeenNs: BASE_TWO,
        lastSeenNs: BASE_TWO + 33_500_000_000,
        eventCount: 32,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 23943,
        parentProcessInstanceId: null,
        identityUnresolved: false,
        ancestryUnresolved: true,
        notes: ["The recorded process was terminated when capture stopped."],
        childInstanceIds: [],
        relationship: "root"
      }
    ],
    roots: [sleeper],
    unresolvedAncestryCount: 1,
    identityUnresolvedCount: 0,
    notes: []
  },
  "mock-complex-003": {
    processes: [
      {
        processInstanceId: launcher,
        pid: 28110,
        comm: "sh",
        executable: "/bin/sh",
        commandLine: "/bin/sh -c \"curl --max-time 2 http://203.0.113.10:8080/health; curl -6 https://[2001:db8::10]/; cat /etc/shadow || true\"",
        firstSeenNs: BASE_THREE,
        lastSeenNs: BASE_THREE + 90_000_000,
        eventCount: 14,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 28109,
        parentProcessInstanceId: null,
        identityUnresolved: false,
        ancestryUnresolved: true,
        notes: ["Parent pid 28109 was outside the recorded target tree."],
        childInstanceIds: [curlA, curlB, catp],
        relationship: "root"
      },
      {
        processInstanceId: curlA,
        pid: 28111,
        comm: "curl",
        executable: "/usr/bin/curl",
        commandLine: "/usr/bin/curl --max-time 2 http://203.0.113.10:8080/health",
        firstSeenNs: BASE_THREE + 10_000_000,
        lastSeenNs: BASE_THREE + 40_000_000,
        eventCount: 13,
        exitObserved: true,
        exitPriority: 28,
        parentPid: 28110,
        parentProcessInstanceId: launcher,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: ["Two failed IPv4 connect attempts were recorded."],
        childInstanceIds: [],
        relationship: "observed"
      },
      {
        processInstanceId: curlB,
        pid: 28112,
        comm: "curl",
        executable: "/usr/bin/curl",
        commandLine: "/usr/bin/curl -6 https://[2001:db8::10]/",
        firstSeenNs: BASE_THREE + 47_000_000,
        lastSeenNs: BASE_THREE + 70_000_000,
        eventCount: 10,
        exitObserved: true,
        exitPriority: 0,
        parentPid: 28110,
        parentProcessInstanceId: launcher,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: ["Recorded a successful IPv6 connect attempt and a failed localhost connect attempt."],
        childInstanceIds: [],
        relationship: "observed"
      },
      {
        processInstanceId: catp,
        pid: 28113,
        comm: "cat",
        executable: "/bin/cat",
        commandLine: "/bin/cat /etc/shadow",
        firstSeenNs: BASE_THREE + 74_000_000,
        lastSeenNs: BASE_THREE + 80_000_000,
        eventCount: 6,
        exitObserved: true,
        exitPriority: 1,
        parentPid: 28110,
        parentProcessInstanceId: launcher,
        identityUnresolved: false,
        ancestryUnresolved: false,
        notes: ["Open of /etc/shadow failed with EACCES and was recorded."],
        childInstanceIds: [],
        relationship: "observed"
      }
    ],
    roots: [launcher],
    unresolvedAncestryCount: 1,
    identityUnresolvedCount: 0,
    notes: ["One ancestry link terminates outside the recorded target tree."]
  }
};

const rules: AnalysisRuleMetadata[] = [
  {
    rule_id: "NET-001",
    version: 1,
    title: "Network connect from a short-lived process",
    description: "A process initiated an outbound connection during a short observed lifetime.",
    conditions: ["A network_connect event belongs to the process instance."],
    required_evidence: ["network_connect event", "process instance"],
    exclusions: [],
    known_false_positives: ["Package managers and health checks."],
    severity_rationale: "Low severity because outbound access is common.",
    confidence_rationale: "High confidence in the observation, not intent.",
    default_severity: "low",
    default_confidence: "high"
  },
  {
    rule_id: "PROC-002",
    version: 1,
    title: "Observed process without a complete lifetime",
    description: "Process activity exists but the full process lifetime was not observed.",
    conditions: ["A process instance was observed without both entry and exit ancestry."],
    required_evidence: ["process instance", "session boundary"],
    exclusions: [],
    known_false_positives: ["Capture interruptions and intentionally long-running targets."],
    severity_rationale: "Low severity because this is a coverage limitation.",
    confidence_rationale: "High confidence in the recorded boundary.",
    default_severity: "low",
    default_confidence: "high"
  },
  {
    rule_id: "FILE-003",
    version: 1,
    title: "Library file opened by a short-lived process",
    description: "A process loaded shared libraries during startup.",
    conditions: ["A file_open event points at a shared-library path."],
    required_evidence: ["file_open event"],
    exclusions: [],
    known_false_positives: ["Normal dynamic linking."],
    severity_rationale: "Informational; this is expected runtime behavior.",
    confidence_rationale: "High confidence in the recorded path.",
    default_severity: "informational",
    default_confidence: "high"
  },
  {
    rule_id: "EXEC-004",
    version: 1,
    title: "Executable replaced during process transition",
    description: "An exec transition was observed for a forked process.",
    conditions: ["A process_fork event is followed by an exec for the child pid."],
    required_evidence: ["process_fork event", "process_exec event"],
    exclusions: [],
    known_false_positives: ["Shell command execution."],
    severity_rationale: "Informational; common shell behavior.",
    confidence_rationale: "Medium confidence because event ordering is bounded by persistence.",
    default_severity: "informational",
    default_confidence: "medium"
  }
];

function analysisFor(sessionId: string): AnalysisReport {
  const session = sessions.find((item) => item.id === sessionId) ?? sessions[0];
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };

  if (session.id === "mock-interrupt-002") {
    return {
      schema_version: "syscall-analysis/v1",
      session_id: session.id,
      session_command: session.commandDisplay,
      session_scope: session.recordingScope,
      session_started_at_ns: session.startedAtNs,
      session_ended_at_ns: session.endedAtNs,
      evidence: {
        status: "interrupted",
        session_status: session.status,
        event_count: session.eventCount,
        process_count: session.processCount,
        ringbuf_lost_events: 0,
        userspace_dropped_events: 0,
        malformed_events: 0,
        filtered_events: session.filteredEvents,
        events_persist_failed: 0,
        unresolved_identity_count: 1,
        verification_assessment: session.verification?.assessment ?? null,
        may_be_incomplete: true,
        notes: ["The target did not complete before capture ended.", "1 process ancestry link is unresolved."]
      },
      rules_evaluated: rules,
      findings: [
        {
          finding_id: "mock-finding-001",
          rule_id: "PROC-002",
          rule_version: 1,
          severity: "low",
          confidence: "high",
          title: "Process remained observable without a complete lifetime",
          explanation: "The target process was observed for 33.5 seconds before the capture boundary terminated it.",
          significance: "The missing post-boundary behavior qualifies the completeness of this session without implying evidence loss.",
          event_ids: [1, 32],
          process_instance_ids: [sleeper],
          pids: [23944],
          time_range: { start_ns: BASE_TWO, end_ns: BASE_TWO + 33_500_000_000 },
          related_findings: [],
          limitations: ["The process may have continued after capture stopped."],
          next_steps: ["Review the session termination reason and target command line."],
          supporting_events: [
            {
              event_id: 1,
              timestamp_ns: BASE_TWO,
              monotonic_ns: 9_000_000_000,
              event_type: "process_exec",
              pid: 23944,
              process_instance_id: sleeper,
              comm: "sleep",
              summary: "/bin/sleep"
            }
          ],
          related_processes: [
            {
              process_instance_id: sleeper,
              pid: 23944,
              comm: "sleep",
              executable: "/bin/sleep",
              parent_process_instance_id: null,
              exit_observed: true
            }
          ],
          correlation: "single_process"
        }
      ],
      limitations: ["Analysis is limited to persisted evidence.", "A finding is an observation, not a verdict."],
      truncated: false
    };
  }

  if (session.id === "mock-complex-003") {
    const events = eventsBySession[session.id] ?? [];
    const ev = (pred: (e: EventView) => boolean) => events.find(pred)!;
    const execCurlA = ev((e) => e.eventType === "process_exec" && e.pid === 28111);
    const connectFail = ev((e) => e.eventType === "network_connect" && e.pid === 28111);
    const connectOkV6 = ev((e) => e.eventType === "network_connect" && e.pid === 28112 && e.payload.kind === "network_connect" && e.payload.success);
    const execCat = ev((e) => e.eventType === "process_exec" && e.pid === 28113);
    const shadowOpen = ev((e) => e.eventType === "file_open" && e.payload.kind === "file_open" && e.payload.path === "/etc/shadow");
    const libOpen = ev((e) => e.eventType === "file_open" && e.pid === 28111 && e.payload.kind === "file_open" && e.payload.path.includes("libcurl"));
    const forkA = ev((e) => e.eventType === "process_fork" && e.payload.kind === "process_fork" && e.payload.childPid === 28111);
    return {
      schema_version: "syscall-analysis/v1",
      session_id: session.id,
      session_command: session.commandDisplay,
      session_scope: session.recordingScope,
      session_started_at_ns: session.startedAtNs,
      session_ended_at_ns: session.endedAtNs,
      evidence: {
        status: "complete",
        session_status: session.status,
        event_count: session.eventCount,
        process_count: session.processCount,
        ringbuf_lost_events: 0,
        userspace_dropped_events: 0,
        malformed_events: 0,
        filtered_events: session.filteredEvents,
        events_persist_failed: 0,
        unresolved_identity_count: 0,
        verification_assessment: session.verification?.assessment ?? null,
        may_be_incomplete: false,
        notes: [
          "Evidence completeness is qualified by target-tree attribution.",
          "Recorded IPv4 and IPv6 connect attempts, including failures and one successful connect attempt.",
          "One denied open of /etc/shadow was recorded as a failed file_open event."
        ]
      },
      rules_evaluated: rules,
      findings: [
        {
          finding_id: "mock-complex-finding-001",
          rule_id: "NET-001",
          rule_version: 1,
          severity: "low",
          confidence: "high",
          title: "Outbound network connect attempts observed across multiple processes",
          explanation: "Short-lived curl processes initiated connect attempts to 203.0.113.10:8080 (IPv4, failed), [2001:db8::10]:443 (IPv6, successful attempt), and 127.0.0.1:9 (IPv4, failed).",
          significance: "The evidence shows network activity attempts and their recorded results; a successful connect attempt does not prove data transfer or an established session beyond the syscall result.",
          event_ids: [connectFail.id, connectOkV6.id],
          process_instance_ids: [curlA, curlB],
          pids: [28111, 28112],
          time_range: { start_ns: connectFail.timestampNs, end_ns: connectOkV6.timestampNs },
          related_findings: ["mock-complex-finding-002"],
          limitations: ["Only connect attempts are recorded; payloads, DNS, and transport protocol details are not captured."],
          next_steps: ["Review destination addresses, ports, and connect results in the network view.", "Correlate with process command lines and file activity."],
          supporting_events: [
            {
              event_id: connectFail.id,
              timestamp_ns: connectFail.timestampNs,
              monotonic_ns: connectFail.monotonicNs,
              event_type: "network_connect",
              pid: 28111,
              process_instance_id: curlA,
              comm: "curl",
              summary: "203.0.113.10:8080 (ipv4, failed)"
            },
            {
              event_id: connectOkV6.id,
              timestamp_ns: connectOkV6.timestampNs,
              monotonic_ns: connectOkV6.monotonicNs,
              event_type: "network_connect",
              pid: 28112,
              process_instance_id: curlB,
              comm: "curl",
              summary: "[2001:db8::10]:443 (ipv6, success)"
            }
          ],
          related_processes: [
            { process_instance_id: curlA, pid: 28111, comm: "curl", executable: "/usr/bin/curl", parent_process_instance_id: launcher, exit_observed: true },
            { process_instance_id: curlB, pid: 28112, comm: "curl", executable: "/usr/bin/curl", parent_process_instance_id: launcher, exit_observed: true }
          ],
          correlation: "cross_process"
        },
        {
          finding_id: "mock-complex-finding-002",
          rule_id: "EXEC-004",
          rule_version: 1,
          severity: "informational",
          confidence: "medium",
          title: "Executable transitions observed in a multi-process shell workflow",
          explanation: "The launcher shell forked and executed curl and cat processes as part of the recorded command sequence.",
          significance: "Fork/exec transitions are expected in shell-driven workflows; they establish observed process lineage for later file and network activity.",
          event_ids: [forkA.id, execCurlA.id, execCat.id],
          process_instance_ids: [launcher, curlA, catp],
          pids: [28110, 28111, 28113],
          time_range: { start_ns: forkA.timestampNs, end_ns: execCat.timestampNs },
          related_findings: ["mock-complex-finding-001"],
          limitations: ["Ordering is bounded by persisted evidence."],
          next_steps: ["Inspect the process tree to follow parent-child relationships."],
          supporting_events: [
            {
              event_id: forkA.id,
              timestamp_ns: forkA.timestampNs,
              monotonic_ns: forkA.monotonicNs,
              event_type: "process_fork",
              pid: 28110,
              process_instance_id: launcher,
              comm: "sh",
              summary: "fork -> pid 28111"
            },
            {
              event_id: execCurlA.id,
              timestamp_ns: execCurlA.timestampNs,
              monotonic_ns: execCurlA.monotonicNs,
              event_type: "process_exec",
              pid: 28111,
              process_instance_id: curlA,
              comm: "curl",
              summary: "/usr/bin/curl"
            }
          ],
          related_processes: [
            { process_instance_id: launcher, pid: 28110, comm: "sh", executable: "/bin/sh", parent_process_instance_id: null, exit_observed: true },
            { process_instance_id: curlA, pid: 28111, comm: "curl", executable: "/usr/bin/curl", parent_process_instance_id: launcher, exit_observed: true }
          ],
          correlation: "process_tree"
        },
        {
          finding_id: "mock-complex-finding-003",
          rule_id: "FILE-003",
          rule_version: 1,
          severity: "informational",
          confidence: "high",
          title: "Shared libraries and sensitive-path access attempts recorded",
          explanation: "Processes loaded runtime libraries and configuration/certificate files; a denied open of /etc/shadow by cat was recorded.",
          significance: "Library and configuration reads are common during startup. The failed /etc/shadow open is recorded evidence of an access attempt and its result, not evidence of file contents being read.",
          event_ids: [libOpen.id, shadowOpen.id],
          process_instance_ids: [curlA, catp],
          pids: [28111, 28113],
          time_range: { start_ns: libOpen.timestampNs, end_ns: shadowOpen.timestampNs },
          related_findings: [],
          limitations: ["File contents are never captured; open results reflect the syscall outcome only."],
          next_steps: ["Review filesystem activity filters for failed opens and sensitive paths."],
          supporting_events: [
            {
              event_id: libOpen.id,
              timestamp_ns: libOpen.timestampNs,
              monotonic_ns: libOpen.monotonicNs,
              event_type: "file_open",
              pid: 28111,
              process_instance_id: curlA,
              comm: "curl",
              summary: "/lib/x86_64-linux-gnu/libcurl.so.4"
            },
            {
              event_id: shadowOpen.id,
              timestamp_ns: shadowOpen.timestampNs,
              monotonic_ns: shadowOpen.monotonicNs,
              event_type: "file_open",
              pid: 28113,
              process_instance_id: catp,
              comm: "cat",
              summary: "/etc/shadow (failed, EACCES)"
            }
          ],
          related_processes: [
            { process_instance_id: curlA, pid: 28111, comm: "curl", executable: "/usr/bin/curl", parent_process_instance_id: launcher, exit_observed: true },
            { process_instance_id: catp, pid: 28113, comm: "cat", executable: "/bin/cat", parent_process_instance_id: launcher, exit_observed: true }
          ],
          correlation: "cross_process"
        }
      ],
      limitations: [
        "Analysis is limited to persisted evidence.",
        "A finding is an observation, not a verdict.",
        "Connect success indicates the syscall attempt result, not an established session or data transfer."
      ],
      truncated: false
    };
  }

  return {
    schema_version: "syscall-analysis/v1",
    session_id: session.id,
    session_command: session.commandDisplay,
    session_scope: session.recordingScope,
    session_started_at_ns: session.startedAtNs,
    session_ended_at_ns: session.endedAtNs,
    evidence: {
      status: "complete",
      session_status: session.status,
      event_count: session.eventCount,
      process_count: session.processCount,
      ringbuf_lost_events: 0,
      userspace_dropped_events: 0,
      malformed_events: 0,
      filtered_events: session.filteredEvents,
      events_persist_failed: 0,
      unresolved_identity_count: 0,
      verification_assessment: session.verification?.assessment ?? null,
      may_be_incomplete: false,
      notes: ["Evidence completeness is qualified by target-tree attribution."]
    },
    rules_evaluated: rules,
    findings: [],
    limitations: ["Analysis is limited to persisted evidence.", "A finding is an observation, not a verdict."],
    truncated: false
  };
}

function verificationFor(sessionId: string): SessionVerificationReport {
  const session = sessions.find((item) => item.id === sessionId) ?? sessions[0];
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };

  if (session.id === "mock-interrupt-002") {
    return {
      session_id: session.id,
      verification_timestamp_ns: BASE_ONE + 24_000_000_000,
      database_schema_version: 5,
      session_status: session.status,
      assessment: "valid_but_incomplete",
      severity_counts: { info: 0, warning: 1, error: 0, critical: 0 },
      findings: [
        {
          code: "VER-COMPLETENESS",
          severity: "warning",
          title: "Capture ended before the target completed",
          detail: "The session is structurally valid, but the target lifetime was cut short by the capture boundary.",
          session_id: session.id,
          event_id: 32,
          process_instance_id: sleeper,
          evidence: ["session status: interrupted", "process instance mock-23944"],
          recommendation: "Treat post-boundary behavior as unobserved."
        }
      ],
      limitations: ["Verification does not prove authenticity or complete collection."]
    };
  }

  if (session.id === "mock-complex-003") {
    const events = eventsBySession[session.id] ?? [];
    const shadowOpen = events.find((e) => e.eventType === "file_open" && e.payload.kind === "file_open" && e.payload.path === "/etc/shadow");
    return {
      session_id: session.id,
      verification_timestamp_ns: BASE_THREE + 120_000_000,
      database_schema_version: 5,
      session_status: session.status,
      assessment: "valid",
      severity_counts: { info: 1, warning: 0, error: 0, critical: 0 },
      findings: [
        {
          code: "VER-EVIDENCE-NOTE",
          severity: "info",
          title: "Recorded failures are preserved as evidence",
          detail: "Failed connect attempts and a denied open of /etc/shadow were recorded with their syscall results. These are application/permission outcomes, not collection failures.",
          session_id: session.id,
          event_id: shadowOpen?.id ?? null,
          process_instance_id: catp,
          evidence: ["network_connect failures recorded", "file_open /etc/shadow errno=EACCES"],
          recommendation: "Interpret failed attempts in context of the recorded command and process tree."
        }
      ],
      limitations: ["Verification does not prove authenticity or complete collection."]
    };
  }

  return {
    session_id: session.id,
    verification_timestamp_ns: BASE_ONE + 24_000_000_000,
    database_schema_version: 5,
    session_status: session.status,
    assessment: "valid",
    severity_counts: { info: 0, warning: 0, error: 0, critical: 0 },
    findings: [],
    limitations: ["Verification does not prove authenticity or complete collection."]
  };
}

export function sessionDetail(sessionId: string): SessionDetail {
  const session = sessions.find((item) => item.id === sessionId);
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  const events = eventsBySession[session.id] ?? [];
  const counts = new Map<EventType, number>();
  for (const event of events) {
    counts.set(event.eventType, (counts.get(event.eventType) ?? 0) + 1);
  }
  return {
    session,
    stats: {
      eventCount: events.length,
      processCount: session.processCount,
      eventsPersisted: events.length,
      eventsByType: [...counts.entries()].map(([eventType, count]) => ({ eventType, count })),
      ringbufLostEvents: 0,
      userspaceDroppedEvents: 0,
      droppedEventsTotal: 0,
      malformedEvents: 0,
      filteredEvents: session.filteredEvents,
      eventsSelfFiltered: 0,
      eventsPersistFailed: 0,
      unresolvedIdentityCount: session.id === "mock-interrupt-002" ? 1 : 0,
      evidenceMayBeIncomplete: session.evidenceIncomplete || session.status === "interrupted",
      terminationReason: session.terminationReason,
      targetExitCode: session.targetExitCode,
      targetExitSignal: session.targetExitSignal
    }
  };
}

export function processTree(sessionId: string): ProcessTreeResponse {
  const tree = trees[sessionId];
  if (!tree) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  return tree;
}

export function sessionEvents(sessionId: string): EventView[] {
  return eventsBySession[sessionId] ?? [];
}

export function overview(recentLimit: number): OverviewResponse {
  const recent = sessions.slice(0, recentLimit);
  const findingCounts = sessions.reduce(
    (acc, s) => {
      const c = s.findingCounts ?? { informational: 0, low: 0, medium: 0, high: 0, critical: 0, total: 0 };
      acc.informational += c.informational;
      acc.low += c.low;
      acc.medium += c.medium;
      acc.high += c.high;
      acc.critical += c.critical;
      acc.total += c.total;
      return acc;
    },
    { informational: 0, low: 0, medium: 0, high: 0, critical: 0, total: 0 }
  );
  return {
    totalSessions: sessions.length,
    activeSessions: 0,
    completedSessions: sessions.filter((s) => s.status === "completed").length,
    interruptedSessions: sessions.filter((s) => s.status === "interrupted").length,
    recoveredSessions: 0,
    failedSessions: 0,
    sessionsWithLoss: 0,
    recentSessions: recent,
    recentFindingCounts: findingCounts,
    latestVerification: sessions[sessions.length - 1]?.verification ?? null
  };
}

export { analysisFor, verificationFor };

export function exportFor(sessionId: string): ExportResult {
  const session = sessions.find((item) => item.id === sessionId);
  if (!session) throw { code: "SESSION_NOT_FOUND", message: "Session not found in mock data." };
  return {
    sessionId: session.id,
    outputPath: `/mock/evidence/exports/${session.id}.json`,
    formatVersion: "syscall-export/v1",
    bytesWritten: 64_138,
    manifest: [
      {
        component: "analysis",
        format: "application/json",
        version: "syscall-analysis/v1",
        sha256: "87bdb0b871a038d20c979ff152a",
        byteLength: 9_603
      },
      {
        component: "events",
        format: "application/json",
        version: "1",
        sha256: "3c8dcb59497f10d4f7f9525057",
        byteLength: 44_763
      },
      {
        component: "manifest",
        format: "application/json",
        version: "1",
        sha256: "0871cbf767819413c686c9925",
        byteLength: 1_378
      },
      {
        component: "metadata",
        format: "application/json",
        version: "1",
        sha256: "f2bc1647c0e7969687af8ba5a8",
        byteLength: 839
      },
      {
        component: "process_instances",
        format: "application/json",
        version: "1",
        sha256: "4de7ae3656018dcf5f45da02",
        byteLength: 1_789
      },
      {
        component: "session",
        format: "application/json",
        version: "1",
        sha256: "4030ba5be888f2b14137a253",
        byteLength: 1_033
      },
      {
        component: "verification",
        format: "application/json",
        version: "1",
        sha256: "00cfb4f507f0bc43a46a65af",
        byteLength: 311
      }
    ],
    status: "exported"
  };
}

export function processFor(sessionId: string, processInstanceId: string): ProcessView | null {
  return trees[sessionId]?.processes.find((item) => item.processInstanceId === processInstanceId) ?? null;
}
