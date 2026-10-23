"""
ssd_lifeguard.write_hunter
~~~~~~~~~~~~~~~~~~~~~~~~~~
Real-Time High-Frequency Write Hunter.

Measures actual physical SSD write IOPS and throughput vs. per-process I/O write
activity, and scans recently modified files on C: to pinpoint background write culprits.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Tuple


@dataclass
class ProcessWriteDelta:
    pid: int
    name: str
    write_ops: int
    write_kb: float
    rate_kb_s: float


@dataclass
class RecentFileWrite:
    path: str
    size_kb: float
    last_write_time: str
    category: str


@dataclass
class WriteHuntResult:
    duration_sec: int
    physical_write_kb_s: float = 0.0
    physical_write_iops: float = 0.0
    total_process_write_kb_s: float = 0.0
    offload_interception_pct: float = 0.0
    top_processes: List[ProcessWriteDelta] = field(default_factory=list)
    recent_files: List[RecentFileWrite] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def classify_file_path(path_str: str) -> str:
    low = path_str.lower()
    if any(k in low for k in ("cache", "code cache", "gpucache", "shadercache", "d3dscache", "dxcache", "glcache")):
        return "Browser / GPU Shader Cache"
    if any(k in low for k in ("indexeddb", "leveldb", "local storage", "webstorage", "cookies")):
        return "Browser IndexedDB / Storage"
    if any(k in low for k in ("nvtopps", "larkshell", "kccsdkbak", "telemetry", ".log", ".evtx", "crashdumps")):
        return "Background Telemetry / Log"
    if any(k in low for k in ("pip", "npm-cache", "uv\\cache", "node-compile-cache")):
        return "Developer Package / Compile Cache"
    if "\\temp\\" in low or low.endswith(".tmp"):
        return "Temporary File"
    return "Application / User Data"


def run_write_hunt(duration_sec: int = 5, recent_minutes: int = 2) -> WriteHuntResult:
    """
    Sample physical disk IOPS/throughput and per-process write deltas over `duration_sec`,
    and scan files modified on C: within `recent_minutes`.
    """
    res = WriteHuntResult(duration_sec=duration_sec)
    if platform.system() != "Windows":
        return res

    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$p1 = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, WriteOperationCount, WriteTransferCount
$d = Get-Counter -Counter '\\LogicalDisk(C:)\\Disk Writes/sec', '\\LogicalDisk(C:)\\Disk Write Bytes/sec' -SampleInterval 1 -MaxSamples {max(1, duration_sec)}
$p2 = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, WriteOperationCount, WriteTransferCount

$iops = ($d.CounterSamples | Where-Object {{ $_.Path -match 'disk writes/sec' }} | Measure-Object CookedValue -Average).Average
$bps  = ($d.CounterSamples | Where-Object {{ $_.Path -match 'disk write bytes/sec' }} | Measure-Object CookedValue -Average).Average

$map1 = @{{}}
foreach ($p in $p1) {{ $map1[[int]$p.ProcessId] = $p }}
$procs = foreach ($p in $p2) {{
    $old = $map1[[int]$p.ProcessId]
    if ($old) {{
        $dOps = [int64]$p.WriteOperationCount - [int64]$old.WriteOperationCount
        $dBytes = [int64]$p.WriteTransferCount - [int64]$old.WriteTransferCount
        if ($dBytes -gt 0 -or $dOps -gt 0) {{
            [PSCustomObject]@{{
                pid = [int]$p.ProcessId
                name = [string]$p.Name
                write_ops = $dOps
                write_kb = [math]::Round($dBytes / 1KB, 2)
                rate_kb_s = [math]::Round($dBytes / 1KB / {max(1, duration_sec)}, 2)
            }}
        }}
    }}
}}
$topProcs = @($procs | Sort-Object write_kb -Descending | Select-Object -First 15)

[PSCustomObject]@{{
    physical_write_kb_s = [math]::Round($bps / 1KB, 2)
    physical_write_iops = [math]::Round($iops, 2)
    top_processes = $topProcs
}} | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=duration_sec + 15,
            creationflags=0x08000000 if platform.system() == "Windows" else 0,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout.strip())
            res.physical_write_kb_s = float(data.get("physical_write_kb_s") or 0.0)
            res.physical_write_iops = float(data.get("physical_write_iops") or 0.0)
            raw_procs = data.get("top_processes") or []
            if isinstance(raw_procs, dict):
                raw_procs = [raw_procs]
            for item in raw_procs:
                res.top_processes.append(
                    ProcessWriteDelta(
                        pid=int(item.get("pid", 0)),
                        name=str(item.get("name", "")),
                        write_ops=int(item.get("write_ops", 0)),
                        write_kb=float(item.get("write_kb", 0.0)),
                        rate_kb_s=float(item.get("rate_kb_s", 0.0)),
                    )
                )
            total_proc_rate = sum(p.rate_kb_s for p in res.top_processes)
            res.total_process_write_kb_s = round(total_proc_rate, 2)
            if total_proc_rate > res.physical_write_kb_s and total_proc_rate > 0:
                res.offload_interception_pct = round(
                    (1.0 - (res.physical_write_kb_s / total_proc_rate)) * 100.0, 1
                )
    except Exception:
        pass

    res.recent_files = scan_recent_modified_files(minutes=recent_minutes, limit=25)
    return res


def scan_recent_modified_files(minutes: int = 2, limit: int = 25) -> List[RecentFileWrite]:
    if platform.system() != "Windows":
        return []
    cutoff = time.time() - (minutes * 60)
    roots = [
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("APPDATA", ""),
        r"C:\ProgramData",
        r"C:\Windows\System32\winevt\Logs",
    ]
    found: List[ Tuple[float, str, float] ] = []
    for r in roots:
        if not r or not os.path.exists(r):
            continue
        for dirpath, dirnames, filenames in os.walk(r):
            # Skip ReparsePoints (junctions pointing to RAMDisk R:) so we only report physical C: writes
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(dirpath)
                if attrs != -1 and (attrs & 0x400):  # FILE_ATTRIBUTE_REPARSE_POINT
                    dirnames[:] = []
                    continue
            except Exception:
                pass
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    st = os.stat(fp, follow_symlinks=False)
                    if st.st_mtime >= cutoff:
                        found.append((st.st_mtime, fp, round(st.st_size / 1024.0, 1)))
                except OSError:
                    continue

    found.sort(key=lambda x: (x[2], x[0]), reverse=True)
    results: List[RecentFileWrite] = []
    for mtime, fp, sz_kb in found[:limit]:
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
        results.append(
            RecentFileWrite(
                path=fp,
                size_kb=sz_kb,
                last_write_time=ts_str,
                category=classify_file_path(fp),
            )
        )
    return results
