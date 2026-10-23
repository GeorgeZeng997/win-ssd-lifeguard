"""
ssd_lifeguard.optimizer
~~~~~~~~~~~~~~~~~~~~~~~
7-Layer SSD Rescue & Lifespan Extension Engine for DRAM-less and High-Wear SSDs.

Layers:
  1. Disable SATA AHCI Link Power Management (HIPM/DIPM/Adaptive -> Active 0)
  2. Disable NTFS LastAccess Timestamp Updates (DisableLastAccess = 1)
  3. Right-Size Bloated Pagefile (e.g. 64 GB -> Fixed 4096 MB on High-RAM Hosts)
  4. Multi-Volume ATA ReTrim (Optimize-Volume -ReTrim)
  5. Dynamic RAMDisk (R:) Deployment via ImDisk Toolkit (RamDyn + ImDiskRD + TEMP/TMP Redirect)
  6. High-Frequency Cache & Telemetry NTFS Junction Offloader (19 Directories + Boot Initializer)
  7. TRIM-First Non-Destructive Hardware Over-Provisioning (OP) Partition Shrinker
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


@dataclass
class JunctionTargetSpec:
    category: str
    name: str
    link_path: str
    ramdisk_subpath: str
    status: str = "Not Linked"


@dataclass
class SystemProtectionStatus:
    sata_lpm_disabled: bool = False
    ntfs_lastaccess_disabled: bool = False
    pagefile_allocated_mb: int = 0
    pagefile_optimized: bool = False
    ramdisk_mounted: bool = False
    ramdisk_drive: str = "R:"
    ramdisk_total_gb: float = 0.0
    ramdisk_free_gb: float = 0.0
    ramdisk_working_set_mb: float = 0.0
    temp_redirected: bool = False
    unallocated_op_gb: float = 0.0
    junctions: List[JunctionTargetSpec] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _run_ps(script: str, timeout: int = 60) -> Tuple[int, str, str]:
    if platform.system() != "Windows":
        return 1, "", "Windows required"
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=0x08000000,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def get_default_junction_specs(ramdisk_temp: str = r"R:\Temp") -> List[JunctionTargetSpec]:
    local_app = os.environ.get("LOCALAPPDATA", r"C:\Users\Administrator\AppData\Local")
    roaming_app = os.environ.get("APPDATA", r"C:\Users\Administrator\AppData\Roaming")
    specs = [
        JunctionTargetSpec("System Temp", "Windows System Temp", r"C:\Windows\Temp", rf"{ramdisk_temp}\WinTemp"),
        JunctionTargetSpec("Browser Cache", "Chrome HTTP Cache", rf"{local_app}\Google\Chrome\User Data\Default\Cache", rf"{ramdisk_temp}\ChromeCache\Cache"),
        JunctionTargetSpec("Browser Cache", "Chrome JS/Wasm Code Cache", rf"{local_app}\Google\Chrome\User Data\Default\Code Cache", rf"{ramdisk_temp}\ChromeCache\Code Cache"),
        JunctionTargetSpec("Browser Cache", "Chrome GPU Cache", rf"{local_app}\Google\Chrome\User Data\Default\GPUCache", rf"{ramdisk_temp}\ChromeCache\GPUCache"),
        JunctionTargetSpec("Browser Cache", "Chrome Shader Cache", rf"{local_app}\Google\Chrome\User Data\ShaderCache", rf"{ramdisk_temp}\ChromeCache\ShaderCache"),
        JunctionTargetSpec("Browser Cache", "Chrome GrShader Cache", rf"{local_app}\Google\Chrome\User Data\GrShaderCache", rf"{ramdisk_temp}\ChromeCache\GrShaderCache"),
        JunctionTargetSpec("Browser Cache", "Edge HTTP Cache", rf"{local_app}\Microsoft\Edge\User Data\Default\Cache", rf"{ramdisk_temp}\EdgeCache\Cache"),
        JunctionTargetSpec("Browser Cache", "Edge JS/Wasm Code Cache", rf"{local_app}\Microsoft\Edge\User Data\Default\Code Cache", rf"{ramdisk_temp}\EdgeCache\Code Cache"),
        JunctionTargetSpec("Browser Cache", "Edge GPU Cache", rf"{local_app}\Microsoft\Edge\User Data\Default\GPUCache", rf"{ramdisk_temp}\EdgeCache\GPUCache"),
        JunctionTargetSpec("Dev Package Cache", "Python Pip Cache", rf"{local_app}\pip\Cache", rf"{ramdisk_temp}\PipCache"),
        JunctionTargetSpec("Dev Package Cache", "Node.js NPM Cache", rf"{local_app}\npm-cache", rf"{ramdisk_temp}\NpmCache"),
        JunctionTargetSpec("Dev Package Cache", "Python uv Cache", rf"{local_app}\uv\cache", rf"{ramdisk_temp}\UvCache"),
        JunctionTargetSpec("GPU & Crash Cache", "Windows CrashDumps", rf"{local_app}\CrashDumps", rf"{ramdisk_temp}\CrashDumps"),
        JunctionTargetSpec("GPU & Crash Cache", "Direct3D Shader Cache", rf"{local_app}\D3DSCache", rf"{ramdisk_temp}\D3DSCache"),
        JunctionTargetSpec("GPU & Crash Cache", "NVIDIA DirectX Cache", rf"{local_app}\NVIDIA\DXCache", rf"{ramdisk_temp}\NVIDIA_DXCache"),
        JunctionTargetSpec("GPU & Crash Cache", "NVIDIA OpenGL Cache", rf"{local_app}\NVIDIA\GLCache", rf"{ramdisk_temp}\NVIDIA_GLCache"),
        JunctionTargetSpec("Telemetry & Logs", "NVIDIA nvtopps Telemetry Log", r"C:\ProgramData\NVIDIA Corporation\nvtopps\nct", rf"{ramdisk_temp}\NVIDIA_nvtopps_nct"),
        JunctionTargetSpec("Telemetry & Logs", "WPS Office Background SDK DB", rf"{roaming_app}\kingsoft\office6\kccsdkbak", rf"{ramdisk_temp}\WPS_kccsdkbak"),
        JunctionTargetSpec("Telemetry & Logs", "Feishu / Lark SDK Telemetry Log", rf"{roaming_app}\LarkShell\sdk_storage\log", rf"{ramdisk_temp}\LarkShell_log"),
    ]
    for s in specs:
        if os.path.exists(s.link_path):
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(s.link_path)
                if attrs != -1 and (attrs & 0x400):
                    s.status = "Active (NTFS Junction -> RAMDisk)"
                else:
                    s.status = "Physical Directory on SSD"
            except Exception:
                s.status = "Unknown"
        else:
            s.status = "Not Present"
    return specs


def check_protection_status() -> SystemProtectionStatus:
    status = SystemProtectionStatus()
    status.junctions = get_default_junction_specs()
    if platform.system() != "Windows":
        return status

    ps = """
$ErrorActionPreference = 'SilentlyContinue'
$lastAcc = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem').NtfsDisableLastAccessUpdate
$pf = Get-CimInstance Win32_PageFileUsage | Select-Object -First 1
$rVol = Get-PSDrive R -ErrorAction SilentlyContinue
$ramDyn = Get-Process RamDyn -ErrorAction SilentlyContinue | Select-Object -First 1
$usrTemp = (Get-ItemProperty 'HKCU:\\Environment').TEMP
$disk0 = Get-Disk -Number 0 -ErrorAction SilentlyContinue
$lpm = powercfg /query SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60

[PSCustomObject]@{
    ntfs_lastaccess_raw = $lastAcc
    pagefile_mb = if ($pf) { [int]$pf.AllocatedBaseSize } else { 0 }
    ramdisk_mounted = [bool]($null -ne $rVol)
    ramdisk_free_gb = if ($rVol) { [math]::Round($rVol.Free / 1GB, 2) } else { 0 }
    ramdisk_used_gb = if ($rVol) { [math]::Round($rVol.Used / 1GB, 2) } else { 0 }
    ramdyn_ws_mb = if ($ramDyn) { [math]::Round($ramDyn.WorkingSet64 / 1MB, 2) } else { 0 }
    user_temp = [string]$usrTemp
    op_gb = if ($disk0) { [math]::Round($disk0.LargestFreeExtent / 1GB, 2) } else { 0 }
    lpm_active_zero = [bool]($lpm -match '0x00000000')
} | ConvertTo-Json -Compress
"""
    rc, out, _ = _run_ps(ps, timeout=20)
    if rc == 0 and out:
        try:
            d = json.loads(out)
            raw_la = int(d.get("ntfs_lastaccess_raw") or 0)
            status.ntfs_lastaccess_disabled = (raw_la & 0x1) == 1
            status.pagefile_allocated_mb = int(d.get("pagefile_mb") or 0)
            status.pagefile_optimized = 0 < status.pagefile_allocated_mb <= 8192
            status.ramdisk_mounted = bool(d.get("ramdisk_mounted"))
            free_gb = float(d.get("ramdisk_free_gb") or 0.0)
            used_gb = float(d.get("ramdisk_used_gb") or 0.0)
            status.ramdisk_free_gb = free_gb
            status.ramdisk_total_gb = round(free_gb + used_gb, 2)
            status.ramdisk_working_set_mb = float(d.get("ramdyn_ws_mb") or 0.0)
            status.temp_redirected = str(d.get("user_temp", "")).upper().startswith("R:\\")
            status.unallocated_op_gb = float(d.get("op_gb") or 0.0)
            status.sata_lpm_disabled = bool(d.get("lpm_active_zero"))
        except Exception:
            pass
    return status


def apply_sata_lpm_fix() -> Tuple[bool, str]:
    """Layer 1: Lock SATA AHCI Link Power Management (HIPM/DIPM/Adaptive) to Active (0)."""
    ps = """
powercfg -attributes 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 -ATTRIB_HIDE
powercfg -attributes 0012ee47-9041-4b5d-9b77-535fba8b1442 dab60367-53fe-4fbc-825e-521d069d2456 -ATTRIB_HIDE
powercfg /setacvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 0
powercfg /setdcvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 0
powercfg /setacvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 dab60367-53fe-4fbc-825e-521d069d2456 0
powercfg /setdcvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 dab60367-53fe-4fbc-825e-521d069d2456 0
powercfg /setacvalueindex SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg /setactive SCHEME_CURRENT
"""
    rc, _, err = _run_ps(ps)
    if rc == 0:
        return True, "SATA AHCI Link Power Management (HIPM/DIPM/Adaptive) locked to Active (0)."
    return False, f"Failed to set SATA LPM policy: {err}"


def apply_ntfs_lastaccess_fix() -> Tuple[bool, str]:
    """Layer 2: Disable NTFS LastAccess updates and verify TRIM is enabled."""
    ps = """
fsutil behavior set DisableLastAccess 1
fsutil behavior set DisableDeleteNotification 0
"""
    rc, out, err = _run_ps(ps)
    if rc == 0:
        return True, f"NTFS LastAccess disabled & TRIM verified. ({out})"
    return False, err or out


def apply_pagefile_fix(size_mb: int = 4096) -> Tuple[bool, str]:
    """Layer 3: Set C:\\pagefile.sys to a fixed size (default 4096 MB)."""
    ps = f"""
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.AutomaticManagedPagefile) {{
    Set-CimInstance -InputObject $cs -Property @{{AutomaticManagedPagefile=$false}}
}}
$pf = Get-CimInstance Win32_PageFileSetting -Filter "Name='C:\\\\pagefile.sys'"
if ($pf) {{
    Set-CimInstance -InputObject $pf -Property @{{InitialSize={size_mb}; MaximumSize={size_mb}}}
}} else {{
    New-CimInstance -ClassName Win32_PageFileSetting -Property @{{Name='C:\\pagefile.sys'; InitialSize={size_mb}; MaximumSize={size_mb}}} | Out-Null
}}
"""
    rc, _, err = _run_ps(ps)
    if rc == 0:
        return True, f"C:\\pagefile.sys configured to fixed {size_mb} MB (takes full effect after reboot)."
    return False, f"Failed to configure pagefile: {err}"


def run_volume_retrim(drives: Optional[List[str]] = None) -> Tuple[bool, str]:
    """Layer 4: Execute ATA ReTrim across specified NTFS volumes."""
    if not drives:
        drives = ["C", "D", "E"]
    letters = ",".join(f"'{d.rstrip(':')}'" for d in drives)
    ps = f"""
$vols = Get-Volume | Where-Object {{ $_.DriveLetter -in @({letters}) -and $_.FileSystem -eq 'NTFS' }}
foreach ($v in $vols) {{
    Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -Verbose
}}
"""
    rc, out, err = _run_ps(ps, timeout=180)
    if rc == 0:
        return True, f"Completed ATA ReTrim across volumes {', '.join(drives)}."
    return False, err or out


def deploy_dynamic_ramdisk(size_gb: int = 16, drive_letter: str = "R") -> Tuple[bool, str]:
    """
    Layer 5: Configure and mount a Dynamic RAMDisk via ImDisk Toolkit (`RamDyn.exe` + `ImDiskRD` service)
    and redirect User/System TEMP & TMP environment variables to `<drive_letter>:\\Temp`.
    """
    dl = drive_letter.rstrip(":").upper()
    if not os.path.exists(r"C:\Program Files\ImDisk\RamDyn.exe"):
        return False, "ImDisk Toolkit is not installed at C:\\Program Files\\ImDisk. Please install ImDisk Toolkit first."

    ps = f"""
$reg = 'HKLM:\\SOFTWARE\\ImDisk'
New-Item -Path $reg -Force | Out-Null
$dwords = @{{
    'DriveSize' = {size_gb}; 'Unit' = 2; 'Dynamic' = 1; 'FileSystem' = 0;
    'WinBoot' = 1; 'TempFolder' = 1; 'Cluster' = 0; 'QuickFormat' = 1;
    'Awealloc' = 0; 'DynMethod' = 0; 'CleanRatio' = 10; 'CleanTimer' = 10;
    'MaxActivity' = 10; 'BlockSize' = 20; 'RDUseMP' = 0;
    '{dl}_DriveSize' = {size_gb}; '{dl}_Unit' = 2; '{dl}_Dynamic' = 1;
    '{dl}_FileSystem' = 0; '{dl}_TempFolder' = 1; '{dl}_Cluster' = 0;
    '{dl}_QuickFormat' = 1; '{dl}_Awealloc' = 0; '{dl}_DynMethod' = 0;
    '{dl}_CleanRatio' = 10; '{dl}_CleanTimer' = 10; '{dl}_MaxActivity' = 10;
    '{dl}_BlockSize' = 20
}}
foreach ($k in $dwords.Keys) {{
    Set-ItemProperty -Path $reg -Name $k -Value $dwords[$k] -Type DWord
}}
$strings = @{{
    'WantedDrive' = '{dl}'; 'Label' = 'RAMDisk'; '{dl}_Label' = 'RAMDisk';
    '{dl}_RDMountPoint' = ''; '{dl}_ImageFile' = ''; '{dl}_AddParam' = ''
}}
foreach ($k in $strings.Keys) {{
    Set-ItemProperty -Path $reg -Name $k -Value $strings[$k] -Type String
}}
Set-ItemProperty -Path 'HKCU:\\Environment' -Name 'TEMP' -Value '{dl}:\\Temp' -Type ExpandString
Set-ItemProperty -Path 'HKCU:\\Environment' -Name 'TMP' -Value '{dl}:\\Temp' -Type ExpandString
Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name 'TEMP' -Value '{dl}:\\Temp' -Type ExpandString
Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name 'TMP' -Value '{dl}:\\Temp' -Type ExpandString
sc.exe config ImDiskRD start= auto | Out-Null
if (-not (Test-Path '{dl}:\\Temp')) {{
    sc.exe start ImDiskRD | Out-Null
    Start-Sleep -Seconds 3
}}
"""
    rc, _, err = _run_ps(ps, timeout=30)
    if rc == 0:
        return True, f"Configured {size_gb} GB Dynamic RAMDisk ({dl}:) and redirected TEMP/TMP to {dl}:\\Temp."
    return False, f"Failed to configure Dynamic RAMDisk: {err}"


def deploy_cache_junctions(ramdisk_temp: str = r"R:\Temp") -> Tuple[bool, str, List[JunctionTargetSpec]]:
    """
    Layer 6: Create target cache folders on RAMDisk, migrate 19 high-frequency browser,
    package-manager, shader, and telemetry directories to NTFS Junctions (`mklink /J`),
    and install the boot-time `init_ramdisk_dirs.cmd` (`R_RunObject`) hook.
    """
    specs = get_default_junction_specs(ramdisk_temp)
    if platform.system() != "Windows":
        return False, "Windows required", specs

    mkdir_lines = ['@echo off']
    for s in specs:
        os.makedirs(s.ramdisk_subpath, exist_ok=True)
        mkdir_lines.append(f'mkdir "{s.ramdisk_subpath}" 2>nul')

    migrated_count = 0
    in_use_count = 0
    for s in specs:
        link = s.link_path
        target = s.ramdisk_subpath
        parent = os.path.dirname(link)
        if not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

        if os.path.exists(link):
            attrs = ctypes.windll.kernel32.GetFileAttributesW(link)
            if attrs != -1 and (attrs & 0x400):
                s.status = "Active (NTFS Junction -> RAMDisk)"
                migrated_count += 1
                continue
            bak = f"{link}_old_bak"
            try:
                if os.path.exists(bak):
                    shutil.rmtree(bak, ignore_errors=True)
                os.rename(link, bak)
                subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True, creationflags=0x08000000)
                shutil.rmtree(bak, ignore_errors=True)
                s.status = "Migrated -> NTFS Junction"
                migrated_count += 1
            except OSError:
                s.status = "In-Use (Scheduled for Boot Junction)"
                in_use_count += 1
                mkdir_lines.append(f'fsutil reparsepoint query "{link}" >nul 2>&1')
                mkdir_lines.append("if errorlevel 1 (")
                mkdir_lines.append(f'    rd /s /q "{link}" 2>nul')
                mkdir_lines.append(f'    mklink /J "{link}" "{target}" >nul 2>&1')
                mkdir_lines.append(")")
        else:
            subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True, creationflags=0x08000000)
            s.status = "Created -> NTFS Junction"
            migrated_count += 1

    init_cmd_path = r"C:\Program Files\ImDisk\init_ramdisk_dirs.cmd"
    if os.path.exists(r"C:\Program Files\ImDisk"):
        with open(init_cmd_path, "w", encoding="ascii", errors="ignore", newline="\r\n") as f:
            f.write("\n".join(mkdir_lines) + "\n")
        _run_ps(
            f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\ImDisk' -Name 'RunObject' -Value '{init_cmd_path}' -Type String; "
            f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\ImDisk' -Name 'R_RunObject' -Value '{init_cmd_path}' -Type String"
        )

    msg = f"Offloaded {migrated_count}/{len(specs)} high-frequency cache/telemetry directories to {ramdisk_temp} ({in_use_count} queued for boot)."
    return True, msg, specs


def configure_over_provisioning(shrink_drive: str = "E", op_size_gb: int = 100) -> Tuple[bool, str]:
    """
    Layer 7: Perform ATA ReTrim on `shrink_drive` first, then non-destructively shrink
    the partition by `op_size_gb` GB to create a clean hardware Over-Provisioning (OP) pool.
    """
    dl = shrink_drive.rstrip(":").upper()
    ps = f"""
$ErrorActionPreference = 'Stop'
Optimize-Volume -DriveLetter {dl} -ReTrim
$part = Get-Partition -DriveLetter {dl}
$sup = Get-PartitionSupportedSize -DriveLetter {dl}
$target = $part.Size - ({op_size_gb} * 1GB)
if ($target -lt $sup.SizeMin) {{
    throw "Requested shrink ({op_size_gb} GB) exceeds available movable space on {dl}:."
}}
Resize-Partition -DriveLetter {dl} -Size $target
"""
    rc, _, err = _run_ps(ps, timeout=180)
    if rc == 0:
        return True, f"TRIMmed {dl}: and reserved {op_size_gb} GB unallocated Hardware Over-Provisioning (OP) space."
    return False, f"Failed to shrink {dl}: for OP: {err}"
