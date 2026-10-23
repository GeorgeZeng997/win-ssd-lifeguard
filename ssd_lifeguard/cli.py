"""
ssd_lifeguard.cli
~~~~~~~~~~~~~~~~~
Command-Line Interface for win-ssd-lifeguard.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .forensics import inspect_physical_drive
from .optimizer import (
    apply_ntfs_lastaccess_fix,
    apply_pagefile_fix,
    apply_sata_lpm_fix,
    check_protection_status,
    configure_over_provisioning,
    deploy_cache_junctions,
    deploy_dynamic_ramdisk,
    run_volume_retrim,
)
from .write_hunter import run_write_hunt


def _print_audit(drive_index: int, as_json: bool) -> int:
    rep = inspect_physical_drive(drive_index)
    if as_json:
        print(json.dumps(rep.to_dict(), indent=2))
        return 0

    print("=" * 76)
    print(f"  WIN-SSD-LIFEGUARD v{__version__} -- DEEP ATA/ACS-3 FORENSIC REPORT")
    print("=" * 76)
    print(f"  Physical Drive   : \\\\.\\PhysicalDrive{rep.drive_index}")
    print(f"  Model            : {rep.model}")
    print(f"  Serial Number    : {rep.serial_number}")
    print(f"  Firmware Rev     : {rep.firmware_rev}")
    print(f"  Capacity         : {rep.capacity_gb:.2f} GiB (TRIM Supported: {rep.trim_supported})")
    print("-" * 76)
    print(f"  Reported SMART Health : {rep.reported_health_pct}%")
    print(f"  True ACS-3 Health     : {rep.true_health_pct}% (Used Endurance: {rep.gp_log04.percentage_used_endurance}%)")
    print(f"  Fake SMART Detected   : {'YES (SPOOFED / LOCKED)' if rep.is_fake_smart else 'No'}")

    if rep.gp_log04.supported:
        g = rep.gp_log04
        print("-" * 76)
        print("  [ACS-3 GP Log 0x04 -- True Hardware Telemetry]")
        print(f"    Power-On Hours       : {g.power_on_hours:,} hrs ({g.power_on_resets:,} power cycles)")
        print(f"    Total Host Writes    : {g.host_writes_gib:,.2f} GiB ({g.write_commands:,} write cmds, avg {g.avg_write_size_kb} KB)")
        print(f"    Total Host Reads     : {g.host_reads_gib:,.2f} GiB ({g.read_commands:,} read cmds)")
        print(f"    SATA Hardware Resets : {g.sata_hardware_resets:,} resets (ASR: {g.sata_asr_events:,}, CRC: {g.sata_crc_errors:,})")

    if rep.vendor_nand.detected:
        v = rep.vendor_nand
        print("-" * 76)
        print("  [Vendor Log 0xE0 -- Hidden FTL & NAND Erase Telemetry]")
        print(f"    Controller Architecture : {v.controller_hint}")
        print(f"    Raw NAND Flash ID       : {v.flash_id_hex} ({v.flash_description})")
        print(f"    Block Erase Counts      : Max = {v.max_erase_count} | Min = {v.min_erase_count} | Avg = {v.avg_erase_count}")
        print(f"    Static Wear Skew Ratio  : {v.erase_skew_ratio}x (Max / Avg)")
        print(f"    Bad Block Count         : Factory = {v.factory_bad_blocks} | Grown = {v.grown_bad_blocks}")

    if rep.anomalies:
        print("-" * 76)
        print("  [FORENSIC ANOMALIES & WARNINGS]")
        for a in rep.anomalies:
            print(f"    [{a.severity}] {a.code}: {a.title}")
            print(f"      -> {a.detail}")

    print("=" * 76)
    return 0


def _print_hunt(duration: int, minutes: int, as_json: bool) -> int:
    res = run_write_hunt(duration_sec=duration, recent_minutes=minutes)
    if as_json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    print("=" * 76)
    print(f"  REAL-TIME WRITE HUNTER ({res.duration_sec}s Sample Window)")
    print("=" * 76)
    print(f"  Physical SSD Write Rate : {res.physical_write_kb_s:,.2f} KB/s ({res.physical_write_iops:.2f} IOPS)")
    print(f"  Total Process Write I/O : {res.total_process_write_kb_s:,.2f} KB/s")
    print(f"  RAMDisk / Cache Offload : {res.offload_interception_pct:.1f}% intercepted before hitting SSD")
    print("-" * 76)
    print(f"  {'PID':<8} {'Process Name':<28} {'Write Ops':>10} {'Write KB':>12} {'Rate (KB/s)':>12}")
    for p in res.top_processes:
        print(f"  {p.pid:<8} {p.name[:27]:<28} {p.write_ops:>10} {p.write_kb:>12.2f} {p.rate_kb_s:>12.2f}")

    if res.recent_files:
        print("-" * 76)
        print(f"  [Recently Modified Physical Files on C: (Last {minutes} min)]")
        for f in res.recent_files[:15]:
            print(f"    [{f.category}] {f.size_kb:>8.1f} KB | {f.last_write_time} | {f.path}")
    print("=" * 76)
    return 0


def _print_status(as_json: bool) -> int:
    st = check_protection_status()
    if as_json:
        print(json.dumps(st.to_dict(), indent=2))
        return 0

    print("=" * 76)
    print("  7-LAYER SSD LIFESPAN PROTECTION STATUS")
    print("=" * 76)
    print(f"  [Layer 1] SATA LPM (HIPM/DIPM Disabled) : {'ACTIVE' if st.sata_lpm_disabled else 'NOT CONFIGURED'}")
    print(f"  [Layer 2] NTFS LastAccess Disabled      : {'ACTIVE' if st.ntfs_lastaccess_disabled else 'NOT CONFIGURED'}")
    print(f"  [Layer 3] Pagefile Right-Sized          : {st.pagefile_allocated_mb} MB ({'OPTIMIZED' if st.pagefile_optimized else 'BLOATED'})")
    print(f"  [Layer 5] Dynamic RAMDisk ({st.ramdisk_drive})          : {'MOUNTED' if st.ramdisk_mounted else 'NOT MOUNTED'} "
          f"({st.ramdisk_free_gb}/{st.ramdisk_total_gb} GB free, RAM used: {st.ramdisk_working_set_mb} MB)")
    print(f"  [Layer 5] TEMP/TMP Redirected to R:     : {'YES' if st.temp_redirected else 'NO'}")
    print(f"  [Layer 7] Hardware Over-Provisioning OP : {st.unallocated_op_gb:.2f} GB Unallocated")
    print("-" * 76)
    print("  [Layer 6] High-Frequency Cache & Telemetry NTFS Junctions:")
    for j in st.junctions:
        print(f"    - {j.name:<32} : {j.status}")
    print("=" * 76)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="win-ssd-lifeguard",
        description=(
            "Deep ATA/ACS-3 SSD Forensics, Fake SMART Detector, Real-Time Write Hunter, "
            "and 7-Layer SSD Lifespan Extension Suite."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_audit = sub.add_parser("audit", help="Run deep ATA/ACS-3/Vendor forensic inspection & Fake SMART check")
    p_audit.add_argument("--drive", type=int, default=0, help="PhysicalDrive index (default: 0)")
    p_audit.add_argument("--json", action="store_true", help="Output report as JSON")

    p_hunt = sub.add_parser("hunt", help="Sample real-time physical SSD writes vs process writes & recent files")
    p_hunt.add_argument("--duration", type=int, default=5, help="Sample window in seconds (default: 5)")
    p_hunt.add_argument("--minutes", type=int, default=2, help="Lookback window in minutes for modified files (default: 2)")
    p_hunt.add_argument("--json", action="store_true", help="Output result as JSON")

    p_status = sub.add_parser("status", help="Check current status of all 7 SSD protection layers")
    p_status.add_argument("--json", action="store_true", help="Output status as JSON")

    p_opt = sub.add_parser("optimize", help="Apply OS & power SSD lifespan protections (Layers 1-4)")
    p_opt.add_argument("--all", action="store_true", help="Apply SATA LPM, NTFS LastAccess, Pagefile, and ReTrim fixes")
    p_opt.add_argument("--sata-lpm", action="store_true", help="Disable SATA HIPM/DIPM link power management")
    p_opt.add_argument("--lastaccess", action="store_true", help="Disable NTFS LastAccess timestamp updates")
    p_opt.add_argument("--pagefile-mb", type=int, default=0, help="Set fixed pagefile.sys size in MB (e.g. 4096)")
    p_opt.add_argument("--retrim", action="store_true", help="Run ATA ReTrim on NTFS volumes")

    p_ram = sub.add_parser("ramdisk", help="Deploy Dynamic RAMDisk and offload 19 high-write cache directories (Layers 5-6)")
    p_ram.add_argument("--size-gb", type=int, default=16, help="Dynamic RAMDisk max size in GB (default: 16)")
    p_ram.add_argument("--drive", type=str, default="R", help="Drive letter for RAMDisk (default: R)")
    p_ram.add_argument("--junctions", action="store_true", help="Also migrate browser/dev/telemetry caches via NTFS Junctions")

    p_op = sub.add_parser("op", help="Reserve unallocated Hardware Over-Provisioning (OP) space (Layer 7)")
    p_op.add_argument("--drive", type=str, default="E", help="Tail partition drive letter to shrink (default: E)")
    p_op.add_argument("--size-gb", type=int, default=100, help="Unallocated OP size in GB to reserve (default: 100)")

    sub.add_parser("gui", help="Launch the Desktop GUI")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command or args.command == "gui":
        from .gui import launch_gui
        launch_gui()
        return 0

    if args.command == "audit":
        return _print_audit(args.drive, args.json)
    if args.command == "hunt":
        return _print_hunt(args.duration, args.minutes, args.json)
    if args.command == "status":
        return _print_status(args.json)
    if args.command == "optimize":
        if args.all or args.sata_lpm:
            ok, msg = apply_sata_lpm_fix()
            print(f"[{'OK' if ok else 'ERR'}] {msg}")
        if args.all or args.lastaccess:
            ok, msg = apply_ntfs_lastaccess_fix()
            print(f"[{'OK' if ok else 'ERR'}] {msg}")
        if args.all or args.pagefile_mb > 0:
            mb = args.pagefile_mb if args.pagefile_mb > 0 else 4096
            ok, msg = apply_pagefile_fix(mb)
            print(f"[{'OK' if ok else 'ERR'}] {msg}")
        if args.all or args.retrim:
            ok, msg = run_volume_retrim()
            print(f"[{'OK' if ok else 'ERR'}] {msg}")
        return 0
    if args.command == "ramdisk":
        ok, msg = deploy_dynamic_ramdisk(size_gb=args.size_gb, drive_letter=args.drive)
        print(f"[{'OK' if ok else 'ERR'}] {msg}")
        if args.junctions:
            ok2, msg2, _ = deploy_cache_junctions(f"{args.drive.rstrip(':')}:\\Temp")
            print(f"[{'OK' if ok2 else 'ERR'}] {msg2}")
        return 0
    if args.command == "op":
        ok, msg = configure_over_provisioning(shrink_drive=args.drive, op_size_gb=args.size_gb)
        print(f"[{'OK' if ok else 'ERR'}] {msg}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
