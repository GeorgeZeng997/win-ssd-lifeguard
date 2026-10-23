"""
ssd_lifeguard.gui
~~~~~~~~~~~~~~~~~
Dark-Themed Desktop GUI for win-ssd-lifeguard.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from . import __version__
from .forensics import DriveForensicReport, inspect_physical_drive, list_physical_drives
from .optimizer import (
    SystemProtectionStatus,
    apply_ntfs_lastaccess_fix,
    apply_pagefile_fix,
    apply_sata_lpm_fix,
    check_protection_status,
    configure_over_provisioning,
    deploy_cache_junctions,
    deploy_dynamic_ramdisk,
    run_volume_retrim,
)
from .write_hunter import WriteHuntResult, run_write_hunt

BG_DARK = "#0f172a"
BG_CARD = "#1e293b"
BG_INPUT = "#334155"
FG_TEXT = "#f8fafc"
FG_MUTED = "#94a3b8"
ACCENT_BLUE = "#38bdf8"
ACCENT_GREEN = "#22c55e"
ACCENT_AMBER = "#f59e0b"
ACCENT_RED = "#ef4444"


class SSDLifeguardApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"Win-SSD-Lifeguard v{__version__} — Deep SSD Forensics & 7-Layer Lifespan Suite")
        self.root.geometry("1180x780")
        self.root.minsize(1020, 680)
        self.root.configure(bg=BG_DARK)

        self.last_report: Optional[DriveForensicReport] = None
        self.last_hunt: Optional[WriteHuntResult] = None
        self.last_status: Optional[SystemProtectionStatus] = None

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self._build_statusbar()

        self.root.after(200, self.refresh_all_async)

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG_DARK, foreground=FG_TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG_DARK)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT)
        style.configure("Card.TLabel", background=BG_CARD, foreground=FG_TEXT)
        style.configure("Muted.TLabel", background=BG_DARK, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=BG_CARD,
            foreground=FG_MUTED,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT_BLUE)],
            foreground=[("selected", "#0f172a")],
        )
        style.configure(
            "Accent.TButton",
            background=ACCENT_BLUE,
            foreground="#0f172a",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 6),
        )
        style.map("Accent.TButton", background=[("active", "#7dd3fc")])
        style.configure(
            "Treeview",
            background=BG_CARD,
            fieldbackground=BG_CARD,
            foreground=FG_TEXT,
            rowheight=26,
            borderwidth=0,
            font=("Consolas", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=BG_INPUT,
            foreground=FG_TEXT,
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#0284c7")])

    def _build_header(self) -> None:
        hdr = ttk.Frame(self.root, padding=(18, 12))
        hdr.pack(fill="x")
        title_lbl = tk.Label(
            hdr,
            text="WIN-SSD-LIFEGUARD",
            bg=BG_DARK,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 16, "bold"),
        )
        title_lbl.pack(side="left")
        sub_lbl = tk.Label(
            hdr,
            text="  |  ATA/ACS-3 Deep Forensics • Fake SMART Detector • Write Hunter • Dynamic RAMDisk & OP Suite",
            bg=BG_DARK,
            fg=FG_MUTED,
            font=("Segoe UI", 10),
        )
        sub_lbl.pack(side="left", padx=(6, 0))

        btn_refresh = ttk.Button(hdr, text="Refresh All Telemetry", style="Accent.TButton", command=self.refresh_all_async)
        btn_refresh.pack(side="right")

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        self.tab_forensics = ttk.Frame(self.notebook, padding=12)
        self.tab_hunter = ttk.Frame(self.notebook, padding=12)
        self.tab_ramdisk = ttk.Frame(self.notebook, padding=12)
        self.tab_rescue = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_forensics, text=" 1. Deep Forensics & Fake SMART ")
        self.notebook.add(self.tab_hunter, text=" 2. Real-Time Write Hunter ")
        self.notebook.add(self.tab_ramdisk, text=" 3. Dynamic RAMDisk & Cache Junctions ")
        self.notebook.add(self.tab_rescue, text=" 4. 7-Layer SSD Rescue & Hardware OP ")

        self._init_forensics_tab()
        self._init_hunter_tab()
        self._init_ramdisk_tab()
        self._init_rescue_tab()

    def _make_card(self, parent: tk.Widget, title: str, initial_val: str, sub: str = "") -> tuple[tk.Label, tk.Label]:
        frame = tk.Frame(parent, bg=BG_CARD, padx=14, pady=10, highlightthickness=1, highlightbackground=BG_INPUT)
        frame.pack(side="left", fill="both", expand=True, padx=5)
        tk.Label(frame, text=title, bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        val_lbl = tk.Label(frame, text=initial_val, bg=BG_CARD, fg=ACCENT_BLUE, font=("Segoe UI", 14, "bold"))
        val_lbl.pack(anchor="w", pady=(4, 2))
        sub_lbl = tk.Label(frame, text=sub, bg=BG_CARD, fg=FG_TEXT, font=("Segoe UI", 9))
        sub_lbl.pack(anchor="w")
        return val_lbl, sub_lbl

    def _init_forensics_tab(self) -> None:
        top_bar = ttk.Frame(self.tab_forensics)
        top_bar.pack(fill="x", pady=(0, 8))
        ttk.Label(top_bar, text="Physical Drive:").pack(side="left")
        drives = [f"PhysicalDrive{i}" for i in list_physical_drives()]
        self.drive_var = tk.StringVar(value=drives[0])
        cb = ttk.Combobox(top_bar, textvariable=self.drive_var, values=drives, width=18, state="readonly")
        cb.pack(side="left", padx=8)
        ttk.Button(top_bar, text="Run Deep ATA/ACS-3 Scan", style="Accent.TButton", command=self.run_forensic_scan_async).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Export JSON Report", command=self.export_forensic_json).pack(side="right")

        cards_row = ttk.Frame(self.tab_forensics)
        cards_row.pack(fill="x", pady=6)
        self.lbl_health_val, self.lbl_health_sub = self._make_card(cards_row, "REPORTED vs TRUE HEALTH", "-- / --", "Awaiting scan...")
        self.lbl_skew_val, self.lbl_skew_sub = self._make_card(cards_row, "NAND ERASE SKEW (MAX / AVG)", "--", "Vendor Log 0xE0")
        self.lbl_reset_val, self.lbl_reset_sub = self._make_card(cards_row, "SATA HARDWARE RESETS", "--", "ACS-3 GP Log 0x04")
        self.lbl_nand_val, self.lbl_nand_sub = self._make_card(cards_row, "HOST WRITES & NAND DIE", "--", "Model / Flash ID")

        mid = ttk.Frame(self.tab_forensics)
        mid.pack(fill="both", expand=True, pady=(8, 0))

        left_box = ttk.Frame(mid)
        left_box.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ttk.Label(left_box, text="Forensic Anomalies & 'Happy Meter' Findings:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self.txt_anomalies = tk.Text(
            left_box,
            bg=BG_CARD,
            fg=FG_TEXT,
            font=("Consolas", 9),
            height=14,
            wrap="word",
            relief="flat",
            padx=10,
            pady=8,
        )
        self.txt_anomalies.pack(fill="both", expand=True)

        right_box = ttk.Frame(mid)
        right_box.pack(side="right", fill="both", expand=True, padx=(6, 0))
        ttk.Label(right_box, text="SMART Attributes (0xB0) & Raw Telemetry:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        cols = ("id", "name", "current", "worst", "raw")
        self.tree_smart = ttk.Treeview(right_box, columns=cols, show="headings", height=14)
        for cid, hdr, w in [("id", "ID", 55), ("name", "Attribute Name", 210), ("current", "Cur", 55), ("worst", "Worst", 55), ("raw", "Raw Value", 120)]:
            self.tree_smart.heading(cid, text=hdr)
            self.tree_smart.column(cid, width=w, anchor="w" if cid == "name" else "center")
        self.tree_smart.pack(fill="both", expand=True)

    def _init_hunter_tab(self) -> None:
        bar = ttk.Frame(self.tab_hunter)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Sample Window (sec):").pack(side="left")
        self.hunt_sec_var = tk.IntVar(value=5)
        ttk.Spinbox(bar, from_=2, to=15, textvariable=self.hunt_sec_var, width=6).pack(side="left", padx=8)
        ttk.Button(bar, text="Start Real-Time Write Hunt", style="Accent.TButton", command=self.run_hunt_async).pack(side="left")

        cards = ttk.Frame(self.tab_hunter)
        cards.pack(fill="x", pady=6)
        self.lbl_phys_write, self.lbl_phys_iops = self._make_card(cards, "PHYSICAL SSD WRITE RATE", "-- KB/s", "-- IOPS (Disk 0)")
        self.lbl_proc_write, self.lbl_proc_sub = self._make_card(cards, "TOTAL PROCESS WRITE I/O", "-- KB/s", "Includes RAMDisk & IPC")
        self.lbl_offload_pct, self.lbl_offload_sub = self._make_card(cards, "RAMDISK / CACHE INTERCEPTION", "-- %", "Prevented from hitting NAND")

        panes = ttk.Frame(self.tab_hunter)
        panes.pack(fill="both", expand=True, pady=(8, 0))

        p_left = ttk.Frame(panes)
        p_left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ttk.Label(p_left, text="Top Active Writing Processes:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self.tree_procs = ttk.Treeview(p_left, columns=("pid", "name", "ops", "kb", "rate"), show="headings")
        for c, h, w in [("pid", "PID", 65), ("name", "Process", 160), ("ops", "Ops", 70), ("kb", "Total KB", 85), ("rate", "KB/s", 85)]:
            self.tree_procs.heading(c, text=h)
            self.tree_procs.column(c, width=w, anchor="w" if c == "name" else "e")
        self.tree_procs.pack(fill="both", expand=True)

        p_right = ttk.Frame(panes)
        p_right.pack(side="right", fill="both", expand=True, padx=(6, 0))
        ttk.Label(p_right, text="Recently Modified Physical Files on C: (Excluding RAMDisk Junctions):", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self.tree_files = ttk.Treeview(p_right, columns=("cat", "size", "time", "path"), show="headings")
        for c, h, w in [("cat", "Category", 160), ("size", "Size KB", 75), ("time", "Modified Time", 130), ("path", "Physical Path", 280)]:
            self.tree_files.heading(c, text=h)
            self.tree_files.column(c, width=w, anchor="w")
        self.tree_files.pack(fill="both", expand=True)

    def _init_ramdisk_tab(self) -> None:
        bar = ttk.Frame(self.tab_ramdisk)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="RAMDisk Drive:").pack(side="left")
        self.ram_drive_var = tk.StringVar(value="R")
        ttk.Entry(bar, textvariable=self.ram_drive_var, width=4).pack(side="left", padx=6)
        ttk.Label(bar, text="Max Capacity (GB):").pack(side="left", padx=(8, 0))
        self.ram_size_var = tk.IntVar(value=16)
        ttk.Spinbox(bar, from_=4, to=64, textvariable=self.ram_size_var, width=6).pack(side="left", padx=6)
        ttk.Button(bar, text="1. Deploy Dynamic RAMDisk & Redirect TEMP", style="Accent.TButton", command=self.deploy_ramdisk_async).pack(side="left", padx=8)
        ttk.Button(bar, text="2. Offload All 19 Caches via NTFS Junctions", style="Accent.TButton", command=self.deploy_junctions_async).pack(side="left", padx=4)

        self.lbl_ramdisk_summary = tk.Label(
            self.tab_ramdisk,
            text="Checking Dynamic RAMDisk status...",
            bg=BG_CARD,
            fg=ACCENT_GREEN,
            font=("Consolas", 10, "bold"),
            padx=12,
            pady=8,
            anchor="w",
        )
        self.lbl_ramdisk_summary.pack(fill="x", pady=(0, 8))

        cols = ("cat", "name", "link", "target", "status")
        self.tree_junctions = ttk.Treeview(self.tab_ramdisk, columns=cols, show="headings")
        for c, h, w in [
            ("cat", "Category", 130),
            ("name", "Cache / Telemetry Target", 190),
            ("link", "Original SSD Path (C:)", 330),
            ("target", "RAMDisk Path (R:)", 220),
            ("status", "Protection Status", 210),
        ]:
            self.tree_junctions.heading(c, text=h)
            self.tree_junctions.column(c, width=w, anchor="w")
        self.tree_junctions.pack(fill="both", expand=True)

    def _init_rescue_tab(self) -> None:
        grid = ttk.Frame(self.tab_rescue)
        grid.pack(fill="both", expand=True)

        items = [
            (
                "Layer 1 — Lock SATA AHCI Link Power Management (HIPM/DIPM -> Active)",
                "Prevents DRAM-less controllers (e.g. Yeestor YS9082HP) from dropping the SATA PHY link during idle sleep and rebuilding FTL tables.",
                "Apply SATA LPM Fix",
                self.run_lpm_fix_async,
            ),
            (
                "Layer 2 — Disable NTFS LastAccess Timestamp Updates & Verify TRIM",
                "Eliminates companion $MFT metadata writes on every file read operation and ensures ATA Delete Notification (TRIM) is active.",
                "Apply NTFS LastAccess Fix",
                self.run_lastaccess_fix_async,
            ),
            (
                "Layer 3 — Right-Size Bloated Windows Pagefile (64 GB -> Fixed 4096 MB)",
                "Prevents massive background pagefile thrashing on high-RAM workstations while preserving crash dump capability.",
                "Set Pagefile to 4096 MB",
                self.run_pagefile_fix_async,
            ),
            (
                "Layer 4 — Multi-Volume ATA ReTrim (C:, D:, E:)",
                "Issues immediate DATA SET MANAGEMENT (TRIM) across all NTFS volumes so the SSD controller reclaims stale flash blocks.",
                "Run Full ATA ReTrim",
                self.run_retrim_async,
            ),
        ]

        for title, desc, btn_text, cmd in items:
            row = tk.Frame(grid, bg=BG_CARD, padx=16, pady=12, highlightthickness=1, highlightbackground=BG_INPUT)
            row.pack(fill="x", pady=6)
            left = tk.Frame(row, bg=BG_CARD)
            left.pack(side="left", fill="x", expand=True)
            tk.Label(left, text=title, bg=BG_CARD, fg=ACCENT_BLUE, font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(left, text=desc, bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(3, 0))
            ttk.Button(row, text=btn_text, style="Accent.TButton", command=cmd).pack(side="right", padx=8)

        op_row = tk.Frame(grid, bg=BG_CARD, padx=16, pady=12, highlightthickness=1, highlightbackground=BG_INPUT)
        op_row.pack(fill="x", pady=6)
        op_left = tk.Frame(op_row, bg=BG_CARD)
        op_left.pack(side="left", fill="x", expand=True)
        tk.Label(
            op_left,
            text="Layer 7 — Hardware Over-Provisioning (OP) Non-Destructive Partition Shrinker",
            bg=BG_CARD,
            fg=ACCENT_AMBER,
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        tk.Label(
            op_left,
            text="Runs ATA ReTrim on the tail volume first, then shrinks it to reserve dedicated unallocated NAND blocks for controller GC & wear leveling.",
            bg=BG_CARD,
            fg=FG_MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(3, 0))
        op_ctrl = tk.Frame(op_row, bg=BG_CARD)
        op_ctrl.pack(side="right")
        tk.Label(op_ctrl, text="Drive:", bg=BG_CARD, fg=FG_TEXT).pack(side="left", padx=4)
        self.op_drive_var = tk.StringVar(value="E")
        ttk.Entry(op_ctrl, textvariable=self.op_drive_var, width=4).pack(side="left", padx=4)
        tk.Label(op_ctrl, text="OP GB:", bg=BG_CARD, fg=FG_TEXT).pack(side="left", padx=4)
        self.op_gb_var = tk.IntVar(value=100)
        ttk.Spinbox(op_ctrl, from_=16, to=500, textvariable=self.op_gb_var, width=6).pack(side="left", padx=4)
        ttk.Button(op_ctrl, text="Reserve Hardware OP", style="Accent.TButton", command=self.run_op_async).pack(side="left", padx=8)

    def _build_statusbar(self) -> None:
        self.status_var = tk.StringVar(value="Ready.")
        bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bg=BG_CARD,
            fg=FG_MUTED,
            anchor="w",
            padx=16,
            pady=6,
            font=("Segoe UI", 9),
        )
        bar.pack(fill="x", side="bottom")

    def set_status(self, msg: str) -> None:
        self.root.after(0, lambda: self.status_var.set(msg))

    def refresh_all_async(self) -> None:
        self.run_forensic_scan_async()
        self.refresh_protection_status_async()

    def run_forensic_scan_async(self) -> None:
        drv_str = self.drive_var.get().replace("PhysicalDrive", "")
        idx = int(drv_str) if drv_str.isdigit() else 0
        self.set_status(f"Running deep ATA/ACS-3 forensic inspection on PhysicalDrive{idx}...")

        def worker() -> None:
            rep = inspect_physical_drive(idx)
            self.last_report = rep
            self.root.after(0, lambda: self._render_forensic_report(rep))
            self.set_status(f"Forensic scan complete for {rep.model} ({rep.serial_number}).")

        threading.Thread(target=worker, daemon=True).start()

    def _render_forensic_report(self, rep: DriveForensicReport) -> None:
        used = rep.gp_log04.percentage_used_endurance
        self.lbl_health_val.config(
            text=f"SMART: {rep.reported_health_pct}% | True: {rep.true_health_pct}%",
            fg=ACCENT_RED if rep.is_fake_smart else ACCENT_GREEN,
        )
        self.lbl_health_sub.config(
            text=f"Used Endurance: {used}% ({'SPOOFED SMART' if rep.is_fake_smart else 'Verified'})"
        )

        if rep.vendor_nand.detected:
            v = rep.vendor_nand
            self.lbl_skew_val.config(
                text=f"Max {v.max_erase_count} / Avg {v.avg_erase_count} ({v.erase_skew_ratio}x)",
                fg=ACCENT_AMBER if v.erase_skew_ratio >= 3.0 else ACCENT_GREEN,
            )
            self.lbl_skew_sub.config(text=f"Min Erase: {v.min_erase_count} | Bad Blocks: {v.factory_bad_blocks}+{v.grown_bad_blocks}")
        else:
            self.lbl_skew_val.config(text="N/A", fg=FG_MUTED)
            self.lbl_skew_sub.config(text="Standard controller")

        resets = rep.gp_log04.sata_hardware_resets
        self.lbl_reset_val.config(
            text=f"{resets:,} Resets",
            fg=ACCENT_RED if resets > 500 else ACCENT_GREEN,
        )
        self.lbl_reset_sub.config(text=f"Power Cycles: {rep.gp_log04.power_on_resets:,} | POH: {rep.gp_log04.power_on_hours:,} h")

        writes_tib = rep.gp_log04.host_writes_gib / 1024.0
        self.lbl_nand_val.config(text=f"{writes_tib:.2f} TiB Written", fg=ACCENT_BLUE)
        nand_desc = rep.vendor_nand.flash_description if rep.vendor_nand.detected else f"{rep.model} ({rep.capacity_gb:.0f} GB)"
        self.lbl_nand_sub.config(text=nand_desc[:44])

        self.txt_anomalies.delete("1.0", "end")
        self.txt_anomalies.insert("end", f"Drive Model   : {rep.model}\n")
        self.txt_anomalies.insert("end", f"Serial / FW   : {rep.serial_number} / {rep.firmware_rev}\n")
        if rep.vendor_nand.detected:
            self.txt_anomalies.insert("end", f"Controller    : {rep.vendor_nand.controller_hint}\n")
            self.txt_anomalies.insert("end", f"NAND Flash ID : {rep.vendor_nand.flash_id_hex} ({rep.vendor_nand.flash_description})\n")
        self.txt_anomalies.insert("end", "-" * 54 + "\n")
        if not rep.anomalies:
            self.txt_anomalies.insert("end", "[OK] No firmware SMART spoofing or wear anomalies detected.\n")
        else:
            for a in rep.anomalies:
                self.txt_anomalies.insert("end", f"[{a.severity}] {a.title}\n  {a.detail}\n\n")

        for item in self.tree_smart.get_children():
            self.tree_smart.delete(item)
        for attr in rep.smart_attributes:
            self.tree_smart.insert(
                "",
                "end",
                values=(f"0x{attr.attr_id:02X}", attr.name, attr.current, attr.worst, f"{attr.raw_value:,} (0x{attr.raw_value:X})"),
            )

    def export_forensic_json(self) -> None:
        if not self.last_report:
            messagebox.showinfo("Export", "Please run a forensic scan first.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile=f"ssd_forensic_{self.last_report.serial_number}.json",
        )
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(self.last_report.to_dict(), f, indent=2)
            messagebox.showinfo("Export Complete", f"Saved forensic report to:\n{fp}")

    def run_hunt_async(self) -> None:
        sec = int(self.hunt_sec_var.get())
        self.set_status(f"Sampling real-time physical SSD IOPS and process write deltas ({sec}s window)...")

        def worker() -> None:
            res = run_write_hunt(duration_sec=sec, recent_minutes=2)
            self.last_hunt = res
            self.root.after(0, lambda: self._render_hunt(res))
            self.set_status(f"Write hunt complete: Physical SSD = {res.physical_write_kb_s} KB/s ({res.physical_write_iops} IOPS).")

        threading.Thread(target=worker, daemon=True).start()

    def _render_hunt(self, res: WriteHuntResult) -> None:
        self.lbl_phys_write.config(
            text=f"{res.physical_write_kb_s:,.2f} KB/s",
            fg=ACCENT_GREEN if res.physical_write_kb_s < 500 else ACCENT_AMBER,
        )
        self.lbl_phys_iops.config(text=f"{res.physical_write_iops:.2f} IOPS (Physical Disk 0)")
        self.lbl_proc_write.config(text=f"{res.total_process_write_kb_s:,.2f} KB/s", fg=ACCENT_BLUE)
        self.lbl_offload_pct.config(text=f"{res.offload_interception_pct:.1f}% Intercepted", fg=ACCENT_GREEN)

        for i in self.tree_procs.get_children():
            self.tree_procs.delete(i)
        for p in res.top_processes:
            self.tree_procs.insert("", "end", values=(p.pid, p.name, p.write_ops, f"{p.write_kb:,.1f}", f"{p.rate_kb_s:,.1f}"))

        for i in self.tree_files.get_children():
            self.tree_files.delete(i)
        for f in res.recent_files:
            self.tree_files.insert("", "end", values=(f.category, f"{f.size_kb:,.1f}", f.last_write_time, f.path))

    def refresh_protection_status_async(self) -> None:
        def worker() -> None:
            st = check_protection_status()
            self.last_status = st
            self.root.after(0, lambda: self._render_protection_status(st))

        threading.Thread(target=worker, daemon=True).start()

    def _render_protection_status(self, st: SystemProtectionStatus) -> None:
        ram_state = (
            f"MOUNTED ({st.ramdisk_drive} {st.ramdisk_free_gb:.2f}/{st.ramdisk_total_gb:.2f} GB Free | "
            f"RAM Footprint: {st.ramdisk_working_set_mb:.1f} MB | TEMP Redirected: {st.temp_redirected} | "
            f"Hardware OP: {st.unallocated_op_gb:.1f} GB)"
            if st.ramdisk_mounted
            else "NOT MOUNTED — Click 'Deploy Dynamic RAMDisk' above to initialize."
        )
        self.lbl_ramdisk_summary.config(
            text=f"Status: {ram_state}",
            fg=ACCENT_GREEN if st.ramdisk_mounted else ACCENT_AMBER,
        )
        for i in self.tree_junctions.get_children():
            self.tree_junctions.delete(i)
        for j in st.junctions:
            self.tree_junctions.insert("", "end", values=(j.category, j.name, j.link_path, j.ramdisk_subpath, j.status))

    def deploy_ramdisk_async(self) -> None:
        drv = self.ram_drive_var.get().strip() or "R"
        sz = int(self.ram_size_var.get())
        self.set_status(f"Deploying {sz} GB Dynamic RAMDisk ({drv}:)...")

        def worker() -> None:
            ok, msg = deploy_dynamic_ramdisk(size_gb=sz, drive_letter=drv)
            self.refresh_protection_status_async()
            self.set_status(msg)
            self.root.after(0, lambda: messagebox.showinfo("Dynamic RAMDisk", msg) if ok else messagebox.showerror("Error", msg))

        threading.Thread(target=worker, daemon=True).start()

    def deploy_junctions_async(self) -> None:
        drv = self.ram_drive_var.get().strip().rstrip(":") or "R"
        self.set_status("Migrating 19 high-frequency cache and telemetry directories to NTFS Junctions...")

        def worker() -> None:
            ok, msg, _ = deploy_cache_junctions(f"{drv}:\\Temp")
            self.refresh_protection_status_async()
            self.set_status(msg)
            self.root.after(0, lambda: messagebox.showinfo("Cache Junction Offloader", msg))

        threading.Thread(target=worker, daemon=True).start()

    def run_lpm_fix_async(self) -> None:
        threading.Thread(target=self._run_simple_action, args=(apply_sata_lpm_fix,), daemon=True).start()

    def run_lastaccess_fix_async(self) -> None:
        threading.Thread(target=self._run_simple_action, args=(apply_ntfs_lastaccess_fix,), daemon=True).start()

    def run_pagefile_fix_async(self) -> None:
        threading.Thread(target=self._run_simple_action, args=(lambda: apply_pagefile_fix(4096),), daemon=True).start()

    def run_retrim_async(self) -> None:
        self.set_status("Running ATA ReTrim across NTFS volumes...")
        threading.Thread(target=self._run_simple_action, args=(run_volume_retrim,), daemon=True).start()

    def run_op_async(self) -> None:
        drv = self.op_drive_var.get().strip() or "E"
        gb = int(self.op_gb_var.get())
        if not messagebox.askyesno(
            "Confirm Hardware Over-Provisioning",
            f"This will run ATA ReTrim on {drv}: and non-destructively shrink {drv}: by {gb} GB "
            "to reserve unallocated NAND Over-Provisioning space.\n\nProceed?",
        ):
            return
        self.set_status(f"TRIMming {drv}: and shrinking by {gb} GB for Hardware OP...")
        threading.Thread(
            target=self._run_simple_action,
            args=(lambda: configure_over_provisioning(shrink_drive=drv, op_size_gb=gb),),
            daemon=True,
        ).start()

    def _run_simple_action(self, fn) -> None:
        ok, msg = fn()
        self.refresh_protection_status_async()
        self.set_status(msg)
        self.root.after(
            0,
            lambda: messagebox.showinfo("Success", msg) if ok else messagebox.showerror("Operation Failed", msg),
        )


def launch_gui() -> None:
    root = tk.Tk()
    SSDLifeguardApp(root)
    root.mainloop()
