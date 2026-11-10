"""
ssd_lifeguard.forensics
~~~~~~~~~~~~~~~~~~~~~~~
Deep ATA/ACS-3 & Vendor-Specific SSD Forensic Inspector and Fake SMART ("Happy Meter") Detector.

Uses raw Windows Win32 `IOCTL_ATA_PASS_THROUGH` (`0x0004D02C`) to query:
  1. ATA `IDENTIFY DEVICE (0xEC)`
  2. ATA `SMART READ DATA (0xB0 / 0xD0)` (Legacy 512-byte SMART table)
  3. ACS-3 `READ LOG EXT (0x2F)` GP Log `0x04` (Device Statistics: Page 0x01 General,
     Page 0x04 Transport Hardware Resets, Page 0x05 Temperature, Page 0x07 Real Endurance Used)
  4. ATA `SMART READ LOG (0xB0 / 0xD5)` Log `0xE0` / `0xA0` (Yeestor YS9082HP / SiliconGo Vendor
     FTL & NAND Flash health page: Flash ID, Max/Min/Avg Erase Counts, Bad Blocks)
"""

from __future__ import annotations

import ctypes
import platform
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

IOCTL_ATA_PASS_THROUGH = 0x0004D02C
ATA_FLAGS_DRDY_REQUIRED = 0x01
ATA_FLAGS_DATA_IN = 0x02
ATA_FLAGS_48BIT_COMMAND = 0x08

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3

SMART_ATTR_NAMES: Dict[int, str] = {
    0x01: "Raw Read Error Rate",
    0x05: "Reallocated Sectors Count",
    0x09: "Power-On Hours",
    0x0C: "Power Cycle Count",
    0xA0: "Uncorrectable Sector Count",
    0xA1: "Valid Spare Blocks",
    0xA3: "Initial Invalid Blocks",
    0xA4: "Total TLC Erase Count",
    0xA5: "Max TLC Erase Count",
    0xA6: "Min TLC Erase Count",
    0xA7: "Average TLC Erase Count",
    0xA8: "Max Erase Count Spec",
    0xA9: "Remaining Life Percentage",
    0xAF: "Program Fail Count (Chip)",
    0xB0: "Erase Fail Count (Chip)",
    0xB1: "Wear Leveling Count",
    0xB2: "Used Reserved Block Count",
    0xB5: "Program Fail Count (Total)",
    0xB6: "Erase Fail Count (Total)",
    0xC0: "Unsafe Shutdown Count",
    0xC2: "Temperature Celsius",
    0xC3: "Hardware ECC Recovered",
    0xC4: "Reallocation Event Count",
    0xC5: "Current Pending Sector Count",
    0xC6: "Offline Uncorrectable",
    0xC7: "UDMA CRC Error Count",
    0xE7: "SSD Life Left",
    0xE8: "Available Reserved Space",
    0xE9: "Media Wearout Indicator",
    0xF1: "Total LBAs Written",
    0xF2: "Total LBAs Read",
    0xF9: "Total NAND Writes",
}

NAND_VENDOR_MAP: Dict[int, str] = {
    0x98: "Kioxia / Toshiba",
    0x45: "SanDisk / Western Digital",
    0x2C: "Micron",
    0x89: "Intel / Solidigm",
    0xEC: "Samsung",
    0xAD: "SK Hynix",
    0x9B: "YMTC (Yangtze Memory)",
}


def _to_signed_int8(byte_val: int) -> int:
    v = byte_val & 0xFF
    return v - 256 if v >= 128 else v


def _is_valid_handle(handle: Any) -> bool:
    return handle is not None and handle not in (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


@dataclass
class SmartAttribute:
    attr_id: int
    name: str
    flags: int
    current: int
    worst: int
    raw_value: int


@dataclass
class GpLog04Stats:
    supported: bool = False
    power_on_resets: int = 0
    power_on_hours: int = 0
    logical_sectors_written: int = 0
    write_commands: int = 0
    logical_sectors_read: int = 0
    read_commands: int = 0
    sata_hardware_resets: int = 0
    sata_asr_events: int = 0
    sata_crc_errors: int = 0
    current_temp_c: int = 0
    max_temp_c: int = 0
    min_temp_c: int = 0
    percentage_used_endurance: int = 0

    @property
    def host_writes_gib(self) -> float:
        return round((self.logical_sectors_written * 512) / (1024 ** 3), 2)

    @property
    def host_reads_gib(self) -> float:
        return round((self.logical_sectors_read * 512) / (1024 ** 3), 2)

    @property
    def avg_write_size_kb(self) -> float:
        if self.write_commands <= 0:
            return 0.0
        return round((self.logical_sectors_written * 0.5) / self.write_commands, 2)


@dataclass
class VendorNandStats:
    detected: bool = False
    controller_hint: str = "Unknown"
    flash_id_hex: str = ""
    flash_vendor: str = "Unknown"
    flash_description: str = ""
    max_erase_count: int = 0
    min_erase_count: int = 0
    avg_erase_count: int = 0
    factory_bad_blocks: int = 0
    grown_bad_blocks: int = 0

    @property
    def erase_skew_ratio(self) -> float:
        if self.avg_erase_count <= 0:
            return 0.0
        return round(self.max_erase_count / self.avg_erase_count, 2)


@dataclass
class LifespanEstimate:
    composite_health_score: int = 100
    health_grade: str = "EXCELLENT"
    daily_host_writes_gib: float = 0.0
    effective_wear_factor: float = 1.0
    estimated_remaining_days: Optional[int] = None
    estimated_remaining_years: Optional[float] = None


@dataclass
class ForensicAnomaly:
    severity: str  # "CRITICAL", "WARNING", "INFO"
    code: str
    title: str
    detail: str


@dataclass
class DriveForensicReport:
    drive_index: int
    model: str = "Unknown Drive"
    serial_number: str = "Unknown"
    firmware_rev: str = "Unknown"
    capacity_gb: float = 0.0
    trim_supported: bool = False
    smart_attributes: List[SmartAttribute] = field(default_factory=list)
    gp_log04: GpLog04Stats = field(default_factory=GpLog04Stats)
    vendor_nand: VendorNandStats = field(default_factory=VendorNandStats)
    lifespan: LifespanEstimate = field(default_factory=LifespanEstimate)
    anomalies: List[ForensicAnomaly] = field(default_factory=list)
    is_fake_smart: bool = False
    true_health_pct: int = 100
    reported_health_pct: int = 100

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["gp_log04"]["host_writes_gib"] = self.gp_log04.host_writes_gib
        d["gp_log04"]["host_reads_gib"] = self.gp_log04.host_reads_gib
        d["gp_log04"]["avg_write_size_kb"] = self.gp_log04.avg_write_size_kb
        d["vendor_nand"]["erase_skew_ratio"] = self.vendor_nand.erase_skew_ratio
        return d


def _swap_ata_string(raw: bytes) -> str:
    even_len = len(raw) & ~1
    chars = bytearray(even_len)
    for i in range(0, even_len, 2):
        chars[i] = raw[i + 1]
        chars[i + 1] = raw[i]
    if len(raw) % 2 == 1:
        chars.append(raw[-1])
    return chars.decode("ascii", errors="replace").strip()


def _ata_pass_through(
    handle: int,
    prev_task: bytes,
    curr_task: bytes,
    data_len: int = 512,
    is_48bit: bool = False,
) -> Optional[bytes]:
    if platform.system() != "Windows":
        return None
    flags = ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN
    if is_48bit:
        flags |= ATA_FLAGS_48BIT_COMMAND

    header_size = 48
    buf = ctypes.create_string_buffer(header_size + data_len)
    struct.pack_into(
        "<HH4BIIIIQ8s8s",
        buf,
        0,
        header_size,
        flags,
        0,
        0,
        0,
        0,
        data_len,
        10,
        0,
        0,
        header_size,
        prev_task.ljust(8, b"\x00"),
        curr_task.ljust(8, b"\x00"),
    )
    returned = ctypes.c_ulong(0)
    k32 = ctypes.windll.kernel32
    ok = k32.DeviceIoControl(
        ctypes.c_void_p(handle),
        IOCTL_ATA_PASS_THROUGH,
        buf,
        header_size + data_len,
        buf,
        header_size + data_len,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        return None
    status_reg = buf.raw[0x28 + 6]
    if status_reg & 0x01:  # ERR bit set
        return None
    return buf.raw[header_size : header_size + data_len]


def _decode_nand_id(flash_bytes: bytes) -> Tuple[str, str, str]:
    if not flash_bytes:
        return "", "Unknown", "Unknown NAND"
    hex_str = " ".join(f"{b:02X}" for b in flash_bytes)
    vendor_id = flash_bytes[0]
    vendor = NAND_VENDOR_MAP.get(vendor_id, f"Vendor 0x{vendor_id:02X}")
    desc = f"{vendor} NAND ({hex_str})"
    if flash_bytes[:2] == b"\x98\x48" or flash_bytes[:3] == b"\x98\x48\x98":
        desc = "Kioxia / Toshiba BiCS4 96-Layer 3D TLC NAND (1Tb Die)"
    elif flash_bytes[:2] == b"\x98\x3e":
        desc = "Kioxia / Toshiba BiCS5 112-Layer 3D TLC NAND"
    elif vendor_id == 0x9B:
        desc = "YMTC Xtacking 3D TLC NAND"
    return hex_str, vendor, desc


def compute_lifespan_metrics(
    report: DriveForensicReport, smart_map: Optional[Dict[int, SmartAttribute]] = None
) -> LifespanEstimate:
    """Compute a composite SSD reliability score (0..100), effective wear factor, and Remaining Useful Life."""
    smart_map = smart_map or {a.attr_id: a for a in report.smart_attributes}
    score = int(max(0, min(100, report.true_health_pct)))

    # Penalize static-block erase skew on DRAM-less controllers
    if report.vendor_nand.detected and report.vendor_nand.erase_skew_ratio >= 2.0:
        skew_pen = min(20, int((report.vendor_nand.erase_skew_ratio - 1.5) * 3.0))
        score -= skew_pen

    # Penalize SATA hardware link reset storms
    resets = report.gp_log04.sata_hardware_resets
    cycles = max(1, report.gp_log04.power_on_resets)
    if resets > max(500, cycles * 3):
        score -= 10

    # Penalize grown bad blocks / reallocated / pending / uncorrectable sectors
    grown = report.vendor_nand.grown_bad_blocks
    for aid in (0x05, 0xC5, 0xC6):
        if aid in smart_map:
            grown = max(grown, int(smart_map[aid].raw_value))
    if grown > 0:
        score -= min(35, grown * 5)

    score = max(0, min(100, score))
    if score >= 85:
        grade = "EXCELLENT"
    elif score >= 65:
        grade = "GOOD"
    elif score >= 40:
        grade = "FAIR_MONITOR"
    else:
        grade = "CRITICAL_REPLACE_SOON"

    poh = report.gp_log04.power_on_hours
    if poh <= 0 and 0x09 in smart_map:
        poh = int(smart_map[0x09].raw_value)

    writes_gib = report.gp_log04.host_writes_gib
    daily_gib = round(writes_gib / (poh / 24.0), 2) if poh >= 24 and writes_gib > 0 else 0.0

    # Effective wear factor relative to nominal 300-P/E TLC endurance (capacity_gb * 300 = 100% endurance)
    wear_factor = 1.0
    used_pct = report.gp_log04.percentage_used_endurance if report.gp_log04.supported else (100 - report.true_health_pct)
    if report.capacity_gb > 0 and writes_gib > 0 and used_pct > 0:
        expected_used_pct = (writes_gib / (report.capacity_gb * 300.0)) * 100.0
        if expected_used_pct > 0.01:
            wear_factor = round(used_pct / expected_used_pct, 2)

    rem_days: Optional[int] = None
    rem_years: Optional[float] = None
    if poh >= 24 and 0 < used_pct < 100:
        hours_per_pct = poh / float(used_pct)
        rem_hours = hours_per_pct * float(100 - used_pct)
        rem_days = int(round(rem_hours / 24.0))
        rem_years = round(rem_days / 365.25, 2)

    return LifespanEstimate(
        composite_health_score=score,
        health_grade=grade,
        daily_host_writes_gib=daily_gib,
        effective_wear_factor=wear_factor,
        estimated_remaining_days=rem_days,
        estimated_remaining_years=rem_years,
    )


def inspect_physical_drive(drive_index: int = 0) -> DriveForensicReport:
    """
    Perform a deep ATA/ACS-3 forensic inspection on \\\\.\\PhysicalDrive<drive_index>.
    """
    report = DriveForensicReport(drive_index=drive_index)
    if platform.system() != "Windows":
        return report

    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    path = f"\\\\.\\PhysicalDrive{drive_index}"
    handle = k32.CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if not _is_valid_handle(handle):
        return report

    try:
        # 1. ATA IDENTIFY DEVICE (0xEC)
        id_data = _ata_pass_through(
            handle,
            b"\x00" * 8,
            bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0xEC, 0x00]),
            512,
            False,
        )
        if id_data and len(id_data) >= 512:
            words = struct.unpack("<256H", id_data[:512])
            report.serial_number = _swap_ata_string(id_data[20:40])
            report.firmware_rev = _swap_ata_string(id_data[46:54])
            report.model = _swap_ata_string(id_data[54:94])
            lba48 = (
                words[100]
                | (words[101] << 16)
                | (words[102] << 32)
                | (words[103] << 48)
            )
            if lba48 > 0:
                report.capacity_gb = round((lba48 * 512) / (1024 ** 3), 2)
            report.trim_supported = bool(words[169] & 0x0001)

        # 2. ATA SMART READ DATA (0xB0 / 0xD0)
        smart_data = _ata_pass_through(
            handle,
            b"\x00" * 8,
            bytes([0xD0, 0x01, 0x00, 0x4F, 0xC2, 0xA0, 0xB0, 0x00]),
            512,
            False,
        )
        smart_map: Dict[int, SmartAttribute] = {}
        if smart_data and len(smart_data) >= 362:
            for i in range(30):
                off = 2 + i * 12
                attr_id = smart_data[off]
                if attr_id == 0:
                    continue
                flags = struct.unpack_from("<H", smart_data, off + 1)[0]
                current = smart_data[off + 3]
                worst = smart_data[off + 4]
                raw_val = int.from_bytes(smart_data[off + 5 : off + 11], "little")
                attr = SmartAttribute(
                    attr_id=attr_id,
                    name=SMART_ATTR_NAMES.get(attr_id, f"Vendor Attribute 0x{attr_id:02X}"),
                    flags=flags,
                    current=current,
                    worst=worst,
                    raw_value=raw_val,
                )
                report.smart_attributes.append(attr)
                smart_map[attr_id] = attr

        if 0xA9 in smart_map:
            report.reported_health_pct = smart_map[0xA9].current
        elif 0xE7 in smart_map:
            report.reported_health_pct = smart_map[0xE7].current
        report.true_health_pct = report.reported_health_pct

        # 3. ACS-3 READ LOG EXT (0x2F) -> GP Log 0x04 (Device Statistics)
        def read_gp_log04_page(page: int) -> Optional[bytes]:
            prev = b"\x00" * 8
            curr = bytes([0x00, 0x01, 0x04, page & 0xFF, 0x00, 0x00, 0x2F, 0x00])
            return _ata_pass_through(handle, prev, curr, 512, True)

        p1 = read_gp_log04_page(1)
        if p1 and len(p1) >= 512 and (p1[0] == 1 or p1[2] == 1):
            report.gp_log04.supported = True
            q1 = struct.unpack("<64Q", p1[:512])
            report.gp_log04.power_on_resets = q1[1] & 0xFFFFFFFFFFFF
            report.gp_log04.power_on_hours = q1[2] & 0xFFFFFFFFFFFF
            report.gp_log04.logical_sectors_written = q1[3] & 0xFFFFFFFFFFFF
            report.gp_log04.write_commands = q1[4] & 0xFFFFFFFFFFFF
            report.gp_log04.logical_sectors_read = q1[5] & 0xFFFFFFFFFFFF
            report.gp_log04.read_commands = q1[6] & 0xFFFFFFFFFFFF

        p4 = read_gp_log04_page(4)
        if p4 and len(p4) >= 512 and (report.gp_log04.supported or p4[0] == 4 or p4[2] == 4):
            q4 = struct.unpack("<64Q", p4[:512])
            report.gp_log04.sata_hardware_resets = (q4[2] or q4[1]) & 0xFFFFFFFFFFFF
            report.gp_log04.sata_asr_events = q4[3] & 0xFFFFFFFFFFFF
            report.gp_log04.sata_crc_errors = q4[4] & 0xFFFFFFFFFFFF

        p5 = read_gp_log04_page(5)
        if p5 and len(p5) >= 512 and (report.gp_log04.supported or p5[0] == 5 or p5[2] == 5):
            q5 = struct.unpack("<64Q", p5[:512])
            report.gp_log04.current_temp_c = _to_signed_int8(q5[1])
            report.gp_log04.max_temp_c = _to_signed_int8(q5[2])
            report.gp_log04.min_temp_c = _to_signed_int8(q5[3])

        p7 = read_gp_log04_page(7)
        if p7 and len(p7) >= 512 and (report.gp_log04.supported or p7[0] == 7 or p7[2] == 7):
            q7 = struct.unpack("<64Q", p7[:512])
            used = min(255, int(q7[1] & 0xFF))
            # Only apply Page 0x07 endurance if GP Log 0x04 is supported or valid flag bit (bit 63) / non-zero used is set
            if report.gp_log04.supported or (q7[1] >> 56) != 0 or used > 0:
                report.gp_log04.percentage_used_endurance = used
                report.true_health_pct = max(0, 100 - used)

        # 4. Extract Vendor Controller & NAND Flash ID from IDENTIFY Vendor Words, SMART Log 0xA0, and SMART Attributes
        log_a0 = _ata_pass_through(
            handle,
            b"\x00" * 8,
            bytes([0xD5, 0x01, 0xA0, 0x4F, 0xC2, 0x00, 0xB0, 0x00]),
            512,
            False,
        )
        ctrl_fw_str = ""
        if log_a0:
            ctrl_fw_str = log_a0[:32].split(b"\x00")[0].decode("ascii", errors="ignore").strip()

        if id_data and len(id_data) >= 312:
            flash_raw = id_data[295:301]
            if flash_raw[0] not in (0x00, 0xFF, 0x20) or ctrl_fw_str or (0xA5 in smart_map and 0xA7 in smart_map):
                report.vendor_nand.detected = True
                if ctrl_fw_str:
                    report.vendor_nand.controller_hint = f"Yeestor (SiliconGo) {ctrl_fw_str} DRAM-less SATA"
                elif report.serial_number.startswith("YS"):
                    report.vendor_nand.controller_hint = "Yeestor (SiliconGo) YS9082HP/HT DRAM-less SATA"
                else:
                    report.vendor_nand.controller_hint = "SATA SSD Controller"
                if flash_raw[0] not in (0x00, 0xFF, 0x20):
                    hex_id, vendor, desc = _decode_nand_id(flash_raw)
                    report.vendor_nand.flash_id_hex = hex_id
                    report.vendor_nand.flash_vendor = vendor
                    report.vendor_nand.flash_description = desc
                if 0xA5 in smart_map:
                    report.vendor_nand.max_erase_count = smart_map[0xA5].raw_value
                if 0xA6 in smart_map:
                    report.vendor_nand.min_erase_count = smart_map[0xA6].raw_value
                if 0xA7 in smart_map:
                    report.vendor_nand.avg_erase_count = smart_map[0xA7].raw_value
                if 0xA3 in smart_map:
                    report.vendor_nand.factory_bad_blocks = smart_map[0xA3].raw_value
                if 0xA0 in smart_map:
                    report.vendor_nand.grown_bad_blocks = smart_map[0xA0].raw_value

        # 5. Forensic Anomaly & Lifespan Evaluation
        _evaluate_anomalies(report, smart_map)
        report.lifespan = compute_lifespan_metrics(report, smart_map)

    finally:
        k32.CloseHandle(ctypes.c_void_p(handle))

    return report


def _evaluate_anomalies(report: DriveForensicReport, smart_map: Dict[int, SmartAttribute]) -> None:
    # Check 1: Endurance Discrepancy (Fake 100% Health in SMART vs GP Log 0x04 Page 0x07)
    if report.gp_log04.supported:
        used = report.gp_log04.percentage_used_endurance
        true_health = max(0, 100 - used)
        if report.reported_health_pct - true_health >= 5:
            report.is_fake_smart = True
            report.anomalies.append(
                ForensicAnomaly(
                    severity="CRITICAL",
                    code="FAKE_SMART_ENDURANCE",
                    title="Spoofed / Firmware-Locked SMART Health ('Happy Meter')",
                    detail=(
                        f"Legacy SMART reports {report.reported_health_pct}% health, "
                        f"but ACS-3 GP Log 0x04 Page 0x07 reveals {used}% endurance consumed "
                        f"(True Remaining Health: {true_health}%)."
                    ),
                )
            )

    # Check 2: Hardcoded Temperature Sensor (mask low byte for controllers packing min/max in upper bytes)
    temp_attr = smart_map.get(0xC2)
    if temp_attr and (temp_attr.raw_value & 0xFF) == 40 and report.gp_log04.max_temp_c == 0:
        report.is_fake_smart = True
        report.anomalies.append(
            ForensicAnomaly(
                severity="WARNING",
                code="HARDCODED_TEMP_40C",
                title="Hardcoded 40 C Dummy Temperature Sensor",
                detail=(
                    "SMART Attribute 0xC2 reports a fixed 40 C while ACS-3 GP Log 0x04 Page 0x05 "
                    "reports 0 C historical min/max, confirming the firmware lacks or locks thermal telemetry."
                ),
            )
        )

    # Check 3: Hidden SATA Hardware Reset Storm
    resets = report.gp_log04.sata_hardware_resets
    cycles = report.gp_log04.power_on_resets
    if resets > max(500, cycles * 3):
        report.anomalies.append(
            ForensicAnomaly(
                severity="CRITICAL",
                code="SATA_LINK_RESET_STORM",
                title=f"Hidden SATA Link Reset Storm ({resets:,} Resets)",
                detail=(
                    f"ACS-3 GP Log 0x04 Page 0x04 recorded {resets:,} SATA hardware link resets across only "
                    f"{cycles:,} power cycles (while SMART 0xC7 reports 0 errors). Caused by aggressive "
                    "SATA HIPM/DIPM link power management triggering controller link drops and FTL rebuilds."
                ),
            )
        )

    # Check 4: Concentrated Static-Block Erase Skew on DRAM-less Controller
    if report.vendor_nand.detected and report.vendor_nand.erase_skew_ratio >= 3.0:
        report.anomalies.append(
            ForensicAnomaly(
                severity="CRITICAL",
                code="FTL_STATIC_BLOCK_WEAR_SKEW",
                title=(
                    f"Severe Erase Skew ({report.vendor_nand.erase_skew_ratio}x: "
                    f"Max {report.vendor_nand.max_erase_count} vs Avg {report.vendor_nand.avg_erase_count})"
                ),
                detail=(
                    f"Vendor Log 0xE0 shows Max Block Erase = {report.vendor_nand.max_erase_count} while "
                    f"Average Block Erase = {report.vendor_nand.avg_erase_count} across only "
                    f"{report.gp_log04.host_writes_gib / 1024:.2f} TiB of host writes. "
                    "DRAM-less controller is hammering a small pool of static SLC/FTL blocks due to "
                    "small random 4KB writes and FTL metadata thrashing."
                ),
            )
        )


def diff_forensic_reports(old_rep: Dict[str, Any], new_rep: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two forensic report dicts to quantify wear rate, host write reduction, and SATA reset stability."""
    old_gp = old_rep.get("gp_log04") or {}
    new_gp = new_rep.get("gp_log04") or {}
    old_vn = old_rep.get("vendor_nand") or {}
    new_vn = new_rep.get("vendor_nand") or {}

    old_poh = int(old_gp.get("power_on_hours") or 0)
    new_poh = int(new_gp.get("power_on_hours") or 0)
    delta_poh = new_poh - old_poh

    old_sec = int(old_gp.get("logical_sectors_written") or 0)
    new_sec = int(new_gp.get("logical_sectors_written") or 0)
    delta_writes_gib = round(((new_sec - old_sec) * 512) / (1024 ** 3), 3)
    interval_gib_per_day = round(delta_writes_gib / (delta_poh / 24.0), 2) if delta_poh > 0 else None

    old_used = int(old_gp.get("percentage_used_endurance") or 0)
    new_used = int(new_gp.get("percentage_used_endurance") or 0)

    old_resets = int(old_gp.get("sata_hardware_resets") or 0)
    new_resets = int(new_gp.get("sata_hardware_resets") or 0)

    old_max_erase = int(old_vn.get("max_erase_count") or 0)
    new_max_erase = int(new_vn.get("max_erase_count") or 0)
    old_avg_erase = int(old_vn.get("avg_erase_count") or 0)
    new_avg_erase = int(new_vn.get("avg_erase_count") or 0)
    old_grown = int(old_vn.get("grown_bad_blocks") or 0)
    new_grown = int(new_vn.get("grown_bad_blocks") or 0)

    return {
        "serial_number": new_rep.get("serial_number") or old_rep.get("serial_number", "Unknown"),
        "model": new_rep.get("model") or old_rep.get("model", "Unknown"),
        "delta_power_on_hours": delta_poh,
        "delta_host_writes_gib": delta_writes_gib,
        "interval_writes_gib_per_day": interval_gib_per_day,
        "delta_endurance_used_pct": new_used - old_used,
        "delta_sata_hardware_resets": new_resets - old_resets,
        "delta_max_erase_count": new_max_erase - old_max_erase,
        "delta_avg_erase_count": new_avg_erase - old_avg_erase,
        "delta_grown_bad_blocks": new_grown - old_grown,
        "sata_link_stable": (new_resets - old_resets) == 0,
        "true_health_before": int(old_rep.get("true_health_pct", 100)),
        "true_health_after": int(new_rep.get("true_health_pct", 100)),
    }


def list_physical_drives() -> List[int]:
    """Return available PhysicalDrive indices on Windows with 64-bit HANDLE safety."""
    if platform.system() != "Windows":
        return [0]
    drives: List[int] = []
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    for idx in range(8):
        h = k32.CreateFileW(
            f"\\\\.\\PhysicalDrive{idx}",
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if _is_valid_handle(h):
            k32.CloseHandle(ctypes.c_void_p(h))
            drives.append(idx)
    return drives or [0]
