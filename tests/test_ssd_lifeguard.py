import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ssd_lifeguard import cli
from ssd_lifeguard.forensics import (
    DriveForensicReport,
    GpLog04Stats,
    SmartAttribute,
    VendorNandStats,
    _decode_nand_id,
    _evaluate_anomalies,
    _is_valid_handle,
    _swap_ata_string,
    _to_signed_int8,
    compute_lifespan_metrics,
    diff_forensic_reports,
)
from ssd_lifeguard.optimizer import get_default_junction_specs, normalize_drive_letter
from ssd_lifeguard.write_hunter import classify_file_path


class TestForensicsAndAnomalyEngine(unittest.TestCase):
    def test_ata_string_swap_and_nand_decode(self) -> None:
        # ATA strings swap byte pairs ("Qu"->"uQ", "ni"->"in", "on"->"no", " S"->"S ", "SD"->"DS", "2T"->"T2", "B "->" B")
        raw = b"uQinnoS DST2 B"
        self.assertEqual(_swap_ata_string(raw), "Qunion SSD2TB")
        self.assertEqual(_to_signed_int8(0x28), 40)
        self.assertEqual(_to_signed_int8(0xFB), -5)

        hex_id, vendor, desc = _decode_nand_id(bytes.fromhex("98 48 98 03 76 E4"))
        self.assertEqual(hex_id, "98 48 98 03 76 E4")
        self.assertEqual(vendor, "Kioxia / Toshiba")
        self.assertIn("BiCS4", desc)

        self.assertFalse(_is_valid_handle(None))
        self.assertFalse(_is_valid_handle(-1))
        self.assertFalse(_is_valid_handle(0xFFFFFFFFFFFFFFFF))
        self.assertTrue(_is_valid_handle(0x1234))

    def test_fake_smart_packed_temp_and_lifespan_metrics(self) -> None:
        rep = DriveForensicReport(
            drive_index=0,
            model="Qunion SSD 2TB",
            serial_number="YS000123",
            capacity_gb=1863.02,
            trim_supported=True,
            reported_health_pct=100,
            true_health_pct=64,
            gp_log04=GpLog04Stats(
                supported=True,
                power_on_resets=180,
                power_on_hours=6158,
                logical_sectors_written=28_600_000_000,  # ~13.32 TiB
                write_commands=900_000_000,
                sata_hardware_resets=6213,
                current_temp_c=40,
                max_temp_c=0,
                min_temp_c=0,
                percentage_used_endurance=36,
            ),
            vendor_nand=VendorNandStats(
                detected=True,
                controller_hint="Yeestor YS9082HP",
                max_erase_count=187,
                min_erase_count=4,
                avg_erase_count=23,
                factory_bad_blocks=12,
                grown_bad_blocks=0,
            ),
        )
        # Packed 0xC2 raw value with min/max in upper bytes and 40 (0x28) in low byte
        smart_map = {
            0xC2: SmartAttribute(0xC2, "Temperature Celsius", 0, 40, 40, 0x002800280028),
            0xA9: SmartAttribute(0xA9, "Remaining Life Percentage", 0, 100, 100, 100),
        }
        _evaluate_anomalies(rep, smart_map)
        codes = {a.code for a in rep.anomalies}
        self.assertTrue(rep.is_fake_smart)
        self.assertIn("FAKE_SMART_ENDURANCE", codes)
        self.assertIn("HARDCODED_TEMP_40C", codes)
        self.assertIn("SATA_LINK_RESET_STORM", codes)
        self.assertIn("FTL_STATIC_BLOCK_WEAR_SKEW", codes)

        life = compute_lifespan_metrics(rep, smart_map)
        self.assertLess(life.composite_health_score, 64)
        self.assertGreater(life.daily_host_writes_gib, 40.0)
        self.assertGreater(life.effective_wear_factor, 10.0)
        self.assertIsNotNone(life.estimated_remaining_days)

    def test_forensic_snapshot_diff_and_cli_diff(self) -> None:
        old_snap = {
            "serial_number": "YS000123",
            "model": "Qunion SSD 2TB",
            "true_health_pct": 64,
            "gp_log04": {
                "power_on_hours": 6158,
                "logical_sectors_written": 28_600_000_000,
                "percentage_used_endurance": 36,
                "sata_hardware_resets": 6213,
            },
            "vendor_nand": {
                "max_erase_count": 187,
                "avg_erase_count": 23,
                "grown_bad_blocks": 0,
            },
        }
        new_snap = {
            "serial_number": "YS000123",
            "model": "Qunion SSD 2TB",
            "true_health_pct": 64,
            "gp_log04": {
                "power_on_hours": 6206,  # +48h (2 days)
                "logical_sectors_written": 28_600_000_000 + 8_388_608,  # +4.0 GiB over 2 days = 2.0 GiB/day
                "percentage_used_endurance": 36,
                "sata_hardware_resets": 6213,  # +0 link resets
            },
            "vendor_nand": {
                "max_erase_count": 187,
                "avg_erase_count": 23,
                "grown_bad_blocks": 0,
            },
        }
        delta = diff_forensic_reports(old_snap, new_snap)
        self.assertEqual(delta["delta_power_on_hours"], 48)
        self.assertAlmostEqual(delta["delta_host_writes_gib"], 4.0, places=2)
        self.assertAlmostEqual(delta["interval_writes_gib_per_day"], 2.0, places=2)
        self.assertTrue(delta["sata_link_stable"])

        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "old.json"
            p2 = Path(tmp) / "new.json"
            p1.write_text(json.dumps(old_snap), encoding="utf-8")
            p2.write_text(json.dumps(new_snap), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(["diff", str(p1), str(p2), "--json"])
            self.assertEqual(rc, 0)
            out_json = json.loads(buf.getvalue())
            self.assertTrue(out_json["sata_link_stable"])


class TestOptimizerAndWriteHunterHelpers(unittest.TestCase):
    def test_drive_letter_validation(self) -> None:
        self.assertEqual(normalize_drive_letter("r:"), "R")
        self.assertEqual(normalize_drive_letter(" E "), "E")
        for bad in ("", "C:\\", "R; calc.exe", "1", "AB"):
            with self.assertRaises(ValueError):
                normalize_drive_letter(bad)

    def test_junction_specs_and_file_classification(self) -> None:
        specs = get_default_junction_specs(r"R:\Temp")
        self.assertEqual(len(specs), 19)
        self.assertEqual(
            classify_file_path(r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cache\data_0"),
            "Browser / GPU Shader Cache",
        )
        self.assertEqual(
            classify_file_path(r"C:\ProgramData\NVIDIA Corporation\nvtopps\nct\001.log"),
            "Background Telemetry / Log",
        )
        self.assertEqual(
            classify_file_path(r"C:\Users\Alice\AppData\Local\pip\Cache\wheels\pkg.whl"),
            "Developer Package / Compile Cache",
        )


if __name__ == "__main__":
    unittest.main()
