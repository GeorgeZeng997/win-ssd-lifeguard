# Win-SSD-Lifeguard

**Deep ATA/ACS-3 SSD Forensics • Fake SMART ("Happy Meter") Detector • Real-Time Write Hunter • 7-Layer SSD Lifespan Extension Suite**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0078D6.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg)](#)

Many budget and OEM SATA SSDs built on **DRAM-less controllers** (such as Yeestor / SiliconGo `YS9082HP`/`YS9082HT`, Maxio `MAS1102`, or Phison `PS3111-S11`) ship with **firmware-locked SMART tables ("Happy Meters")**:
- Standard tools (CrystalDiskInfo, Windows WMI) read legacy SMART (`0xB0 / 0xD0`) and report **100% Health**, **40°C constant temperature**, and **0 CRC/Link errors** forever—even when the NAND is heavily worn or experiencing thousands of SATA PHY link resets.
- Worse, because DRAM-less controllers lack external SDRAM to cache the Flash Translation Layer (FTL) mapping table, small 4KB random writes (browser caches, telemetry logs, NTFS `LastAccess` updates, and oversized pagefiles) force the controller to repeatedly erase and rewrite a **tiny pool of fixed static SLC/FTL blocks**, causing `8x+` localized wear amplification.

**Win-SSD-Lifeguard** bypasses superficial OS health checks using raw Win32 `IOCTL_ATA_PASS_THROUGH` (`0x0004D02C`) to extract the **true hardware telemetry**, hunt down background write culprits in real time, and deploy a **7-Layer Lifespan Extension Suite** (including a zero-wear **Dynamic RAMDisk**, **19 NTFS Cache Junctions**, and **TRIM-First Hardware Over-Provisioning**).

---

## Key Features

### 1. Deep ATA/ACS-3 & Vendor NAND Forensics (Fake SMART Detector)
- **Raw `IOCTL_ATA_PASS_THROUGH` Inspection**:
  - `IDENTIFY DEVICE (0xEC)`: Extracts true LBA48 capacity, firmware revision, and DSM/TRIM capability.
  - `SMART READ DATA (0xB0 / 0xD0)`: Parses all 30 legacy SMART attributes and raw 48-bit counters.
  - **`READ LOG EXT (0x2F)` GP Log `0x04` (ACS-3 Device Statistics)**:
    - **Page `0x07` (Solid State Device Statistics)**: Reads the un-spoofed **Percentage Used Endurance Indicator**.
    - **Page `0x04` (Transport Statistics)**: Reveals hidden **SATA Hardware Link Resets** (`0x1845+`) and ASR events that legacy SMART `0xC7` hides.
    - **Page `0x05` (Temperature Statistics)**: Verifies whether the `40°C` SMART sensor is a hardcoded dummy constant (`Min/Max = 0°C`).
    - **Page `0x01` (General Statistics)**: True Power-On Hours, Power Cycles, Logical Sectors Written/Read, and average write command size.
  - **`SMART READ LOG (0xB0 / 0xD5)` Vendor Log `0xE0`**:
    - Decodes Yeestor / SiliconGo internal FTL & NAND flash telemetry: **Raw 6-Byte NAND Flash ID** (e.g., `98 48 98 03 76 E4` $\rightarrow$ Kioxia BiCS4 96-Layer 3D TLC), **Max / Min / Average Block Erase Counts**, **Factory vs. Grown Bad Blocks**, and **Static-Block Erase Skew Ratio (`Max / Avg`)**.

### 2. Real-Time High-Frequency Write Hunter
- Simultaneously samples Windows `PhysicalDisk` / `LogicalDisk` hardware write IOPS and throughput (`KB/s`) alongside per-process `WriteTransferCount` / `WriteOperationCount` deltas.
- Computes the live **RAMDisk & Cache Interception Ratio (%)**—showing how much process write traffic is absorbed in RAM before ever reaching physical NAND.
- Scans physical directories on `C:` (automatically skipping `FILE_ATTRIBUTE_REPARSE_POINT` junctions) to pinpoint the exact files modified in the last N minutes (`Browser IndexedDB/LevelDB`, `Background Telemetry`, `Package Caches`, `Event Logs`).

### 3. 7-Layer SSD Rescue & Lifespan Extension Suite
| Layer | Protection Mechanism | Technical Implementation | Impact |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **SATA AHCI Link Power Lock** | Unhides & sets `HIPM/DIPM` (`0b2d69d7...`) and `Adaptive` (`dab60367...`) to `Active (0)` | Stops SATA PHY link drops (`6,000+` resets) and emergency FTL rebuilds |
| **Layer 2** | **Disable NTFS `LastAccess`** | `fsutil behavior set DisableLastAccess 1` & `DisableDeleteNotification 0` | Eliminates companion `$MFT` metadata writes on file reads |
| **Layer 3** | **Right-Size `pagefile.sys`** | Locks bloated `C:\pagefile.sys` (e.g. `64 GB` $\rightarrow$ fixed `4096 MB`) via WMI/CIM | Reclaims ~60 GB of SSD space and stops background page thrashing |
| **Layer 4** | **Multi-Volume ATA `ReTrim`** | Runs `Optimize-Volume -ReTrim` across `C:`, `D:`, `E:` | Flushes `1+ TB` of stale LBA mappings in the controller's FTL |
| **Layer 5** | **Dynamic RAMDisk (`R:`)** | Configures ImDisk `RamDyn.exe` (`-1` native TRIM / `FSCTL_GET_VOLUME_BITMAP`) + `ImDiskRD` service + `TEMP`/`TMP` redirect | 16 GB NTFS RAMDisk uses only `~33 MB` idle RAM, writes at `~1 GB/s`, frees RAM automatically on file deletion |
| **Layer 6** | **19 Cache & Telemetry NTFS Junctions** | Converts Chrome/Edge caches, `pip`, `npm`, `uv`, `CrashDumps`, `D3DSCache`, `NVIDIA DXCache/GLCache/nvtopps`, `WPS`, and `Feishu/Lark` logs into `mklink /J` junctions pointing to `R:\Temp`, backed by boot-time `init_ramdisk_dirs.cmd` (`R_RunObject`) | Offloads ~90% of daily 4KB random writes to RAM with zero application reconfiguration |
| **Layer 7** | **Hardware Over-Provisioning (OP)** | Executes ATA `ReTrim` on the tail volume first, then non-destructively shrinks it (e.g., `100 GB`) | Gives the DRAM-less controller a permanent, pre-TRIMmed 100 GB spare block pool for GC and wear leveling |

---

## Real-World Forensic Case Study

On a workstation equipped with a **2TB SATA SSD (`Qunion SSD 2TB`, Yeestor `YS9082HP` DRAM-less controller + Kioxia BiCS4 96L TLC `98 48 98 03 76 E4`)** after ~6,158 power-on hours:

1. **What standard SMART tools reported (`0xB0`)**:
   - `Remaining Life (0xA9)`: **`100%`**
   - `Temperature (0xC2)`: **`40°C`** (never changes)
   - `UDMA CRC Errors (0xC7)`: **`0`**
2. **What `win-ssd-lifeguard audit` uncovered (`GP Log 0x04` + `Vendor Log 0xE0`)**:
   - **True Endurance Consumed (`GP Log 0x04 Page 0x07`)**: **`36%` used (`64%` remaining health)** despite only **`13.32 TiB`** of total host writes!
   - **Concentrated Static-Block Erase Skew (`Vendor Log 0xE0`)**:
     - `Max Block Erase Count`: **`187`**
     - `Average Block Erase Count`: **`23`** (`Min = 4`)
     - **Erase Skew Ratio**: **`8.13x`** (`187 / 23`) — proving the DRAM-less controller was repeatedly hammering a small fixed pool of static SLC/FTL metadata blocks due to continuous 4KB temporary/telemetry writes and `6,213` SATA HIPM/DIPM link resets.
3. **Post-Remediation Result**:
   - After deploying all 7 layers (including the 16 GB Dynamic RAMDisk `R:`, 19 NTFS cache/telemetry junctions, and 100 GB Hardware OP), background physical SSD write activity dropped from continuous high-IOPS chatter to **`~0–8 IOPS`** (`~90%` of process write operations intercepted in RAM).

---

## Quick Start

### 1. Standalone Windows Executable (GUI & CLI)
Download `win-ssd-lifeguard-windows-x64.exe` from the [Releases](https://github.com/GeorgeZeng997/win-ssd-lifeguard/releases) page and run as **Administrator**:
- Double-click `win-ssd-lifeguard-windows-x64.exe` to launch the **4-Tab Dark-Themed Desktop GUI**.
- Or run from an elevated terminal (`PowerShell` / `cmd`) for CLI automation.

### 2. Install from Source
```bash
git clone https://github.com/GeorgeZeng997/win-ssd-lifeguard.git
cd win-ssd-lifeguard
pip install -e .
```

### 3. CLI Usage Examples
```bash
# Launch Desktop GUI
win-ssd-lifeguard gui

# 1. Deep ATA/ACS-3 Forensic Audit & Fake SMART Check
win-ssd-lifeguard audit --drive 0
win-ssd-lifeguard audit --drive 0 --json

# 2. Hunt Real-Time High-Frequency Disk Writes (5s sample)
win-ssd-lifeguard hunt --duration 5 --minutes 2

# 3. Check Status of All 7 SSD Lifespan Protection Layers
win-ssd-lifeguard status

# 4. Apply OS & Power Fixes (SATA LPM + NTFS LastAccess + 4GB Pagefile + ReTrim)
win-ssd-lifeguard optimize --all

# 5. Deploy 16 GB Dynamic RAMDisk (R:) & Offload 19 Cache/Telemetry Directories
win-ssd-lifeguard ramdisk --size-gb 16 --drive R --junctions

# 6. Reserve 100 GB Unallocated Hardware Over-Provisioning (OP) Space from E:
win-ssd-lifeguard op --drive E --size-gb 100
```

---

## License

Released under the [MIT License](LICENSE).
