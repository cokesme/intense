# Samsung Galaxy S22 (`SM-S901U1`) Bootloader & Firmware Architecture

This document describes the architecture, binary structure, trust boundaries, and boot/runtime interactions of the **32 firmware images** in the extracted Samsung **`BL` (Bootloader)** package.

---

## 1. Platform & Build Identity

| Property | Observed Value |
| :--- | :--- |
| **Device / Model** | Samsung Galaxy S22 (`r0q`, `SM-S901U1`, CSC `NA_XAA`, `R0Q_USA_OPEN`) |
| **Samsung Build / CL** | `S901U1UES8GYK3` / CL `103321188R` (signed `2025-11-10`) |
| **SoC / Platform** | Qualcomm Snapdragon 8 Gen 1 (`SM8450` / `SM8450P`, codename `Waipio`, `soc_hw=0xa001`, `oem_id=0x20`) |
| **Qualcomm Metabuild** | `Waipio.LA.1.0.r1-00808-STD.PROD-1` |
| **Core Firmware Versions** | Boot `BOOT.MXF.2.0-00805-WAIPIO-1` · TZ/Hyp `TZ.XF.5.18-44858-40` (`WAPIONAAA`) · AOP `AOP.HO.4.0-00388-WAIPIO_E-1` · CPUCP `CPUCP.FW.1.0-00081-WAIPIO.EXT-5` · DDR `272.56.227` |
| **AVB Security Patch** | `2025-11-01` (Boot/Vendor OS `12`, System OS `16` per `vbmeta.img` properties) |

---

## 2. SoC Hardware & Execution Privilege Architecture

The Snapdragon 8 Gen 1 (`SM8450`) runs firmware across **six distinct processor architectures / execution environments**: the Trust Management Engine (TME), Application Processor Subsystem (`APSS` ARMv8 across EL3/S-EL1/EL2/EL1/EL0), three power/memory/serial microcontrollers (`AOP`, `CPUCP`, `SHRM`, plus `QUPv3` serial engines), Hexagon `QDSP6` DSPs (`ADSP`, `CDSP`, `SLPI`, `GPU ZAP`, `IPA`), Tensilica `Xtensa` media processors (`CAMERA_ICP`, `VPU`, `EVA`), and the Secure Processing Subsystem (`SPU`).

```mermaid
flowchart TB
    subgraph HW["Hardware Root of Trust and Fuses"]
        PBL["PBL Mask ROM"]
        QFPROM["QFPROM eFuses (sec.elf: OEM_ID=0x20, OEM_PK_HASH, Knox WB, KG)"]
        RPMB["UFS RPMB and SFS Secure Storage"]
    end

    subgraph TME["Trust Management Engine (TME)"]
        SEQ["TME Sequencer (xbl_s.melf sub-ELF 0: SEQ_FW r79)"]
        TMERISC["TME Core - 32-bit RISC-V FreeRTOS (xbl_s.melf sub-ELF 1: TME_FW)"]
    end

    subgraph MCU["SoC Control Microcontrollers and Serial Engines"]
        AOP["AOP - ARM Cortex-M/R (aop.mbn + aop_devcfg.mbn)"]
        CPUCP["CPUCP - 32-bit RISC-V RVC (cpucp.elf)"]
        SHRM["SHRM - 32-bit RISC-V RVC (shrm.elf)"]
        QUPV3["QUPv3 GENI Engines (qupv3fw.elf: SPI/QSPI/I2C/I3C/UART)"]
    end

    subgraph APSS["Application Processor Subsystem (APSS - ARMv8 AArch64)"]
        subgraph SEC["Secure World (EL3 and S-EL1)"]
            EL3["EL3 Monitor and PSCI (tz.mbn @ 0x14680000)"]
            QTEE["S-EL1 QTEE Kernel (tz.mbn @ 0x1c00b000)"]
            QCOM_TAS["Platform TAs: uefi_sec.mbn, km41.mbn, storsec.mbn"]
            SAM_TAS["Samsung TAs: bksecapp.mbn, engmode.mbn, tz_hdm.mbn, tz_iccc.mbn, tz_kg.mbn, vaultkeeper.mbn"]
            NONHLOS_TAS["NON-HLOS.bin TAs (38 split + 4 monolithic TAs)"]
        end

        subgraph HYP["Non-Secure EL2 (Hypervisor)"]
            GUNYAH["Gunyah Hypervisor and Resource Manager (hypvm.mbn)"]
            SAM_UH["Samsung uH / RKP / KDP - Rust EL2 Payload (devcfg.mbn)"]
            CPUSYSVM["CPUSS Guest VM (cpusys_vm in NON-HLOS.bin)"]
        end

        subgraph NS_EL1["Non-Secure EL1 / EL0 (Bootloader -> Android HLOS)"]
            XBL["XBL Loader / SBL1 (xbl_s.melf sub-ELF 2 + xbl_config.elf)"]
            UEFI["UEFI SEC + DXE (uefi.elf + imagefv.elf + Core_NON-HLOS.bin)"]
            ABL["ABL Apps: LinuxLoader / Odin / Cryptest / QuestSOD (abl.elf)"]
            RAMDUMP["Crash Dump Mode (XblRamdump.elf)"]
            HLOS["Android Kernel and Userspace (verifies via vbmeta.img)"]
        end
    end

    subgraph SUBSYS["Offload Subsystems (Loaded from NON-HLOS.bin + dspso.bin)"]
        DSP["Hexagon QDSP6: adsp, cdsp, slpi, a730_zap, ipa_fws + dspso.bin .so libs"]
        XTENSA["Tensilica Xtensa: CAMERA_ICP, vpu20_4v, evass"]
        SPU["ARM SPU: spss1p (StrongBox / Secure Element)"]
    end

    PBL --> SEQ --> TMERISC
    QFPROM --- TMERISC
    QFPROM --- QTEE
    RPMB --- QTEE
    TMERISC -->|"Authenticates and Releases"| XBL
    XBL -->|"Loads and Configures"| AOP
    XBL -->|"Loads"| SHRM
    XBL -->|"Loads"| CPUCP
    XBL -->|"Loads"| QUPV3
    XBL -->|"Loads"| EL3
    XBL -->|"Loads"| GUNYAH
    XBL -->|"Hands off"| UEFI
    UEFI -->|"Launches"| ABL
    ABL -->|"Normal Boot (AVB)"| HLOS
    XBL -.->|"DLOAD / Fault Cookie"| RAMDUMP
    SAM_UH --- GUNYAH
    QTEE --- QCOM_TAS
    QTEE --- SAM_TAS
    QTEE --- NONHLOS_TAS
    HLOS -->|"PIL / FastRPC"| DSP
    HLOS -->|"PIL"| XTENSA
    QCOM_TAS -.->|"km41.mbn via spcom"| SPU
```

---

## 3. Boot Sequence & Execution Flow

### Cold Boot, Verified Boot, Download Mode & Crash Dump Paths

```mermaid
sequenceDiagram
    autonumber
    participant PBL as "PBL (Mask ROM)"
    participant TME as "TME (xbl_s.melf)"
    participant XBL as "XBL Loader (xbl_s.melf)"
    participant MCU as "SHRM / AOP / CPUCP / QUPv3"
    participant TZ as "TZ / QTEE (tz.mbn)"
    participant HYP as "Gunyah + uH/RKP (hypvm.mbn + devcfg.mbn)"
    participant UEFI as "UEFI (uefi.elf)"
    participant ABL as "ABL (abl.elf)"
    participant HLOS as "Android Kernel / Userspace"
    participant DSP as "Subsystems / DSPs"

    PBL->>TME: Load & verify xbl_s.melf (TME Sequencer + RISC-V TME_FW)
    TME->>TME: Check QFPROM OEM_PK_HASH (sec.elf) & anti-rollback
    TME->>XBL: Authenticate & start XBL Loader (AArch64 @ 0x14819fa8)
    XBL->>XBL: Read xbl_config.elf (DCB DDR tables, CPR, pre_ddr-soc.dtb, platform.dtb)
    XBL->>MCU: Load shrm.elf (LPDDR5 init), aop.mbn + aop_devcfg.mbn, cpucp.elf, qupv3fw.elf
    alt DLOAD / Minidump Cookie Set (0x01FD3000)
        XBL->>XBL: Launch XblRamdump.elf (@ 0xa7d00000) -> USB Sahara / SD / UFS Dump
    else Normal Boot
        XBL->>XBL: Apply apdp.mbn (Debug Policy) & sec.elf checks
        XBL->>TZ: Load & start EL3 Monitor + S-EL1 QTEE (tz.mbn)
        XBL->>HYP: Load EL2 Gunyah Hypervisor (hypvm.mbn) & devcfg.mbn (DALPROP + uH/RKP/KDP)
        XBL->>UEFI: Hand off to uefi.elf (@ 0xa7000000, Sec.dll + DXE FVs)
        UEFI->>UEFI: Init UFS, USB, Display, PMIC, SCM/TZ, VerifiedBootDxe
        UEFI->>ABL: QcomBds launches abl.elf (LinuxLoader)
        ABL->>TZ: Query/update bksecapp, tz_iccc, tz_kg, tz_hdm, uefi_sec, km41
        alt Download Mode Key / Reboot-to-Odin
            ABL->>ABL: Launch Odin app + load JPEG screens from imagefv.elf
        else Standard Boot
            ABL->>ABL: AVB 2.0 verify vbmeta.img (RSA-4096) -> xbl, tz, hyp, abl, boot, vendor_boot
            ABL->>HLOS: Boot Linux Kernel (EL1) under EL2 Gunyah + Samsung uH/RKP/KDP
            HLOS->>DSP: Mount NON-HLOS.bin (/vendor/firmware_mnt) & dspso.bin (/vendor/dsp)
        end
    end
```

---

## 4. Cryptographic Signing, Verification & Container Layers

Every binary in this package sits inside a multi-layered trust envelope tying hardware fuses (`QFPROM`) to Qualcomm MBN v7, Android Verified Boot (`AVB 2.0`), and Samsung's Odin flashing signature (`SignerVer02`).

```mermaid
flowchart LR
    subgraph ROOT["Hardware & Cryptographic Roots"]
        FUSE["QFPROM OEM_PK_HASH (sec.elf rows 0x221c0500..0x221c0530)\nSHA-384 of Samsung ECDSA384 ROOT 3"]
        QTI_ROOT["Qualcomm SRoT MBNv7 Image Signing Root CA 6\n(ECDSA P-384)"]
        AVB_KEY["AVB 2.0 RSA-4096 Public Key\n(modulus SHA-256: 357b7152...)"]
    end

    subgraph MBN["Qualcomm MBN v7 ELF Segment (PT_NULL)"]
        HASH_TBL["SHA-384 Hash Table\n(1 digest per ELF Program Header)"]
        META["common_metadata (sw_id, hash_algo=3)\n+ qti_metadata + oem_metadata (soc_hw=0xa001, oem_id=0x20)"]
        SIG_CHAIN["ECDSA-SHA384 Signatures + DER X.509 Chains\n(Dual QTI+OEM on Core FW; OEM-only on Configs/TAs)"]
    end

    subgraph AVB["AVB 2.0 Verification (vbmeta.img)"]
        VBMETA["vbmeta.img (AVB0, SHA256_RSA4096, flags=0)"]
        HASH_DESC["6 Hash Descriptors\nxbl, tz, hyp, abl, boot, vendor_boot"]
        TREE_DESC["6 dm-verity Hashtrees + FEC\nsystem, system_ext, vendor, vendor_dlkm, product, odm"]
        CHAIN_DESC["4 Chained Partitions\nrecovery, dtbo, prism, optics"]
    end

    subgraph ODIN["Samsung Odin Flashing Wrapper"]
        SIGNER["SignerVer02 512-byte Footer\n(31 of 32 files; omitted on dspso.bin)\nS901U1UES8GYK3 | SM-S901U1_NA_XAA_QKEY0 | SRPUG22A008"]
    end

    FUSE -->|"Verifies OEM Chain"| SIG_CHAIN
    QTI_ROOT -->|"Verifies QTI Chain"| SIG_CHAIN
    HASH_TBL --> META --> SIG_CHAIN
    AVB_KEY -->|"Signs"| VBMETA
    VBMETA --> HASH_DESC
    VBMETA --> TREE_DESC
    VBMETA --> CHAIN_DESC
    SIGNER -.->|"Verified by abl.elf Odin during flashing"| MBN
```

### Key Container Observations
1. **MBN v7 Metadata vs. Legacy OU Fields**: Unlike older Qualcomm MBN v3/v5 images, MBN v7 stores `sw_id`, `hw_id`/`soc_hw`, `oem_id`, and `anti_rollback_ver` in binary metadata structs (`common_metadata` / `qti_metadata` / `oem_metadata`) rather than X.509 `OU` strings.
2. **Qualcomm Wrapper Machine-ID Quirks**:
   - `xbl_s.melf` (sub-ELF 0) and `xbl_config.elf` set `e_machine = EM_M32` (`AT&T WE32100`, value `1`) as Qualcomm's dummy tag for proprietary data/sequencer containers.
   - `uefi.elf` (`ELFCLASS64`) and `abl.elf` (`ELFCLASS32`) set `e_machine = EM_ARM` (`40`) on the outer ELF wrapper even though every PE32+/TE UEFI driver and application inside their Firmware Volumes is **AArch64 (`0xaa64`)**.
3. **Production Blank Placeholders**: `QcomCate.fv`, `quest.fv`, and `testvector.fv` are 100% zero-filled (`0x00`) up to their 512-byte `SignerVer02` footer; meanwhile, `Core_NON-HLOS.bin` holds the actual LZMA-compressed `QcomCatePkg` UEFI volume (built from a `LAHAINA-1` tree).

---

## 5. TrustZone (`QTEE`), RPMB & Samsung Security Architecture

All 9 standalone `.mbn` Trusted Applications (`sw_id=0xc`, `ELF64 ET_DYN`, linked against `libcmnlib.so` via MINK/GPAppLib) run in **S-EL1 QTEE** (`tz.mbn`), isolating hardware fuses, RPMB partitions, and cryptographic keys from Android (`EL1`/`EL0`).

```mermaid
flowchart LR
    subgraph CALLERS["Non-Secure Callers (ABL / Android HALs / Apps)"]
        ABL_C["abl.elf (Bootloader)"]
        KG_HAL["kg-service HAL (PROCA auth)"]
        VK_CLIENTS["12 Samsung Vault Clients\n(DRK, FMM, Rampart, SSU, CASS, AASA, AID, etc.)"]
        KM_HAL["Android KeyMint / StrongBox HAL"]
        UEFI_C["uefi.elf (Boot Services)"]
    end

    subgraph QTEE_TA["S-EL1 QTEE Trustlets"]
        BK["bksecapp.mbn\n(BL lock, Knox WB fuse, EK fuse, SHK wrap)"]
        ICCC["tz_iccc.mbn\n(BL/ROT/TA/KERN/SYS/BLDP integrity & DIR)"]
        HDM["tz_hdm.mbn\n(JWS Enterprise/Privoro HW block policies)"]
        KG["tz_kg.mbn\n(Knox Guard lock, HOTP/ECDH, KG fuse)"]
        VK["vaultkeeper.mbn\n(Sheltered/unsheltered encrypted vaults)"]
        ENG["engmode.mbn\n(Signed factory/diag tokens & ESS)"]
        KM["km41.mbn\n(Keymaster 4.x + KeyMint + RKP + ICE)"]
        USEC["uefi_sec.mbn\n(Authenticated UEFI variables & PKCS#7)"]
        STOR["storsec.mbn\n(UFS Secure Write-Protect)"]
    end

    subgraph SEC_RES["Protected Hardware & Storage"]
        RPMB_P["UFS RPMB Partitions\n(engmode, vaultkeeper, bksecapp, etc.)"]
        SFS["Secure File System (SFS) & OEM Buffer"]
        FUSES["QFPROM Fuses & SHK / GPCE HW Keys"]
        SPU_HW["SPSS / StrongBox (spss1p via spcom)"]
    end

    ABL_C --> BK
    ABL_C --> ICCC
    ABL_C --> KG
    ABL_C --> HDM
    KG_HAL --> KG
    VK_CLIENTS --> VK
    KM_HAL --> KM
    UEFI_C --> USEC
    UEFI_C --> STOR

    HDM <-->|"Cross-check policies"| ICCC
    HDM <-->|"KG_BLOCK / UNBLOCK"| KG
    BK --> FUSES
    BK --> RPMB_P
    KG --> FUSES
    KG --> RPMB_P
    VK --> RPMB_P
    VK --> SFS
    ENG --> RPMB_P
    ICCC --> SFS
    USEC --> RPMB_P
    KM --> RPMB_P
    KM <--> SPU_HW
```

---

## 6. Complete File Reference (All 32 Files)

### 6.1 Primary Boot Chain & Crash Handling

| File | Size (Bytes) | Format / Arch | `sw_id` / Signing | Load / Entry | Purpose |
| :--- | ---: | :--- | :--- | :--- | :--- |
| `xbl_s.melf` | 4,194,304 | Multi-ELF (3 ELFs: `EM_M32`, `RISC-V`, `AArch64`) + AVB + `SignerVer02` | `0x35` (TME), `0x36` (XBL); Dual QTI+OEM | `0x2211c000` / `0x20412800` / `0x14819fa8` | Stage-1 bootloader: TME Sequencer (`SEQ_FW r79`), RISC-V TME RoT FW (`ssg.tmefw.1.0.1`), and AArch64 XBL Loader (`BOOT.MXF.2.0-00805-WAIPIO-1`). |
| `xbl_config.elf` | 143,132 | ELF64 (`EM_M32` container) + `SignerVer02` | `0x25`; OEM-only | `0x1494e000` | `CFGL` archive containing DDR calibration bins (`A001_8_0100/0200_1_dcb.bin`), `cpr.bin`, `pre_ddr-soc.dtb`, and `platform.dtb` (`qcom,waipio-mtp`). |
| `uefi.elf` | 3,153,452 | ELF64 (`EM_ARM` wrapper, AArch64 UEFI FV) + `SignerVer02` | `0x9`; OEM-only | `0xa7000000` | XBL Core UEFI (`Sec.dll`, `uefiplat.cfg`, 2 Gzip FVs with `DxeCore`, ~95 DXE drivers, `QcomBds`, `QcomChargerApp`, `SamsungQuestApp`, `SamsungDdrApp`, 32 panel XMLs). |
| `abl.elf` | 4,194,304 | ELF32 (`EM_ARM` wrapper, AArch64 UEFI FV) + AVB + `SignerVer02` | `0x1c`; OEM-only | `0x9fa00000` | Android Bootloader LZMA FV containing 4 AArch64 UEFI apps: `LinuxLoader` (AVB 2.0 + Knox/FMM checks), `Odin` (Download Mode flashing), `Cryptest`, and `QuestSOD`. |
| `XblRamdump.elf` | 1,707,660 | ELF64 (`AArch64`) + `SignerVer02` | `0x42`; OEM-only | `0xa7d00000` | Crash/memory dump handler triggered by DLOAD/minidump cookies; dumps DRAM/AOP/TZ/SMMU/NOC via USB Sahara, SD/FAT, UFS/NVMe, or enters EDL. |

### 6.2 SoC Microcontrollers, Peripheral Firmware & Configs

| File | Size (Bytes) | Format / Arch | `sw_id` / Signing | Load / Entry | Purpose |
| :--- | ---: | :--- | :--- | :--- | :--- |
| `aop.mbn` | 258,736 | ELF32 (`ARM`) + `SignerVer02` | `0x21`; Dual QTI+OEM | `0xb000009` | Always-On Processor firmware (`AOP.HO.4.0-00388-WAIPIO_E-1`) managing RPMh power domains, PMIC rails, clocks, and sleep modes. |
| `aop_devcfg.mbn` | 15,964 | ELF32 (`ARM`, data) + `SignerVer02` | `0x3d`; OEM-only | `0x80880000` | AOP DeviceConfig mapping 119 PMIC VRM/LDO/SMPS/GPIO/clock resources (`smpb*`, `bobc1`, `rfclka*`, `vrm.*`). |
| `cpucp.elf` | 156,160 | ELF32 (`RISC-V` RVC) + `SignerVer02` | `0x31`; Dual QTI+OEM | `0x90` (`0x17d00000` / `0x80b00000`) | CPU Control Processor FW handling cluster (`Silver`/`Gold_Plus`) DVFS/DCVS, thermal limits, `CPRh`, `ACD`, `APM`, and `SCMI`. |
| `shrm.elf` | 69,464 | ELF32 (`RISC-V` RVC) + `SignerVer02` | `0x20`; Dual QTI+OEM | `0x200000` (`paddr=0x19040000`) | Shared Resource Manager FW (`DDR_FW version : 272.56.227`) managing LPDDR5 frequency scaling, retention, and DRAM PHY/controller states. |
| `qupv3fw.elf` | 51,644 | ELF32 (`QDSP6`-tagged) + `SignerVer02` | `0x24`; Dual QTI+OEM | `paddr=0x1000..0x79c0` | QUPv3 (HW `0x3008`) serial engine firmware bundle: `QSI` common image plus `SEFW` microcode for SPI, QSPI, I2C, I3C (x2), UART, and `proto=0x6`. |
| `devcfg.mbn` | 339,788 | ELF64 (`AArch64`) + `SignerVer02` | `0x5`; OEM-only | `0x1c000000` / `0x805a0000` | TZ/HYP DALPROP tables (QUPv3/GPII perms, SMMU, NOC/DDRSS, `HypX*`) **plus** an executable Rust-compiled EL2 binary implementing Samsung **uH / RKP / KDP**. |
| `apdp.mbn` | 11,820 | ELF32 (`ET_NONE`, `ARM`) + `SignerVer02` | `0x200`; OEM-only | `0x149fd000` | Application Processor Debug Policy (TLV struct governing JTAG/debug/crashdump permissions for `soc_hw=0xa001ffff`, `oem_id=0x20`). |
| `sec.elf` | 11,820 | ELF64 (`ET_NONE`, `ARM`) + `SignerVer02` | `0x2b`; OEM-only | `0x808ff000` | SecDat (`ver=3`, 21 QFPROM entries) specifying `OEM_ID=0x20` and 7 FEC-encoded `OEM_PK_HASH` rows matching `ECDSA384 ROOT 3`. |

### 6.3 Hypervisor, TrustZone & Platform Trustlets

| File | Size (Bytes) | Format / Exec Level | `sw_id` / Signing | App Name / Key Symbols | Purpose |
| :--- | ---: | :--- | :--- | :--- | :--- |
| `hypvm.mbn` | 10,485,760 | ELF64 PIE (`AArch64`, NS-EL2) + AVB + `SignerVer02` | `0x15`; Dual QTI+OEM | `gunyah-e86e9edb0 perf`, `GKPG` (`musl-c-runtime`, `resource-manager`) | Gunyah Hypervisor & RootVM Resource Manager: Stage-2 isolation, SMMU virtualization, `hyp_assign`/`memparcel`, Gunyah IPC, dynamic DT overlays. |
| `tz.mbn` | 4,194,304 | ELF64 (`AArch64`, EL3 + S-EL1) + AVB + `SignerVer02` | `0x7`; Dual QTI+OEM | `TZ.XF.5.18-44858-40` | EL3 PSCI/CPU power-gating monitor (`0x14680000`) + S-EL1 QTEE kernel (`0x1c00b000`): MINK IPC, TA loader, GPCE HW crypto, SMMUv3/VMIDMT, RPMB, `KeymasterLite`. |
| `uefi_sec.mbn` | 171,852 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `qcom.tz.uefisecapp` | Manages authenticated UEFI Secure Boot variables (`PK`, `KEK`, `db`, `dbx`) in RPMB/UFS, enforces variable policies, and verifies PKCS#7/X.509 signatures. |
| `km41.mbn` | 315,212 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `keymaster64` | Implements Keymaster 4.x and **Android KeyMint** (`KEYMINT_*`, RKP CSRs), StrongBox/SPU bridging (`IStrongBox_*`), Trusted Confirmation UI, attestation, and ICE keys. |
| `storsec.mbn` | 32,588 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `qcom.tz.storsecapp` | Minimal storage security TA exposing `CMD_GET_SECURE_WP_CONFIG` and `CMD_SET_SECURE_WP_CONFIG` for UFS write-protection. |
| `bksecapp.mbn` | 65,356 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `bksecapp` (`v2.0.0`) | Samsung boot-phase TA: enforces pre-HLOS lock (`SetBlBootComplete`), reads/blows Knox Warranty Bit & EK fuses, sets KASLR flag, wraps keys via SHK, and manages `bksecapp` RPMB. |

### 6.4 Samsung Security Trustlets & Verified Boot

| File | Size (Bytes) | Format / Exec Level | `sw_id` / Signing | App Name / Key Details | Purpose |
| :--- | ---: | :--- | :--- | :--- | :--- |
| `engmode.mbn` | 1,294,156 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `engmode` | Verifies Samsung-signed engineering/diagnostic unlock tokens (`EM_CMD_INSTALL_TOKEN`, ESS v1) and recovery counters in RPMB to gate factory/engineering modes. |
| `tz_hdm.mbn` | 1,363,788 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `tz_hdm` | Samsung Hardware Device Manager: enforces enterprise/Knox/Privoro hardware-blocking policies (`device_block`, `compromised_block`, `btonly_bit`) using JWS-signed policies, QFPROM fuses, RPMB, ICCC, and KG. |
| `tz_iccc.mbn` | 85,836 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `tz_iccc` | Samsung Integrity Check & Control: tracks cross-stage security state (`BL`, `ROT`, `TA`, `KERN`, `SYS`, `BLDP`), enforces TA/UID command permissions, and produces Device Integrity Reports (`DIR`). |
| `tz_kg.mbn` | 1,527,628 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `tz_kg` | Samsung Knox Guard: enforces financing/enterprise device locks, authenticates `kg-service` via PROCA, manages KG QFPROM fuse bits, and verifies HOTP/ECDH/RSA unlock tokens. |
| `vaultkeeper.mbn` | 1,011,532 | ELF64 `ET_DYN` (`AArch64` S-EL1 TA) + `SignerVer02` | `0xc`; OEM TA chain | `vaultkeeper` | Provides isolated, rollback-protected RPMB/SFS sheltered & unsheltered vaults for 12 Samsung clients (`DRK`, `FMM`, `RAMPART`, `SSU`, `CASS`, `AASA`, `AID`, `BT`, `WIFI`, `SWIFI`, `RTTS`, `SBAUTH`) gated by PROCA & custom-kernel checks. |
| `vbmeta.img` | 10,176 | AVB 2.0 (`AVB0`) + `SignerVer02` | `SHA256_RSA4096`, `flags=0` | `avbtool 1.3.0`, 22 descriptors | Top-level AVB root verifying 6 hash partitions (`abl`, `boot`, `hyp`, `tz`, `vendor_boot`, `xbl`), 6 dm-verity hashtrees (`system`, `system_ext`, `vendor`, `vendor_dlkm`, `product`, `odm`), and 4 chained partitions (`recovery`, `dtbo`, `prism`, `optics`). |

### 6.5 UEFI Firmware Volumes, Boot Graphics & Diagnostic Placeholders

| File | Size (Bytes) | Format | Signing | Contents & Purpose |
| :--- | ---: | :--- | :--- | :--- |
| `imagefv.elf` | 8,396,332 | ELF32 (`ARM`) + UEFI FV (LZMA) + `SignerVer02` | MBN v7 (`0x27`, OEM) | Stores 26 JPEG UI assets used by ABL/Odin (`download.jpg`, `download_error.jpg`, `warning.jpg`, `warning_svb.jpg`, `device_lock.jpg`, `device_unlock.jpg`, `secure_error.jpg`, `orange_state*.jpg`, `custom_logo*.jpg`, `SUD_0..10.jpg`, `android_logo.jpg`, `setting_logo.jpg`). |
| `Core_NON-HLOS.bin` | 524,800 | Raw UEFI FV (LZMA) + `SignerVer02` | Footer only | Contains `QcomCatePkg` (`CateApp`, `CATEDxe`, `CateSampleDxe`, `Smp2pDxe`, `SSRDxe`, and 2 Q6 test joblists) built from `BOOT.MXF.1.0-00405-LAHAINA-1`. |
| `QcomCate.fv` | 524,800 | 512 KiB zero-filled + `SignerVer02` | Footer only | Empty production partition placeholder for `qcomcate` (active payload is in `Core_NON-HLOS.bin`). |
| `quest.fv` | 590,336 | 576 KiB zero-filled + `SignerVer02` | Footer only | Empty production partition placeholder for Qualcomm QUEST (UEFI Self-Test). |
| `testvector.fv` | 8,389,120 | 8 MiB zero-filled + `SignerVer02` | Footer only | Empty production partition placeholder for diagnostic `testvector` FV. |

### 6.6 Subsystem & DSP Filesystem Images

| File | Size (Bytes) | Format / Mount Point | Contents & Purpose |
| :--- | ---: | :--- | :--- |
| `NON-HLOS.bin` | 116,388,352 | FAT16 (`4096` B/sector) + `SignerVer02` (`/vendor/firmware_mnt`) | 553 files: `verinfo/` (`ver_info.txt`, `slpi_ver.txt`) and `image/` holding 10 split subsystems (`adsp`, `cdsp`, `slpi`, `CAMERA_ICP`, `vpu20_4v`, `evass`, `a730_zap`, `ipa_fws`, `spss1p`, `cpusys_vm`), 38 split TAs (37 AArch64 ELFs + encrypted `prov`), 8 monolithic ELFs/TAs (`widevine.mbn`, `rtic.mbn`, `tuiauthapp.mbn`, `eid.mbn`, etc.), 5 QMI service-registry JSONs, and `gptauuid.xml`. *(Modem/WLAN firmware resides outside this image, e.g. in `CP`.)* |
| `dspso.bin` | 67,108,864 | ext4 (`64 MiB`, label `dsp`) (`/vendor/dsp`) | 83 files (78 Hexagon `QDSP6` `ET_DYN` shared libs/FastRPC shells + 5 `map_*.txt` manifests): `/adsp` (40 libs: audio codecs, Fluence voice modules, `fastrpc_shell_0`), `/cdsp` (31 libs: EVA/CVP vision, `libvpp_*` AI/QNN/FRC, camera streamer, `fastrpc_shell_3`), `/sdsp` (7 libs: sensor skels, `fastrpc_shell_2`). |
