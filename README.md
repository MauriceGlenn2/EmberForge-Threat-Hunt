# 🔥 IR-2026-0131-EF // EMBERFORGE: SOURCE LEAK
> **Status: 🚧 Work in Progress** — Investigation active. Flags updating as hunt progresses.

---

## Incident Overview

| Field | Detail |
|---|---|
| **Case ID** | IR-2026-0131-EF |
| **Severity** | Critical |
| **Reported** | 2026-01-30 |
| **Environment** | emberforge.local |
| **Platform** | Microsoft Sentinel — `EmberForgeX_CL` |
| **Log Sources** | Sysmon + Windows Security + Windows System |
| **Investigation Window** | 2026-01-30 21:00 UTC → 2026-01-31 00:00 UTC |

**Trigger:** Unreleased source code from EmberForge Studios' upcoming title *Neon Shadows* appeared on underground forums. External threat intelligence flagged the leak within 48 hours.

---

## Affected Assets

| Host | IP | Role |
|---|---|---|
| EC2AMAZ-B9GHHO6 | 10.1.173.145 | Workstation (Patient Zero) |
| EC2AMAZ-16V3AU4 | 10.1.57.66 | Server |
| EC2AMAZ-EEU3IA2 | 10.1.160.76 | Domain Controller |

---

## ATT&CK Kill Chain

```
Initial Access → Execution → [LOCKED] → [LOCKED] → [LOCKED] → Exfiltration
```

---

## Flag Progress

### Phase 01 — Exfiltration

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 1 | Source directory of stolen data | `C:\GameDev` | 2026-01-30 23:11:28 |
| Flag 2 | Cloud provider that received data | `MEGA` | — |
| Flag 3 | Attacker email used to authenticate | `jwilson.vhr@proton.me` | — |
| Flag 5 | Exfiltration tool | `rclone.exe` | 2026-01-30 23:06:36 |
| Flag 6 | Destination IP | `66.203.125.15` | 2026-01-30 23:12:53 |
| Flag 7 | Plaintext password exposed in command line | `Summer2024!` | — |
| Flag 8 | Compression cmdlet used (LOTL) | `Compress-Archive` | — |
| Flag 9 | Attacker staging server | `sync.cloud-endpoint.net` | — |

### Phase 02 — Credential Access

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 4 | Domain credential file accessed via VSS | `ntds.dit` | 2026-01-30 23:35:10 |

### Phase 03 — Initial Access

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 10 | Malicious file loaded on workstation | `review.dll` | 2026-01-30 21:27:03 |
| Flag 11 | Drive letter (ISO mount bypass) | `D:` | — |
| Flag 12 | Patient zero account | `lmartin` | — |
| Flag 13 | Execution chain | `explorer.exe > rundll32.exe > review.dll` | — |
| Flag 14 | Extraction step | `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\` | 2026-01-30 21:24:04 |
| Flag 15 | Primary C2 payload dropped | `C:\Users\Public\update.exe` | 2026-01-30 21:40:24 |

### Phase 04 — Command & Control

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 15 | C2 beacon domain | `cdn.cloud-endpoint.net` | — |
| Flag 16 | Resolved C2 IP | `104.21.30.237` | — |

---

## Attack Narrative

### Delivery
Lisa Martin (`lmartin`) was targeted via a spearphishing lure. She downloaded a 7-Zip installer (`7z2501-x64.exe`) via Edge browser, which installed 7-Zip and extracted a malicious ISO archive containing `review.dll`.

### Initial Access
The ISO was mounted as `D:` — bypassing Windows Mark of the Web (MOTW) protections. Lisa double-clicked `review.dll` from Explorer, which was loaded via `rundll32.exe` calling the `StartW` export — a common C2 framework DLL payload pattern.

```
msedge.exe
  └── 7z2501-x64.exe          (7-Zip installer)
      └── 7zG.exe              (archive extraction → EmberForge_Review\)
          └── explorer.exe     (Lisa browses D: drive)
              └── rundll32.exe "D:\review.dll,StartW"   ← initial execution
```

### Execution & Privilege Escalation
The DLL dropped `update.exe` to `C:\Users\Public\` and established persistence via scheduled task named `WindowsUpdate`. A `fodhelper.exe` UAC bypass was used to elevate privileges silently.

```
rundll32.exe (review.dll)
  └── schtasks → WindowsUpdate task (C:\Users\Public\update.exe)
  └── reg.exe → ms-settings COM hijack (fodhelper UAC bypass)
      └── fodhelper.exe → update.exe (elevated)
          └── schtasks → WindowsUpdate as SYSTEM
```

### Command & Control
`update.exe` beaconed to `cdn.cloud-endpoint.net` resolving to `104.21.30.237` via HTTPS (port 443), routing through Cloudflare to obscure the true origin server.

### Exfiltration
From the server (`EC2AMAZ-16V3AU4`), the attacker:
1. Compressed `C:\GameDev` → `C:\Users\Public\gamedev.zip` using `Compress-Archive`
2. Uploaded via `rclone.exe` to MEGA account `jwilson.vhr@proton.me`
3. Destination IP: `66.203.125.15` (`bt5.api.mega.co.nz`)

### Credential Access
On the Domain Controller, the attacker used VSS (Volume Shadow Copy) to access the locked `ntds.dit` file, extracting every domain credential hash:

```
vssadmin create shadow /For=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
vssadmin delete shadows /Quiet   ← evidence destroyed
```

---

## Attacker Infrastructure

| Asset | Value |
|---|---|
| Staging server | `sync.cloud-endpoint.net:8080` |
| C2 domain | `cdn.cloud-endpoint.net` |
| C2 IP | `104.21.30.237`, `172.67.174.46` (Cloudflare proxied) |
| Exfil destination | `bt5.api.mega.co.nz` / `66.203.125.15` |
| MEGA account | `jwilson.vhr@proton.me` |

---

## Key KQL Queries

```kql
// Process executions — workstation
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| project UtcTime_s, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

// Exfil tool network connections
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s contains "rclone"
| project UtcTime_s, Computer, DestinationIp_s, DestinationPort_s, DestinationHostname_s

// VSS credential theft — DC
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s has_any ("vssadmin", "shadow", "ntds")
| project UtcTime_s, CommandLine_s

// C2 DNS beacon
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| extend ResolvedIP = extract("QueryResults'>([^<]+)", 1, Raw_s)
| where QueryName_s == "cdn.cloud-endpoint.net"
| project UtcTime_s, Computer, Image_s, QueryName_s, ResolvedIP
```

---

## Exfil Channels Ruled Out

| Channel | Checked | Method | Result |
|---|---|---|---|
| DNS tunnelling | ✅ | EID 22 — reviewed QueryName_s for anomalies | No evidence |
| HTTP POST to external | ✅ | EID 1 — CommandLine_s searched for curl/IWR/wget/ftp | Not found beyond known staging |
| FTP | ✅ | Included in has_any filter | Not found |
| MEGA via rclone | ✅ | EID 3 + EID 1 correlated | Confirmed exfil channel |

---

> 🚧 **Investigation ongoing.** Lateral movement and persistence phases still being documented.
