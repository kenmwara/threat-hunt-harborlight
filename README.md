<!-- banner --><a href="https://github.com/kenmwara"><img src="https://raw.githubusercontent.com/kenmwara/kenmwara/main/assets/brand/card-harborlight.png?v=977dd7ad" width="100%" alt="Harborlight: Akira ransomware at a dental practice, traced from a phishing ISO to the domain controller. 46/46 flags · first to finish."></a>

# Threat Hunt Report: Hunt 22 "Harborlight" (Akira ransomware at a dental and insurance practice, HL-INC-2026-0204)

A [Cyber Range](https://www.skool.com/cyber-range) live community threat hunt (Hunt 22, "Harborlight"): human-operated ransomware at a dental and insurance practice, traced from one phishing download on a front-office workstation to the file server and the domain controller, from Sysmon, Windows Security, PowerShell and Defender logs with KQL. All 46 flags, finished on time, first to finish. Published after the hunt closed on 13 October 2026; this is version 3 (23 October 2026), rebuilt in my 17-section report format with every finding re-run on the same dataset, eleven detections replayed and exhibits E1–E11. The designed copy is in the repo: [Hunt22-Harborlight-Report.pdf](Hunt22-Harborlight-Report.pdf).

**Analyst:** Ken Kariuki · **Live hunt:** 3 October 2026 · **Result:** 46 of 46 flags, 4,060 / 4,190 points, completed on time (first finisher on the scoreboard at completion)

## 1. Front matter

| Field | Value |
|---|---|
| Hunt | Cyber Range Hunt 22, "Harborlight" (HL-INC-2026-0204) |
| Author | Ken Kariuki |
| Version | v3.0, 2026-10-23 |
| Result | 46 of 46 flags, 4,060 / 4,190 points, completed on time; first finisher on the scoreboard at completion |
| Classification | TLP:CLEAR (simulated range data; the hunt closed on 2026-10-13) |
| Distribution | Public |

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-10-03 | Written during the live hunt |
| 2.0 | 2026-10-03 | Confidence labels; seven detection rules tested on the dataset; the change that closes each gap |
| 3.0 | 2026-10-23 | 17-section structure; every finding re-run on the same dataset; Windows Security, PowerShell and Defender logs added; eleven detections replayed; exhibits E1–E11 |

**Clock note.** Every event is on 2026-02-04, and every time in this report is UTC from `EventTime`. `TimeGenerated` is
ingestion time (every row was ingested on 2026-08-18 between 15:57 and 15:59 UTC), so each query bounds `TimeGenerated`
wide and orders by `EventTime`. The portal displays Pacific time (PST, UTC-8), so 01:57 UTC shows as 3 Feb 5:57 PM.

**Labels.** "(Confidence: High/Medium/Low)" marks inferences only; logged facts cite an exhibit (E#, App C). Passwords
that appear in the attacker's command lines are masked in every exhibit.

## 2. Executive summary

At 01:57:15 UTC Emily Grant, a front-office user, downloaded `Vendor_Invoice_Review.7z` in Edge. She installed 7-Zip to
open it, and the ISO inside carried `review.dll`, which `rundll32.exe` ran at 01:59:15. A second lure re-ran the same DLL
at 02:25:06, and one second later the implant was talking to `cdn.cloud-endpoint.net`, a host name behind Cloudflare.

From that one workstation the attacker took the estate in just over three hours. They bypassed UAC, ran as SYSTEM inside
the Print Spooler, opened LSASS with full access on all three hosts, and used **Emily.Grant's own password** to mount the
admin shares of the file server (03:34:09) and the domain controller (04:28:22). On the file server they pulled their tools
from a second host name, `sync.cloud-endpoint.net`, switched Defender off, copied `C:\Shares` to a MEGA account and
destroyed the backups; on the domain controller they copied the Active Directory database. **Akira** ransomware ran on all
three hosts between 05:13:05 and 05:17:35, the logs were cleared, and the directory recorded a new account, `svc_sql`,
added to **Domain Admins** at 05:22:57.

The incident did not end with the ransom notes. Microsoft Defender quarantined the workstation's implant at 09:24:04, the
only control that acted all day, and nobody followed it to the servers. When someone finally signed in at the file
server's console at 13:44:55, as its local Administrator, the sign-in started a second copy of the implant under that
account; the server's three implants were still beaconing when its data ends at 14:47:52. The domain controller was never
touched and was still beaconing at 18:47:29, the last event in the data. Observed dwell: 16 h 50 min 14 s. The stolen
share, the AD database copy and the `svc_sql` domain admin all remain with the attacker. Severity: Critical.

| Hosts encrypted | Data to MEGA | Alerts acted on | New domain admin |
|---|---|---|---|
| **3 of 3** (128 notes, 27 files (E6)) | **Sent** (volume not determined (B1)) | **0** (Defender quarantined one implant itself (E10)) | **svc_sql** (Domain Admins at 05:22:57 (E6)) |

**Recommended now.** Isolate the file server and the domain controller; block both `cloud-endpoint.net` host names; disable
`svc_sql`; reset every domain password and the `krbtgt` password twice; rebuild the domain controller from a backup taken
before 4 February; and start the breach-notification process for the patient and claims data on `C:\Shares`. Nobody signs
in to an infected host before it is isolated (F9).

## 3. Overview

| Item | Value |
|---|---|
| Hunt type | Live community hunt, flag-guided (46 questions), on a simulated intrusion |
| Client | Harborlight Dental & Insurance; IT run by Coastal MSP, with no SOC and no alert queue (range brief) |
| Subject | Emily.Grant, front-office user on BACKOFFICE-PC1 |
| Hosts | BACKOFFICE-PC1 (172.16.0.109, workstation) · HL-FS01 (172.16.0.8, file server) · ADDC01 (172.16.0.7, domain controller); domain HARBORLIGHT (Harborlight.local), one flat /24 |
| Period | 2026-02-04 00:00:18 UTC to 2026-02-04 18:47:29 UTC (E9) |
| Data | `HarborlightDental_CL` in workspace LAW-SilentCorridor, 44,989 rows: Sysmon 27,231, Windows event logs 17,758 (E9), queried from Microsoft Defender Advanced Hunting and the Log Analytics query API |
| Analyst | Ken Kariuki, lead analyst, with AI tooling (§16); live hunt 2026-10-03, re-analysis 2026-10-23 |
| Classification; severity | Human-operated ransomware with data theft and domain compromise; Critical (Confidence: High) |

## 4. Hypothesis and ABLE

**Hypothesis.** A phishing download on the front-office workstation gave an operator a foothold, which they widened with
the user's own credentials to the file server and the domain controller, then used to steal the shared files and encrypt
all three hosts.

| ABLE | Content |
|---|---|
| Actor | Unknown operator using Akira-branded ransomware; infrastructure `cdn.cloud-endpoint.net` and `sync.cloud-endpoint.net` behind Cloudflare; MEGA account `jwilson.vhr@proton.me` |
| Behaviour | Archive and ISO lure, DLL through rundll32, UAC bypass, injection into the Print Spooler, LSASS access, admin-share lateral movement, staged tool downloads, rclone to MEGA, anti-recovery, encryption, log clearing, a new domain admin |
| Location | BACKOFFICE-PC1, HL-FS01, ADDC01 |
| Evidence | Sysmon 1, 3, 8, 10, 11, 12, 13, 15, 22, 29; Security 4624, 4625, 4720, 4728, 4732, 1102; System 104, 1074; PowerShell 4104; Defender 1116, 1117 |

Counter-hypotheses, judged in §10: H1 insider (Emily); H2 the MSP's own administration; H3 a commodity infection with no
operator; H4 encryption without data theft.

## 5. Threat intel inputs

The range brief set the scenario, the hosts and the table. Public reporting on Akira, CISA and FBI advisory AA24-109A
("#StopRansomware: Akira Ransomware", released 2024-04-18, updated 2025-11-13), served for cross-reference: it lists rclone
to MEGA for exfiltration, abuse of remote tools such as AnyDesk, and vssadmin shadow-copy deletion. No indicator came from
intel; every indicator in App D comes from the logs. The chain matches that reporting in broad strokes (technique
similarity, not attribution; Confidence: Low): the ransomware binary was not analysed, and the note name and the `.akira`
extension are all that tie it to Akira.

## 6. Scope, data sources and blind spots

| Source | Rows (E9) | Shows | Coverage confidence |
|---|---|---|---|
| Sysmon (EventID, Computer) | 27,231 | Process, network, file, registry, DNS, process access | High on all three hosts |
| Windows Security (EventCode, ComputerName) | 15,876 | Sign-ins, account and group changes, log clears | High on the servers; partial on the workstation (B3) |
| PowerShell Operational | 952 | Script blocks (4104), mostly on the file server | High where it ran |
| Windows System and Application | 911 | Services, log clears (104), power events (1074) | Medium |
| Defender Operational | 19 | Detections and configuration changes | Workstation only (B2) |
| Network, proxy, firewall, DNS server; MSP and AnyDesk logs; MEGA | – | Not available | None |

- **B1** No network, proxy, firewall or DNS-server logs: the bytes sent to MEGA and the content of the beacons are not observable.
- **B2** Defender's own log is collected only from the workstation; the servers' Defender state after 04:03 is inferred from the commands that switched it off (E10).
- **B3** The workstation's log-clear events (1102, 104) are missing, although `wevtutil cl` ran there 21 times (E5).
- **B4** Most Sysmon fields sit in `EventData_Xml`; the flattened columns are empty for events 8 and 10.
- **B5** `TimeGenerated` is ingestion time (clock note); `EventTime` is used throughout.
- **B6** No memory, disk images or binaries: `review.dll`, `taskhostw.exe` and `updater.exe` are known by path, behaviour and Defender verdict only.
- **B7** No AnyDesk or MSP-side logs: who used AnyDesk at 10:43 and 13:47 cannot be told.
- **B8** The data ends at 18:47:29; whether the domain controller's beacon stopped or collection ended is not known.

## 7. Execution

**Method.** The live hunt followed the 46 questions in order; each answer was taken from a query result and checked
against the raw rows before it was submitted (§16). Version 3 re-ran every finding on 2026-10-23 against the same dataset
and saved each query with its output as an exhibit: the lures and first execution (E1), the UAC bypass (E2), injection
and LSASS access (E3), admin shares, WMI and the copy to MEGA (E4), anti-recovery and log clearing (E5), encryption, the
new domain admin and the last beacons (E6), the consoles after the encryption (E7), the detection replay (E8), the
dataset itself (E9), what Defender and PowerShell logging saw (E10), and the file server's beacons around the first sign-in (E11). Version 3 also read the three log families v2 had
not used: Windows Security, PowerShell script blocks and Defender.

**Dead ends.** The 268 Credential Manager reads (5379) are the operating system's own, all day long. `akira_svc` is only
looked up (`net user akira_svc /domain`), never created: the only account created is `svc_sql` (E6). The genuine
OneDrive client opening other processes under Emily's profile is routine. The first two `net group "Domain Admins"`
attempts failed on mangled quoting. The Defender tamper detection at 01:14 is Defender's own (§9.11). Account changes by
ANONYMOUS LOGON at 00:16:44 (`svc_backup`) and 06:16:44 (`svc_sql`) fall at the same minute and second six hours apart,
which looks like a periodic background job (Confidence: Medium). The `RuntimeBroker.exe` copies that v2 left unresolved
are attacker downloads (F4).

## 8. Timeline

| Time (UTC) | Event | Source · evidence |
|---|---|---|
| 2026-02-04 00:29:02 UTC | AnyDesk is already running on BACKOFFICE-PC1, 88 minutes before the first lure | Sysmon 10 · E7 |
| **2026-02-04 01:57:15 UTC** | Edge downloads `Vendor_Invoice_Review.7z` to Emily's Downloads; 7-Zip follows at 01:58:13 | Sysmon 15 · E1 |
| **2026-02-04 01:59:15 UTC** | `rundll32.exe D:\review.dll,StartW` from the mounted ISO (again at 01:59:32 and 02:00:08) | Sysmon 1 · E1 |
| 2026-02-04 02:25:06 UTC | Second lure: a loop over drive letters D to J runs `review.dll` from E: | Sysmon 1 · E1 |
| **2026-02-04 02:25:07 UTC** | First C2: rundll32 resolves `cdn.cloud-endpoint.net` (104.21.30.237, 172.67.174.46) | Sysmon 22, 3 · App A q4 |
| 2026-02-04 02:32:48 UTC | rundll32 injects into notepad.exe | Sysmon 8 · E3 |
| **2026-02-04 02:42:39 UTC** | fodhelper reaches High integrity; `taskhostw.exe` starts High at 02:42:40 | Sysmon 1, 13 · E2 |
| 2026-02-04 02:47:11 UTC | taskhostw.exe injects into spoolsv.exe (SYSTEM); spoolsv opens lsass.exe with 0x1fffff at 02:49:46 | Sysmon 8, 10 · E3 |
| 2026-02-04 02:56:31 UTC | Through notepad.exe, the implant resolves the domain's hosts, sweeps port 445 and writes `20260203185934_recon.zip` | Sysmon 3, 11, 22 · v2 |
| **2026-02-04 03:34:09 UTC** | `net use Z: \\172.16.0.8\C$` as Emily.Grant, password in clear; the implant is copied to HL-FS01 | Sysmon 1 · E4 |
| 2026-02-04 03:41:54 UTC | HL-FS01: Run key `SecurityHealth` and task `WindowsUpdate` (onstart, SYSTEM), both to taskhostw.exe | Sysmon 13, 1 · App D |
| 2026-02-04 03:42:36 UTC | HL-FS01: first log wipe; the server logs its own clear events | Sysmon 1; Security 1102; System 104 · E5 |
| 2026-02-04 03:44:57 UTC | HL-FS01: `powershell -enc` downloads tools from `sync.cloud-endpoint.net` (five files to 03:53:43) | PowerShell 4104 · E10 |
| **2026-02-04 03:57:40 UTC** | HL-FS01: renamed rclone copies `C:\Shares` to `mega:HARBORLIGHT-exfil` (again at 03:58:33 and 04:00:14) | Sysmon 1, 22 · E4 |
| 2026-02-04 04:03:50 UTC | HL-FS01: five Defender protections switched off (again at 04:05:13) | PowerShell 4104 · E10 |
| 2026-02-04 04:04:05 UTC | HL-FS01: shadow copies, boot recovery and the backup catalog deleted (again at 04:05:12–04:05:26) | Sysmon 1 · E5 |
| **2026-02-04 04:28:22 UTC** | `net use Y: \\172.16.0.7\C$` from HL-FS01 with the same account | Sysmon 1 · E4 |
| **2026-02-04 04:33:55 UTC** | ADDC01: `ntdsutil` IFM copies the AD database to `C:\Windows\Temp\ntds` (again at 04:35:35) | Sysmon 1 · E5 |
| 2026-02-04 04:42:28 UTC | ADDC01: WMI `process call create` deletes shadow copies | Sysmon 1 · E4 |
| **2026-02-04 05:13:05 UTC** | Akira `updater.exe` runs: HL-FS01 05:13:05, ADDC01 05:14:15, BACKOFFICE-PC1 05:17:35 | Sysmon 11 · E6 |
| 2026-02-04 05:18:21 UTC | Sixteen log channels cleared per host, to 05:20:01 | Sysmon 1; Security 1102 · E5 |
| **2026-02-04 05:22:57 UTC** | `svc_sql` (created 05:21:56, added to Administrators 05:22:28) added to Domain Admins | Security 4720, 4732, 4728 · E6 |
| 2026-02-04 09:24:04 UTC | Defender quarantines the workstation's taskhostw.exe (Trojan:Win32/SuspGolang.AG); that host's last beacon was 09:23:49 | Defender 1116, 1117 · E10, E6 |
| 2026-02-04 10:43:40 UTC | AnyDesk on the workstation resolves its relay hosts (who connected is not logged) | Sysmon 22 · E7 |
| **2026-02-04 13:44:55 UTC** | HL-FS01 console sign-in as the local Administrator after three failures; Explorer starts a second copy of the implant at 13:45:16 | Security 4625, 4624; Sysmon 1 · E7, E11 |
| 2026-02-04 13:49:31 UTC | Workstation console sign-in as the local helpdesk account, which opens AnyDesk and reads its connection log | Security 4624; Sysmon 1 · E7 |
| 2026-02-04 14:27:48 UTC | The workstation is powered off | System 1074 · E7 |
| 2026-02-04 14:47:52 UTC | HL-FS01's data ends with all three implants still beaconing | Sysmon 3 · E6, E11 |
| **2026-02-04 18:47:29 UTC** | ADDC01's last beacon, and the last event in the data | Sysmon 3 · E6, E9 |

## 9. Findings

**F1 One user, two lures, one DLL.** *State:* Edge wrote both archives to Emily's Downloads, 7-Zip extracted each ISO, and
`rundll32.exe` ran `review.dll,StartW` from D: three times, then from E: through a drive-letter loop; the first C2 lookup
follows that run by one second. *Show:* E1; App A q1. *Interpret:* the archive-in-ISO packaging is a common way to keep
the browser's download mark off the files inside (Confidence: Medium; the mark is not logged), and the second lure was a
relaunch, not new malware (Confidence: High).

**F2 Elevation, then SYSTEM through the Print Spooler.** *State:* the implant pointed the per-user `ms-settings` handler
at `C:\Users\Public\taskhostw.exe`; the first fodhelper stayed Medium, the launch through cmd produced a High fodhelper
and a High taskhostw.exe one second later; taskhostw.exe then injected into spoolsv.exe on every host it reached. *Show:*
E2, E3. *Interpret:* from 02:47 onwards the commands on each host come from the Print Spooler, as SYSTEM (Confidence:
High).

**F3 Her own password opened both servers.** *State:* `lsass.exe` was opened with PROCESS_ALL_ACCESS by spoolsv.exe on the
workstation and by taskhostw.exe on all three hosts; Emily.Grant's password was typed in clear on `net use` to the file
server's `C$` (03:34:09) and the domain controller's (04:28:22), and on a WMI command (04:42:28). *Show:* E3, E4.
*Interpret:* the attacker knew her password (Confidence: High); that it came from LSASS memory is likely but not proven,
since no dump file is logged (Confidence: Medium).

**F4 The tools came from a second host name.** *State:* on the file server, taskhostw.exe launched `powershell -enc` six
times between 03:44:56 and 03:53:43, and script-block logging shows five downloads from `https://sync.cloud-endpoint.net/`:
`RuntimeBroker.exe`, a fake `MsMpEng.exe` placed inside `C:\ProgramData\Microsoft\Windows Defender\`, `config.dat`,
`update.bat` and `rclone.conf`. *Show:* E10; App A q6. *Interpret:* the operator staged the toolkit per host on demand,
and v2's `RuntimeBroker.exe` copies are part of it (Confidence: High).

**F5 `C:\Shares` went to MEGA.** *State:* rclone, renamed `MsMpEng.exe` in `C:\ProgramData\Microsoft`, ran
`copy C:\Shares mega:HARBORLIGHT-exfil` three times between 03:57:40 and 04:00:14 and resolved MEGA storage nodes 39
times, to 04:03:39. *Show:* E4. *Interpret:* the upload ran and reached MEGA (Confidence: High); the volume is not
determined (B1).

**F6 Recovery destroyed, the AD database copied, the logs cleared.** *State:* the file server lost its shadow copies, boot
recovery and backup catalog, each twice, 81 seconds apart; the domain controller's AD database was copied with `ntdsutil`
IFM and its shadow copies deleted; `wevtutil cl` ran on all three hosts, and the servers logged their own clears (1102,
104). *Show:* E5. *Interpret:* every domain credential must be treated as exposed (Confidence: High that the copy exists
on the host; its transfer is not logged).

**F7 Encryption, and a domain admin the directory confirms.** *State:* `updater.exe` wrote 128 ransom notes and renamed 27
distinct files to `.akira` across the three hosts; the domain controller logged `svc_sql` created (4720), added to
Administrators (4732) and to Domain Admins (4728) at 05:22:57. `svc_sql` never signs in anywhere in the data. *Show:* E6.
*Interpret:* `svc_sql` is a standing backdoor into the domain, not yet used (Confidence: High; v2 rated this Medium
before the directory's own events were read).

**F8 Defender acted once, on the workstation only.** *State:* at 09:23:31 Defender on the workstation detected the implant
as Trojan:Win32/SuspGolang.AG and quarantined taskhostw.exe at 09:24:04; that host's beacon stops at 09:23:49. On the file
server the same implant had switched five Defender protections off at 04:03. *Show:* E10, E6. *Interpret:* the only
control that worked all day was never seen by a person, so no response reached the two servers for another 4 h 20 min
(Confidence: High).

**F9 The first response ran the backdoor again, as Administrator.** *State:* at 13:44:55, after three failures, someone
signed in at the file server's console as its local Administrator; within 22 seconds three ransom notes opened and
`C:\Users\Public\taskhostw.exe` started under that account, launched by Explorer. The implants already running never
stopped: after the launch taskhostw.exe's beacons roughly double, to 192 in the 47 minutes of the 14:00 hour against 94
and 96 for the other two implants, and the server's data ends at 14:47:52 with all three still beaconing. At 13:49:31 the
workstation's local helpdesk account signed in, opened AnyDesk and read AnyDesk's `connection_trace.txt` twice; the
workstation was powered off at 14:27:48. Nothing touched the domain controller. *Show:* E7, E11, E6. *Interpret:* the
sign-in fired the Run-key persistence set at 03:41:54 (Confidence: Medium; a manual launch would look the same) and gave
the attacker a copy running with the Administrator's token; the domain controller, the most valuable host, was still
under attacker control when the data ends (Confidence: High).

**F10 AnyDesk was already there.** *State:* AnyDesk.exe was running from 00:29:02, before the first lure; the implant's
processes opened it between 02:47 and 03:31; it resolved AnyDesk relays at 10:43 and 13:47, and the helpdesk account used
it at 13:50. *Show:* E7. *Interpret:* most likely the MSP's own remote-support tool (Confidence: Medium); whether the
attacker used it is not determined (B7).

**9.11 Negative findings**

| Looked for | Where | Method | Result |
|---|---|---|---|
| Attacker activity before the first lure | BACKOFFICE-PC1, 00:55 to 01:57 | Process creation | None: updaters, a service host and Emily starting Edge at 01:53:40 |
| Defender's 01:14 tamper detection as part of the attack | BACKOFFICE-PC1 | E10; registry events | Defender's own process and services.exe rewrote its service keys at 01:13:59; judged Defender's own (Confidence: Medium) |
| Other accounts created | Security 4720, all hosts | E6 | Only `svc_sql`; `akira_svc` is only looked up |
| Other privileged-group changes | Security 4728, 4732, 4756 | E8 R11 | Only the two `svc_sql` additions |
| `svc_sql` used | Security, all hosts | Sign-ins and Kerberos events naming it | None after its creation |
| Attacker services | Security 4697; System 7045 | Service installs | Only Windows' per-user services, created by the 13:44 and 13:49 sign-ins |
| A beacon from the workstation after the quarantine | Sysmon 3 | E6 | None after 09:23:49 |
| The AD database copy leaving the DC | Sysmon 3, 11 | Network and file events | None logged (B1) |

## 10. Hypothesis outcome

**Confirmed** on logged facts: the lures and first execution (E1), the admin-share movement with Emily's password (E4),
the copy to MEGA (E4), the AD database copy (E5), encryption on all three hosts and the new domain admin (E6). **Not
determined:** how much data reached MEGA (B1), whether the AD database copy left the host (B1), and who was at the
consoles after the encryption (B7).

| Counter-hypothesis | Verdict and evidence |
|---|---|
| H1 Insider (Emily) | Rejected (Confidence: High): her own logged steps are two downloads and two extractions; everything after runs from implant processes, as SYSTEM, at machine speed (E1–E3) |
| H2 The MSP's own administration | Rejected (Confidence: High): a renamed rclone to a proton.me MEGA account, deleted backups and ransomware (E4–E6); the sign-ins after 13:44 fit a response instead (F9) |
| H3 A commodity infection with no operator | Rejected (Confidence: Medium): tools staged per host on demand (E10), commands retyped after mangled quoting, and a new domain admin |
| H4 Encryption without theft | Rejected (Confidence: High): three rclone copies of `C:\Shares` and 39 MEGA lookups (E4) |

**Dwell.** Observed span 16 h 50 min 14 s, from the download at 01:57:15 to the last event at 18:47:29. First execution
to the domain controller: 2 h 29 min 07 s (01:59:15 to 04:28:22); to the first encryption: 3 h 13 min 50 s. Beaconing
outlived the last encryption by 13 h 29 min 54 s. Time to detection: Defender's first true detection came at 09:23:31,
7 h 26 min 16 s after the download, and no person acted until 13:44:55. End of exposure: not established (B8).

**Scope and impact.** Three of three hosts encrypted; 27 files renamed `.akira` and 128 notes. Accounts: Emily.Grant
(password known to the attacker) and `svc_sql` (Domain Admins); every domain credential is exposed through the AD
database copy. Data: `C:\Shares` on the file server of a dental and insurance practice left for MEGA; its contents are not
logged, so it is treated as patient and claims data. Recovery: shadow copies, boot recovery and the backup catalog on the
file server destroyed. Legal decides on notification.

## 11. ATT&CK coverage

| Stage | ATT&CK | Status |
|---|---|---|
| Initial access | T1566 Phishing (the download is logged; how it reached her is not) | Download observed; delivery inferred |
| Execution | T1204.002 Malicious File; T1218.011 Rundll32; T1059.001 PowerShell; T1059.003 Windows Command Shell; T1047 Windows Management Instrumentation | Observed |
| Defence evasion | T1553.005 Mark-of-the-Web Bypass (inferred, F1); T1055 Process Injection; T1036.005 Match Legitimate Name or Location; T1027 Obfuscated Files or Information (`-enc`); T1562.001 Disable or Modify Tools; T1070.001 Clear Windows Event Logs | Observed, except T1553.005 |
| Privilege escalation | T1548.002 Bypass User Account Control | Observed |
| Credential access | T1003.001 LSASS Memory (full-access opens; no dump logged); T1003.003 NTDS | Observed |
| Discovery | T1018 Remote System Discovery; T1046 Network Service Discovery | Observed |
| Lateral movement | T1021.002 SMB/Windows Admin Shares; T1078.002 Domain Accounts; T1570 Lateral Tool Transfer | Observed |
| Command and control | T1071.001 Web Protocols; T1105 Ingress Tool Transfer | Observed; the real server behind Cloudflare is not identified |
| Exfiltration | T1567.002 Exfiltration to Cloud Storage | Observed; volume not determined (B1) |
| Persistence | T1547.001 Registry Run Keys; T1053.005 Scheduled Task; T1136.002 Domain Account; T1098.007 Additional Local or Domain Groups | Observed |
| Impact | T1486 Data Encrypted for Impact; T1490 Inhibit System Recovery; T1489 Service Stop | Observed |

Hunted, not observed: T1219 Remote Access Software (AnyDesk was installed before the intrusion; attacker use is not
shown, F10); T1090.004 Domain Fronting (Cloudflare addresses only; fronting cannot be told from ordinary proxying here).

## 12. Detection and telemetry gaps

Owners are proposed, not accepted.

| Gap | Impact | Fix (owner) | Acceptance test |
|---|---|---|---|
| Defender's workstation alert reached nobody (F8) | The servers kept beaconing for hours | Send Defender alerts to the MSP's on-call pager (MSP) | A test detection on the workstation pages the on-call within 5 minutes |
| Defender could be switched off from a script on the server (F4) | The file server had no protection from 04:03 | Tamper Protection on every server (MSP) | `Set-MpPreference -DisableRealtimeMonitoring $true` from an admin shell leaves protection on |
| A front-office user could mount an ISO and run a DLL from it | The foothold | Block ISO mounting; application control on mounted drives and `C:\Users\Public` (MSP) | A standard user cannot run a DLL from D: or an EXE from Public |
| fodhelper elevated silently | SYSTEM on the workstation | UAC "Always notify"; no local admin for front-office accounts (MSP) | The same registry change no longer produces a High process |
| LSASS was readable on all three hosts | Credential theft | LSASS protection (RunAsPPL) and Credential Guard (MSP) | A full-access open of lsass.exe is denied |
| A workstation reached the admin shares of both servers | Lateral movement in two hops | Segment the network; block SMB and RPC from workstations to servers (MSP) | A port test from the workstation to both servers on 445 and 135 fails |
| One user's password opened `C$` on the domain controller | Domain compromise | Users out of server administrators; separate admin accounts with MFA (MSP) | `net use \\ADDC01\C$` as Emily.Grant is refused |
| Data could go to consumer cloud storage | Exfiltration | Block MEGA and similar services at the firewall and in DNS (MSP) | A MEGA lookup from the file server is blocked and logged |
| Backups could be deleted from the host | No recovery | An offline or immutable copy of `C:\Shares` and the domain controller (MSP) | A test restore from that copy succeeds |
| A new domain admin raised no alert | A standing backdoor | Alert on 4728 and 4732 for privileged groups, R11 (MSP) | Adding a test account to Domain Admins alerts within minutes |
| Logs were cleared on the hosts, and the workstation's clear events never arrived (B3) | Lost evidence | Forward logs as they are written; alert on 1102 and 104 (MSP) | Clearing a test channel alerts and loses nothing centrally |
| The first responder signed in to an infected server, and the sign-in ran a second copy of the implant as Administrator (F9) | Attacker code with a privileged token; the server was never isolated | An incident runbook: isolate before any interactive sign-in, and never sign in to a suspected host with a privileged account (MSP) | A tabletop exercise in which the responder isolates first |
| R3 and R7 skip any path containing "Windows Defender" | The fake `MsMpEng.exe` inside that folder escapes both rules | Exclude only `\Windows Defender\Platform\`, by signer (MSP) | A replay flags the 03:47:19 file |

## 13. New detections

All eleven were replayed on 2026-10-23 against the whole dataset (E8, App B). R1–R7 are the v2 rules and return the v2
counts exactly; R8–R11 were logic only in v2 and are written and tested here. A false positive is a hit on anything that
is not attack activity; the dataset carries a day of ordinary background (Edge and OneDrive updaters, WMI, compatibility
telemetry), and no rule fires on it. One simulated day is a thin benign baseline, so status for all eleven: proposed.

| Rule | Logic (source) | Maps to | Hits / FP (unit) |
|---|---|---|---|
| R1 | rundll32.exe running a DLL from a drive other than C: (Sysmon 1) | T1218.011 | 4 / 0 (processes) |
| R2 | `ms-settings\shell\open\command` written, by command line or registry event (Sysmon 1, 13) | T1548.002 | 6 / 0 (events) |
| R3 | A program started from `C:\Users\Public` or `C:\ProgramData\Microsoft` (Sysmon 1) | T1036.005 | 7 / 0 (processes) |
| R4 | Remote thread into spoolsv.exe or notepad.exe (Sysmon 8) | T1055 | 13 / 0 (threads) |
| R5 | `--config` + `copy` + a named remote on one command line (Sysmon 1) | T1567.002 | 3 / 0 (processes) |
| R6 | An account added to the domain or an admin group from a command line (Sysmon 1) | T1136.002, T1098.007 | 13 / 0 (processes) |
| R7 | A DNS lookup by a program in Public, ProgramData or by rundll32.exe (Sysmon 22) | T1071.001 | 64 / 0 (lookups) |
| R8 | lsass.exe opened with 0x1fffff by anything but Defender (Sysmon 10) | T1003.001 | 5 / 0 (opens) |
| R9 | WMI `process call create` on a node, or a shell started by WmiPrvSE.exe (Sysmon 1) | T1047 | 1 / 0 (processes) |
| R10 | Shadow-copy, boot-recovery, backup-catalog, AD-export or log-clear commands, and the logs' own clear events (Sysmon 1; Security 1102; System 104) | T1490, T1003.003, T1070.001 | 128 / 0 (events) |
| R11 | A member added to Domain, Enterprise or Schema Admins or Administrators (Security 4728, 4732, 4756) | T1098.007 | 2 / 0 (changes) |

Expected false positives and tuning: R1 installers on mounted media (allow by signer); R3 vendor updaters under
ProgramData (audit first, then allow by signer; narrow the Defender exclusion to `\Platform\`, §12); R4 accessibility and
security tools (exclude signed vendor paths, never a source in Public); R5 a genuine rclone backup (allow by host and
account, never by file name, since the attacker renamed the tool); R6 and R11 real provisioning (alert outside change
windows); R7 vendor agents (allow known signers); R8 backup and EDR agents (allow by signer); R9 management tools (allow
known admin hosts); R10 a planned backup rotation (rare enough to alert on every hit).

## 14. Handover to IR

Compromise confirmed: human-operated ransomware with data theft and a domain compromise. For the client IR lead and Legal;
every action is recommended, not executed (range).

| # | Risk (since) | Action |
|---|---|---|
| 1 | The file server and the domain controller under attacker control; the DC still beaconing at the end of the data (since 2026-02-04 03:35:11 UTC) | Isolate both now; block `cdn.cloud-endpoint.net` and `sync.cloud-endpoint.net` at DNS and the firewall |
| 2 | `svc_sql` in Domain Admins (since 2026-02-04 05:22:57 UTC) | Disable and delete it; review every privileged group |
| 3 | The AD database copied (since 2026-02-04 04:33:55 UTC) | Reset every domain password and the `krbtgt` password twice; rebuild the DC from a backup taken before 4 February |
| 4 | Emily.Grant's password known to the attacker (since 2026-02-04 03:34:09 UTC at the latest) | Reset it and review her sign-ins |
| 5 | `C:\Shares` exfiltrated (since 2026-02-04 03:57:40 UTC) | Legal: notification decision for patient and claims data |
| 6 | Implants and persistence remain: Run key `SecurityHealth`, task `WindowsUpdate`, `OneDriveSync.exe`, `wsync.exe`, `RuntimeBroker.exe` | Remove them from isolated hosts; never sign in interactively before isolation (F9) |
| 7 | Recovery destroyed on the file server | Restore from an offline copy, if one exists |
| 8 | Evidence ages out | Preserve the table's rows and AnyDesk's `connection_trace.txt` |

A password reset on its own would not help: the domain admin, the AD database copy and the implants would all survive it.

## 15. Next-hunt leads

| Lead | Data needed |
|---|---|
| Who used AnyDesk at 10:43 and 13:47 (F10) | AnyDesk connection logs and `connection_trace.txt`; the MSP's records |
| How much of `C:\Shares` reached MEGA | Firewall or proxy logs from 2026-02-04 03:57:40 UTC |
| Whether the AD database copy left the DC | Network logs; file-share auditing on ADDC01 |
| The real server behind `cloud-endpoint.net` | Passive DNS; a Cloudflare abuse report |
| Who was at the two consoles at 13:44 and 13:49 | The MSP's ticket and on-call records |
| The workstation's missing log-clear events (B3) | The workstation's own Security and System logs, if they survive |

## 16. AI tools declaration

I ran this hunt as the lead analyst and used Claude (Anthropic), through Claude Code, as my AI tooling.

- **The live hunt (3 October).** Claude drafted KQL and ran it in an Advanced Hunting tab in my signed-in browser, then returned the raw results. Where its browser tool refused credential-access and anti-recovery queries, I ran the drafted KQL in my own tab. I set the order of the pivots, checked each answer against its raw result and submitted every answer myself. I used two paid wording hints (15 points each) and one reveal, on the anti-recovery repeat flag, where the grader rejected an answer the data and the hints supported (reported to staff).
- **This version (23 October).** Claude restructured the report into the 17-section format I now use for live hunts, re-ran every exhibit query and all eleven detection rules against the same dataset through the range's Log Analytics query tool, drafted the new sections, and found the Windows Security, PowerShell and Defender evidence that v2 had not used. I reviewed each new finding against its exhibit and approved all text.
- **Data handling.** I signed in to every portal myself; no passwords or keys were given to the AI. The passwords in the attacker's command lines are masked in every exhibit.

## 17. Appendices

### A. Queries

All queries run against `workspace("LAW-SilentCorridor").HarborlightDental_CL` with a wide `TimeGenerated` bound and
`EventTime` for order (clock note). The exhibit queries (E1–E11) are printed with their output in App C.

```kql
// q1 What landed in Downloads, and what wrote it (initial access)
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and Computer has "BACKOFFICE-PC1" and EventID in ("11","15")
| extend T = column_ifexists("TargetFilename",""), Img = column_ifexists("Image","")
| where T has "Downloads"
| project EventTime, EventID, Img, T
| order by EventTime asc

// q2 Process tree with integrity level (the fodhelper attempts)
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and Computer has "BACKOFFICE-PC1" and EventID == "1"
| extend X = tostring(EventData_Xml)
| extend Img = extract("Image.>([^<]+)", 1, X), Cmd = extract("CommandLine.>([^<]+)", 1, X),
         IL = extract("IntegrityLevel.>([^<]+)", 1, X), Parent = extract("ParentImage.>([^<]+)", 1, X)
| where Img has_any ("fodhelper", "taskhostw", "reg.exe")
| project EventTime, Img, Cmd, IL, Parent
| order by EventTime asc

// q3 Injection into the Print Spooler, per host
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and EventID in ("8","10")
| extend X = tostring(EventData_Xml)
| extend Src = extract("SourceImage.>([^<]+)", 1, X), Tgt = extract("TargetImage.>([^<]+)", 1, X),
         Access = extract("GrantedAccess.>([^<]+)", 1, X)
| where Tgt has "spoolsv"
| summarize First = min(tostring(EventTime)), n = count() by Computer, EventID, Src, Access

// q4 Beaconing: destination, port, volume and last-seen per implant
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and EventID == "3"
| extend X = tostring(EventData_Xml)
| extend Img = extract("Image.>([^<]+)", 1, X), Dst = extract("DestinationIp.>([^<]+)", 1, X),
         Port = extract("DestinationPort.>([^<]+)", 1, X)
| where Img has_any ("Public", "ProgramData", "rundll32") and not(Dst startswith "172.16.")
| summarize First = min(tostring(EventTime)), Last = max(tostring(EventTime)), n = count() by Computer, Img, Dst, Port

// q5 Ransom notes and encrypted files per host
workspace("LAW-SilentCorridor").HarborlightDental_CL
| where TimeGenerated > ago(1000d) and EventID == "11"
| extend F = extract("TargetFilename.>([^<]+)", 1, tostring(EventData_Xml))
| summarize Notes = countif(F has "akira_readme"), EncryptedFiles = dcountif(F, F endswith ".akira") by Computer

// q6 Tool staging: every lookup of the cloud-endpoint.net names, and the encoded PowerShell that fetched the tools
let T = workspace("LAW-SilentCorridor").HarborlightDental_CL | extend X = tostring(EventData_Xml);
union
 (T | where EventID == "22" | extend Qn = extract("QueryName.>([^<]+)", 1, X), Img = extract(@"<Data Name=.Image.>([^<]+)", 1, X)
    | where Qn has "cloud-endpoint"
    | summarize n = count(), First = min(todatetime(EventTime)), Last = max(todatetime(EventTime)) by Host = tostring(split(Computer, ".")[0]), A = Qn, B = Img),
 (T | where EventID == "1" | extend Cmd = extract("CommandLine.>([^<]+)", 1, X), Img = extract(@"<Data Name=.Image.>([^<]+)", 1, X), Par = extract("ParentImage.>([^<]+)", 1, X)
    | where Img endswith "powershell.exe" and todatetime(EventTime) between (datetime(2026-02-04 03:40) .. datetime(2026-02-04 04:10))
    | summarize n = count(), First = min(todatetime(EventTime)), Last = max(todatetime(EventTime)) by Host = tostring(split(Computer, ".")[0]), A = strcat("powershell parent ", tostring(split(Par, @"\")[-1])), B = substring(Cmd, 0, 90))
| order by First asc
```

Method notes: host names carry the domain suffix (`BACKOFFICE-PC1.Harborlight.local`), so filters use `has`; the Windows
event-log rows use `EventCode` and `ComputerName` and leave `EventID` and `Computer` empty (E9).

### B. Detection rules

The eleven rules run as one query; the result is E8.

```kql
// B1 R1-R7 as in v2; R8-R11 new in v3
let T = workspace("LAW-SilentCorridor").HarborlightDental_CL | extend X = tostring(EventData_Xml);
let P = T | where EventID == "1" | extend Img = extract(@"<Data Name=.Image.>([^<]+)", 1, X), Cmd = extract("CommandLine.>([^<]+)", 1, X), Parent = extract("ParentImage.>([^<]+)", 1, X);
let W = T | where isempty(Computer) | extend Host = tostring(ComputerName), M = tostring(Message);
union
 (P | where Img endswith "rundll32.exe" and Cmd matches regex @"(?i)\s[d-z]:\\[^\\\s]+\.dll" | extend Rule = "R1", Detail = Cmd),
 (P | where Cmd has "ms-settings" and Cmd has "shell" and Cmd has "command" | extend Rule = "R2", Detail = Cmd),
 (T | where EventID in ("12", "13") | extend Obj = extract("TargetObject.>([^<]+)", 1, X) | where Obj has "ms-settings" and Obj has "command" | extend Rule = "R2", Detail = Obj),
 (P | where (Img contains "\\Users\\Public\\" or Img contains "\\ProgramData\\Microsoft\\") and Img !has "Windows Defender" | extend Rule = "R3", Detail = Img),
 (T | where EventID == "8" | extend Src = extract("SourceImage.>([^<]+)", 1, X), Tgt = extract("TargetImage.>([^<]+)", 1, X) | where Tgt has_any ("spoolsv.exe", "notepad.exe") | extend Rule = "R4", Detail = strcat(Src, " -> ", Tgt)),
 (P | where Cmd has "--config" and Cmd has "copy" and Cmd matches regex @"\s[A-Za-z0-9_-]{2,}:[A-Za-z0-9_-]" | extend Rule = "R5", Detail = Cmd),
 (P | where (Cmd has "/add" and Cmd has "/domain") or Cmd has "Add-ADGroupMember" or (Cmd has "localgroup" and Cmd has "Administrators" and Cmd has "/add") | extend Rule = "R6", Detail = Cmd),
 (T | where EventID == "22" | extend Img = extract(@"<Data Name=.Image.>([^<]+)", 1, X), Qn = extract("QueryName.>([^<]+)", 1, X) | where (Img contains "\\Users\\Public\\" or Img contains "\\ProgramData\\" or Img endswith "rundll32.exe") and Qn !endswith ".local" and Qn has "." and Img !has "Windows Defender" | extend Rule = "R7", Detail = strcat(Img, " -> ", Qn)),
 (T | where EventID == "10" | extend Src = extract("SourceImage.>([^<]+)", 1, X), Tgt = extract("TargetImage.>([^<]+)", 1, X), Acc = extract("GrantedAccess.>([^<]+)", 1, X) | where Tgt endswith "lsass.exe" and Acc == "0x1fffff" and Src !has "Windows Defender" and Src !endswith "MsMpEng.exe" | extend Rule = "R8", Detail = Src),
 (P | where (Cmd has "/node:" and Cmd has "process call create") or (Parent endswith "WmiPrvSE.exe" and Img has_any ("cmd.exe", "powershell.exe", "vssadmin.exe", "rundll32.exe")) | extend Rule = "R9", Detail = Cmd),
 (P | where (Cmd has "vssadmin" and Cmd has "delete") or (Cmd has "shadowcopy" and Cmd has "delete") or (Cmd has "bcdedit" and Cmd has "/set") or (Cmd has "wbadmin" and Cmd has "delete") or (Cmd has "ntdsutil" and Cmd has "ifm") or (Cmd has "wevtutil" and Cmd has " cl ") | extend Rule = "R10", Detail = Cmd),
 (W | where tostring(EventCode) in ("1102", "104") | extend Rule = "R10", Detail = strcat("event ", tostring(EventCode)), Computer = Host),
 (W | where tostring(EventCode) in ("4728", "4732", "4756") | extend G = extract(@"Group:\s+Security ID:\s+\S+\s+Group Name:\s+([^\r\n]+)", 1, M) | where G in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators") | extend Rule = "R11", Detail = G, Computer = Host)
| summarize Hits = count(), Hosts = dcount(Computer), Distinct = dcount(Detail), First = format_datetime(min(todatetime(EventTime)), "HH:mm:ss"), Last = format_datetime(max(todatetime(EventTime)), "HH:mm:ss") by Rule
| order by toint(substring(Rule, 1)) asc
```

### C. Exhibits

**E1 The two lures and the first execution** (BACKOFFICE-PC1). *Supports:* Edge wrote both archives to Emily's Downloads, 7-Zip was fetched and extracted each ISO, and rundll32 ran review.dll from D: three times, then from E: through the drive-letter loop. *Does not prove:* How the archives reached her (link or attachment), or that the files inside lacked the download mark.

![E1 The two lures and the first execution](exhibits/E1-the-two-lures-and-the-first-execution-20261023.png)

**E2 UAC bypass through fodhelper** (BACKOFFICE-PC1). *Supports:* The implant pointed the per-user ms-settings handler at C:\Users\Public\taskhostw.exe; the first fodhelper launch stayed Medium, the launch through cmd produced a High-integrity fodhelper, and taskhostw.exe started High one second later as its child. *Does not prove:* Why the first launch did not elevate.

![E2 UAC bypass through fodhelper](exhibits/E2-uac-bypass-through-fodhelper-20261023.png)

**E3 Injection into the Print Spooler, and full-access opens of LSASS** (all three). *Supports:* Remote threads into notepad.exe and spoolsv.exe on every host (13 in all), and lsass.exe opened with PROCESS_ALL_ACCESS (0x1fffff) by spoolsv.exe on the workstation and by taskhostw.exe on all three hosts. *Does not prove:* That memory was dumped: no dump file is logged.

![E3 Injection into the Print Spooler, and full-access opens of LSASS](exhibits/E3-injection-into-the-print-spooler-and-ful-20261023.png)

**E4 Admin shares, WMI and the copy to MEGA** (all three). *Supports:* Emily.Grant's own account (password typed in clear, masked here) mounted C$ on the file server, then the domain controller; WMI ran a shadow-copy delete with the same account; the renamed rclone copied C:\Shares to mega:HARBORLIGHT-exfil three times and resolved MEGA storage nodes 39 times. *Does not prove:* How much data reached MEGA: Sysmon records the lookups, not the bytes.

![E4 Admin shares, WMI and the copy to MEGA](exhibits/E4-admin-shares-wmi-and-the-copy-to-mega-20261023.png)

**E5 Anti-recovery, the AD database copy and log clearing, per host** (all three). *Supports:* The file server lost shadow copies, boot recovery and the backup catalog (each command twice); the domain controller's AD database was copied with ntdsutil IFM and its shadow copies deleted; wevtutil cleared logs on all three hosts, and the servers' own clear events (1102, 104) confirm it. *Does not prove:* The workstation's clear events: wevtutil ran there 21 times, but no 1102 or 104 from it is in the dataset.

![E5 Anti-recovery, the AD database copy and log clearing, per host](exhibits/E5-anti-recovery-the-ad-database-copy-and-l-20261023.png)

**E6 Encryption, the new domain admin, and beacons that outlived both** (all three). *Supports:* 128 ransom notes and 27 distinct .akira paths across the estate (two of them appear in two hosts' logs, so the per-host figures sum to 29); the directory's own events show svc_sql created, then added to Administrators and Domain Admins; the implants kept connecting to the C2 addresses until 09:23, 14:47 and 18:47. *Does not prove:* What the beacons carried, or that Akira's own encryptor (rather than a look-alike) was used: the binary was not analysed.

![E6 Encryption, the new domain admin, and beacons that outlived both](exhibits/E6-encryption-the-new-domain-admin-and-beac-20261023.png)

**E7 After the encryption: the consoles, AnyDesk and a second copy of the implant** (HL-FS01, BACKOFFICE-PC1). *Supports:* AnyDesk was running on the workstation from 00:29, before the first lure. At 13:44 to 13:45 a console sign-in as the file server's local Administrator opened three ransom notes and started C:\Users\Public\taskhostw.exe; at 13:49 the workstation's local helpdesk account signed in, opened AnyDesk and read AnyDesk's connection_trace.txt twice; the workstation was powered off at 14:27:48. *Does not prove:* Who was at either console, or who used AnyDesk at 10:43 and 13:47: the account names fit staff or the MSP, and the logs do not say which.

![E7 After the encryption: the consoles, AnyDesk and a second copy of the implant](exhibits/E7-after-the-encryption-the-consoles-anydes-20261023.png)

**E8 Detection replay: eleven rules on the whole dataset** (all three). *Supports:* R1 to R7 return exactly the v2 counts; the four new rules (R8 to R11) fire on attack activity only. The dataset also holds a day of ordinary background (Edge and OneDrive updaters, WMI, compatibility telemetry), and no rule fires on any of it. *Does not prove:* Production false-positive rates: one simulated day is a small benign baseline.

![E8 Detection replay: eleven rules on the whole dataset](exhibits/E8-detection-replay-eleven-rules-on-the-who-20261023.png)

**E9 The dataset: rows by host and source** (all three). *Supports:* 44,989 rows in two schemas: Sysmon (27,231 rows, EventID and Computer) and Windows event logs (17,758 rows, EventCode and ComputerName: Security, System, Application, PowerShell, and Defender on the workstation only). Event time runs 2026-02-04 00:00:18 to 18:47:29 UTC. *Does not prove:* Anything from outside the three hosts: no firewall, proxy, DNS server or MSP logs.

![E9 The dataset: rows by host and source](exhibits/E9-the-dataset-rows-by-host-and-source-20261023.png)

**E10 What Defender and PowerShell logging saw** (BACKOFFICE-PC1, HL-FS01). *Supports:* The implant pulled its tools from a second host name, sync.cloud-endpoint.net (five IWR downloads, among them a fake MsMpEng.exe inside the Windows Defender folder), and switched five Defender protections off, twice. On the workstation Defender detected the implant as Trojan:Win32/SuspGolang.AG and quarantined taskhostw.exe at 09:24:04, 15 seconds after that host's last beacon. *Does not prove:* That the 01:14 DefenderTamperingRestore detection belongs to the attack: it comes 43 minutes before the first lure, beside Defender's own service-key writes.

![E10 What Defender and PowerShell logging saw](exhibits/E10-what-defender-and-powershell-logging-saw-20261023.png)

**E11 HL-FS01's beacons per hour, around the 13:44 console sign-in** (HL-FS01). *Supports:* All three implants beaconed steadily (about 120 connections an hour each) through the morning; after the 13:45:16 launch, taskhostw.exe roughly doubles (150 in the 13:00 hour, 192 in the 47 minutes of the 14:00 hour against 94 and 96), so a second copy was running; the server's data ends at 14:47:52 with all three still beaconing. *Does not prove:* Why the server's data stops at 14:47:52: no shutdown event is logged there.

![E11 HL-FS01's beacons per hour, around the 13:44 console sign-in](exhibits/E11-hl-fs01-s-beacons-per-hour-around-the-13-20261023.png)

### D. Indicators

| Type | Value | Context |
|---|---|---|
| C2 host name | `cdn.cloud-endpoint.net` | Cloudflare 104.21.30.237 and 172.67.174.46, ports 80 and 443; every implant (E6) |
| Staging host name | `sync.cloud-endpoint.net` | The source of the five tool downloads on HL-FS01 (E10) |
| Lures | `Vendor_Invoice_Review.7z` / `.iso`, `Harborlight_Insurance_Claims.7z` / `.iso`, `review.dll` (export `StartW`) | Emily's Downloads; D: and E: (E1) |
| Implants | `C:\Users\Public\taskhostw.exe`, `C:\Users\Public\OneDriveSync.exe`, `C:\ProgramData\Microsoft\OneDriveSync.exe`, `C:\ProgramData\Microsoft\wsync.exe`, `C:\ProgramData\Microsoft\RuntimeBroker.exe` | Defender verdict on taskhostw.exe and review.dll: Trojan:Win32/SuspGolang.AG (E10) |
| Exfiltration tool | `C:\ProgramData\Microsoft\MsMpEng.exe` (rclone), `rclone.conf`, `config.dat`; a second copy at `C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe` | HL-FS01 (E4, E10) |
| Exfiltration target | `mega:HARBORLIGHT-exfil`, account `jwilson.vhr@proton.me` | HL-FS01 (E4) |
| Scripts | `C:\ProgramData\Microsoft\update.bat`, `C:\Users\Public\defender.bat` | HL-FS01; all hosts |
| Ransomware | `updater.exe` (`C:\Users\Public`, and `C:\ProgramData\Microsoft` on HL-FS01), `akira_readme.txt`, extension `.akira` | All hosts (E6) |
| Staging files | `C:\Users\Public\20260203185934_recon.zip`, `C:\Windows\Temp\ntds` | BACKOFFICE-PC1; ADDC01 |
| Registry | `HKCU\Software\Classes\ms-settings\shell\open\command`; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth` | BACKOFFICE-PC1 (E2); HL-FS01 |
| Scheduled task | `WindowsUpdate` to `C:\Users\Public\taskhostw.exe` (onstart, SYSTEM) | HL-FS01 |
| Accounts | `Emily.Grant` (password known to the attacker); `svc_sql` (SID ending -2105, Domain Admins) | E4, E6 |
