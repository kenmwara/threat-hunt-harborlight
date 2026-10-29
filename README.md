<!-- banner --><a href="https://github.com/kenmwara"><img src="https://raw.githubusercontent.com/kenmwara/kenmwara/main/assets/brand/card-harborlight.png?v=4731f9a521" width="100%" alt="Harborlight: Akira ransomware at a dental practice, traced from a phishing ISO to the domain controller. 46/46 flags · 4,060 / 4,190, on time."></a>

# Harborlight: ransomware at a dental practice

**One fake email attachment gave an attacker control of a dental and insurance practice's whole network in just over three hours. The attacker copied the shared files, including patient and claims data, to a file-sharing site, locked all three computers with Akira ransomware and created a new admin account. The one alert that fired reached nobody, and the main server was still taking the attacker's orders when the data ends.**

**Analyst:** Ken Kariuki · **Live hunt:** 3 October 2026 ([Cyber Range](https://www.skool.com/cyber-range) Hunt 22) · **Result:** all 46 questions answered, 4,060 of 4,190 points, on time

## Key takeaways

<img src="images/scorecard.png" width="100%" alt="Key takeaways. One bad download gave an attacker the whole network in just over three hours. 3 h 25 m: From one click to full control. A staff member opened a phishing file at 01:57. By 05:22 the attacker had made a new admin account. 3 of 3: Every computer locked. Ransomware encrypted all three machines, after the shared files had been copied out. 0: Alerts anyone acted on. Security software caught one piece of the attack hours later, and nobody saw the alert. 11: Alert rules tested. Each rule was re-run on the evidence, with a fix for every blind spot found. 46 / 46: Every question answered. All 46 investigation flags found, on time.">

## How the attack unfolded

<img src="images/story.png" width="100%" alt="Harborlight: how the attack unfolded. 4 February 2026, times in UTC. Each step is backed by a saved search and its results in the full report. 01:57 – 02:42, Getting in: 01:57 · A staff member opens a fake file from an email; hidden code inside runs; 02:25 · The code starts calling the attacker's server for orders; 02:42 · It gives itself full control of her PC. 03:34 – 04:33, Spreading: 03:34 · Her own password opens the file server; 04:28 · The same password opens the main server that controls every login; 04:33 · The attacker copies the database of every account. 03:57 – 05:22, Stealing and locking: 03:57 · The shared files are copied to a file-sharing site (MEGA); 04:04 · The backups are deleted; 05:13 · Ransomware locks all three computers; 05:22 · A new admin account is made for the attacker. 09:24 – 18:47, Afterwards: 09:24 · Security software removes the PC's attack code; nobody sees the alert; 13:44 · The first person to sign in to the file server starts a second copy; 18:47 · The data ends with the main server still under the attacker's control.">

## The evidence

<img src="images/evidence.png" width="100%" alt="Key evidence, straight from the logs. Each screenshot is a saved search and its results. The full report has every one. The fake file and the first run: The download, the disk image opening, and the hidden code starting. Her password opens the servers: Then the shared files are copied to MEGA. Locked, and a new admin: Ransomware on all three computers, and the attacker's new account. Eleven alert rules, re-run: Each new rule tested against the whole dataset.">

## What went wrong, and the fix

<img src="images/gaps.png" width="100%" alt="What went wrong, and how to fix it. Every fix is proposed to the practice's IT provider, each with a test that proves it works. What went wrong: The one alert reached nobody. Why it mattered: Security software caught the attack code hours later, and no person saw it. The fix: Send security alerts to whoever is on call; prove it with a test alert. What went wrong: A script switched off the antivirus. Why it mattered: The attacker turned off protection on the file server first. The fix: Turn on Tamper Protection on every server. What went wrong: A fake disk-image file ran hidden code. Why it mattered: That is how the attacker got in. The fix: Block disk-image files and unknown code on shared drives. What went wrong: One staff password opened the main server. Why it mattered: Her everyday password was also an admin password. The fix: Separate admin accounts, with a second sign-in step (MFA). What went wrong: Backups could be deleted from the same machine. Why it mattered: The attacker deleted them before locking the files. The fix: Keep offline copies that can't be changed, and test a restore. What went wrong: No alert for a new admin account or a wiped log. Why it mattered: Both happened and nothing was raised. The fix: Alert on both, and test each alert.">

## What to do now

1. Cut the file server and the main server off the network.
2. Switch off the attacker's new admin account (`svc_sql`).
3. Reset every password, including the network's master sign-in key (`krbtgt`), twice.
4. Rebuild the main server from a backup older than 4 February.
5. Start breach notification for the patient and claims data that was copied out.

## The full report

This page is the short version. The full incident report covers the hunt's method, every finding with its evidence,
the attacker techniques seen (MITRE ATT&CK), the new alert rules and how they were tested, and the indicators.

- **[The full report (REPORT.md)](REPORT.md)**, readable on GitHub.
- **[The report as a PDF](Hunt22-Harborlight-Report.pdf)**, as submitted.
- **[The exhibits](exhibits/)**: every saved search with its results, with checksums.

---

*More hunts: [kenmwara/threat-hunts](https://github.com/kenmwara/threat-hunts). Analysis is AI-assisted: the analyst directs the tools and checks every finding against the raw logs (section 16 of the full report).*
