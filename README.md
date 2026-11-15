# BoilerStorm 2026: Team toolkit

Defensive scripts, checklists and templates for the ClosedAI network (1 OPNsense + 4 servers).
**Every script is read-only by default.** It reports and logs, and changes nothing, except the ones named `harden`, `audit-on` and `restore-web`, which ask or say what they change.
All output stays **on the box** (`C:\bs\` on Windows, `/root/bs/` on Linux). Never copy it out. Screenshots are the only thing that leaves.

## 1. Get it onto a box (no clipboard, so type it)

Replace `USER/REPO` with ours. Use the frozen tag so everyone has the same version.

**Windows (PowerShell as Administrator):**
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
iwr -UseBasicParsing https://github.com/USER/REPO/archive/refs/tags/frozen.zip -OutFile C:\bs.zip
Expand-Archive C:\bs.zip C:\ -Force ; cd C:\REPO-frozen
Get-ChildItem -Recurse | Unblock-File ; Set-ExecutionPolicy -Scope Process Bypass -Force
```
If it fails, the proxy may need to be named explicitly: add `-Proxy http://<proxy>:<port>` (check `netsh winhttp show proxy` or the browser's proxy setting).

**Linux (as root):**
```bash
cd /root && curl -L -o bs.tgz https://github.com/USER/REPO/archive/refs/tags/frozen.tar.gz
tar xzf bs.tgz && cd REPO-frozen
```
If curl fails: `env | grep -i proxy`, then `curl -x http://<proxy>:<port> ...`

## 2. What's inside

| Path | What | Where to run |
|---|---|---|
| `win/hunt.ps1` / `linux/hunt.sh` | **Run first.** Persistence, backdoor and webshell hunt. Works with no baseline | every box |
| `win/baseline.ps1` / `linux/baseline.sh` | Snapshot: users, groups, ports, processes, services, tasks/cron, autoruns, keys, web files, DNS records. The first run becomes the baseline | every box, at 10:00 |
| `win/diff.ps1` / `linux/diff.sh` | New snapshot vs baseline, prints only **what changed**. Use `-Loop 600` / `--loop 600` | every box, every ~20 min |
| `win/backup.ps1` / `linux/backup.sh` | On-box backups: DNS zones, GPOs, AD export, IIS config + web roots, shares + ACLs, /etc, DB dumps, Redis, mail config, firewall rules | every box, before hardening |
| `win/audit-on.ps1` / `linux/audit-on.sh` | Turns on the logging you need (4688 with command line, 4698, 4104, Kerberos, DS changes / journald persistent, auditd rules) | every box, early |
| `win/logwatch.ps1` / `linux/logwatch.sh` | **Live** log monitor in its own window/TTY: logons, brute force by IP, new users/groups/services/tasks, webshell process trees, log clearing, sudo, cron edits | every box, all day |
| `win/loghunt.ps1` / `linux/loghunt.sh` | One-shot "what happened in the last N hours" for incident reports (+ IIS / Apache log analysis) | when writing a report |
| `win/adaudit.ps1` | AD audit: privileged groups, roastable accounts, delegation, DCSync rights, AdminSDHolder, GPO scripts, GPP passwords, DNS zone settings | CAI-DC01 |
| `win/fim.ps1` / `linux/fim.sh` | File integrity monitor (web roots, SYSVOL, startup, cron, sudoers, PAM, systemd...) | WEB01, mail01, db01 |
| `win/harden.ps1` / `linux/harden.sh` | Interactive y/N quick hardening. Only scoring-safe items. Logs before/after for memos | after hunting |
| `win/restore-web.ps1` | Defacement recovery: quarantines the current web root, restores the backup, restarts IIS | WEB01 |
| `watch/svcwatch.sh` + `svcwatch.ps1` + `targets.conf` | **Network/service checker** for all hosts on public and LAN IPs: ping, ports, banners, HTTP content fingerprint (defacement), DNS answers (tampering). Status board + change log | one Linux box (Alt+F2) or Windows |
| `fw/opnsense.md` | Firewall checklist, console recovery, how to block one IP | cai-fw01 |
| `docs/TODO.md` | Tonight + day-of checklist | team |
| `docs/first30.md` | First 30 minutes per host + 5-minute re-harden after a revert | each box owner |
| `docs/threats.md` | Attack matrix per machine: what Red Team will try, evidence, how to close the path (the 50%) | hunter + report writer |
| `docs/injects.md` | Likely injects and what evidence to collect, memo + report checklists | captain |
| `templates/` | Word memo + incident report layouts, CSV trackers (incident timeline, inject board, PCR log, password change log) | captain's laptop |

## 3. Run order per box

**Windows** (PowerShell as admin, from the repo folder):
```
.\win\audit-on.ps1 ; .\win\hunt.ps1 ; .\win\baseline.ps1 ; .\win\backup.ps1
.\win\adaudit.ps1                      # DC only
start powershell "-ep bypass -noexit -file $PWD\win\logwatch.ps1"
start powershell "-ep bypass -noexit -file $PWD\win\fim.ps1"        # WEB01
.\win\harden.ps1
```
**Linux** (root, from the repo folder):
```
bash linux/audit-on.sh ; bash linux/hunt.sh ; bash linux/baseline.sh ; bash linux/backup.sh
# Alt+F2 / Alt+F3 (new console) or tmux:
bash linux/logwatch.sh
bash watch/svcwatch.sh -n <TEAM>
bash linux/fim.sh
bash linux/harden.sh
```

## 4. Rules these scripts respect (and you must too)

- Never touch the **Splunk Universal Forwarder** or the **competition CA**
- No attempt to identify or treat the scoring engine differently. svcwatch only checks our own hosts
- Nothing is uploaded anywhere. No VirusTotal. Outputs stay on the box
- Read-only by default, so nothing gets auto-deleted (lawsuit + legal hold: **disable, don't delete**)
- Block single IPs only, never subnets. No containers. No hostname/IP changes
- Scored account passwords change **only** through a PCR in Quotient

## 5. Reading the output

- `ALERT` (red): look now. `WARN` (yellow): look soon. `INFO` (gray): context
- Every line has a timestamp and hostname, ready for an incident report
- Diff/hunt files are saved under `C:\bs\` / `/root/bs/`. Open CSVs with `Import-Csv <file> | Out-GridView`
