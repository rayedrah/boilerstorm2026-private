# Team split (tonight + tomorrow)

Fill in names. Everyone owns a folder tonight and a set of boxes tomorrow.
Rule for tonight: **you only merge to `main` what you have run at least once.**

| Role | Person | Owns in the repo | Owns tomorrow (Guacamole) | Backup for |
|---|---|---|---|---|
| Captain / Inject lead | `[name]` | `README.md`, `docs/TODO.md`, `docs/injects.md`, `templates/` | Quotient, tickets, PCRs, itops@ mailbox, every memo | Firewall |
| Windows lead | `[name]` | `win/*`, `watch/svcwatch.ps1` | CAI-DC01, CAI-WEB01 | Captain (memos) |
| Linux lead | `[name]` | `linux/*`, `watch/svcwatch.sh` | cai-db01, cai-mail01 | Hunter |
| Network + Hunter | `[name]` | `fw/opnsense.md`, `watch/targets.conf`, `docs/threats.md`, `docs/first30.md` | cai-fw01 (first 20 min), then hunting across boxes, incident reports, sponsor challenge | Linux |

## Tonight, per role (stop by 22:15)

**Captain**
- [ ] Repo private now. Invite the team. Make it **public before filing the ticket** (the packet requires a public repo)
- [ ] Open `templates/memo-template.docx` + `incident-report-template.docx`, adjust layout to taste, test PDF export
- [ ] Print or copy the CSV trackers (inject board, incident timeline, PCR log)
- [ ] 22:15 merge freeze → tag `frozen` → make public → test download from a clean machine → file ticket (ask for written AI-OK)

**Windows lead**
- [ ] Windows Server eval VM (or any Windows 10/11 for the non-AD parts): run `hunt`, `baseline`, `diff`, `logwatch`, `harden -ReportOnly`
- [ ] If you can, promote a lab DC and run `adaudit`, `backup`
- [ ] Fix anything that errors. Learn what each ALERT means (`docs/threats.md`)

**Linux lead**
- [ ] Ubuntu + Rocky VM/container: run `hunt.sh`, `baseline.sh`, `diff.sh`, `logwatch.sh`, `fim.sh`, `harden.sh --report`
- [ ] `svcwatch.sh -n 1 -c` with a small test targets file against your VMs
- [ ] Know how to open a second console (Alt+F2) and use tmux if installed

**Network + Hunter**
- [ ] OPNsense VM if possible: walk through `fw/opnsense.md` (backup XML, NAT, block one IP with an alias, console menu)
- [ ] Read `docs/threats.md` end to end; be able to explain each row
- [ ] Draft `targets.conf` changes once Quotient shows scored services (tomorrow 9:30)

## Git workflow (keep it simple tonight)

```
git clone https://github.com/USER/REPO.git && cd REPO
git checkout -b <your-name>
# edit, test
git add -A && git commit -m "what you changed"
git push -u origin <your-name>
# open a Pull Request on GitHub; captain merges
```
Small fixes: commit straight to `main` is fine if you tell the group chat.
