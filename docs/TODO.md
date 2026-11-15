# BoilerStorm 2026 TODO (team N)

## Tonight (Sat Nov 14)

- [ ] Captain: create a **public** GitHub repo with a short name. Push this folder
- [ ] Everyone: read README.md and this file
- [ ] Each role: run your scripts once in a lab VM/WSL (Windows Server eval ISO, Ubuntu, Rocky), so you know what the output looks like
- [ ] Check the repo has **no real passwords, tokens or personal info**
- [ ] From a clean machine: download the repo zip with no login (exact URL in README). Confirm it unzips and runs
- [ ] **Captain files the ticket with the repo URL before 23:59.** Add the AI-assistance confirmation line. Screenshot the confirmation
- [ ] Do not push after 23:59 (only the frozen version may be used)
- [ ] Print or hand-write: `docs/first30.md` for your box, the PCR log, the inject board, the incident timeline (templates/)
- [ ] Each person writes the repo zip URL on paper (no clipboard in Guacamole)
- [ ] Charge laptops. Sleep

## Sun 9:00 to 10:00

- [ ] Check in by 9:00, sit together, one monitor each max
- [ ] Everyone signs in to auth.purdueblue.team. Captain answers the **Welcome inject** right away
- [ ] Open Quotient: write down **every scored service and every scored account** (those passwords change only via PCR)
- [ ] Edit `watch/targets.conf` on paper to match the scored services
- [ ] Agree who takes which Guacamole console (one person per host)

## 10:00 to 10:30 (each person on their own box, see first30.md)

- [ ] Change the `admin` password (firewall, DC, WEB, db, mail). Captain changes itops@ only if it is **not** scored, otherwise PCR
- [ ] Download + unzip the repo
- [ ] Run `hunt` + `baseline` + `backup` + `audit-on`. Screenshot the hunt summary (pre-existing access evidence)
- [ ] Start `logwatch` (and `fim` on WEB01, `svcwatch` on db01 or mail01) in their own windows/TTYs
- [ ] Fix the ALERT lines, highest first. **Screenshot before you fix. Log it on the timeline**
- [ ] Watch Quotient after every change

## All day

- [ ] Every 15 min: captain checks Quotient + itops@ mailbox, updates the inject board
- [ ] Every 30 min: 2-minute standup. What's down, what's suspicious, next inject due
- [ ] Each box owner: run `diff` every ~20 min (or `diff -Loop 600` / `diff.sh --loop 600`)
- [ ] Each incident: screenshot → timeline → contain → close the path → report within 30 min
- [ ] Each inject: read twice → split hands-on work → captain writes memo → read once more → upload **10 min before due**
- [ ] Sponsor challenge drops: hunter takes it
- [ ] 15:15 no new hardening. 15:45 last incident report uploaded. 16:00 hard stop

## Things we decided

- Disable, never delete (users, mail, logs). Lawsuit + "records must be kept"
- Block single IPs only, never subnets. Never filter by "is this the scorer"
- Never touch the Splunk Universal Forwarder or the competition CA
- Nothing leaves the environment except screenshots for memos/reports
