# First 30 minutes, per host

Get the repo onto the box first (README has the exact commands). One person per Guacamole console.
**Screenshot with the clock visible before you change anything.** The 10:00 state is evidence.

## cai-fw01 (OPNsense), network person, about 15 min, then go hunting

1. Log in to the web UI from a Windows box's browser (https://10.42.0.1). Change the `admin` password (System > Access > Users)
2. **System > Configuration > Backups: download the config XML** and save it on the DC/WEB box. This is your restore point
3. System > Access > Users: any user besides admin/root? Any API keys? Screenshot, then disable
4. Firewall > NAT > Port Forward + One-to-One: write down what maps PUB.x → LAN.x. Anything extra (e.g. high port → 3389/22)? Screenshot, disable
5. Firewall > Rules > WAN: list the allow rules. Scored ports must stay open. "Any → any" or rules to the firewall itself on 22/443/80 from WAN → disable
6. System > Settings > Administration: web GUI + SSH listen on **LAN** only. Keep the anti-lockout rule
7. System > Settings > Cron: anything odd → screenshot, remove
8. Firewall > Log Files > Live View: watch for a minute. Note IPs hammering you
9. Tell the team the NAT table (they need it to debug "PUB down, LAN up")

## CAI-DC01 (Windows Server 2025), Windows lead

1. Change `CLOSEDAI\admin` password. Create a break-glass Domain Admin (boring name, long password, write it on paper)
2. Get the repo. `Unblock-File` the scripts. Open 3 PowerShell windows as admin
3. Window 1: `.\audit-on.ps1` → `.\hunt.ps1` → `.\adaudit.ps1` → `.\baseline.ps1` → `.\backup.ps1`
4. Window 2: `.\logwatch.ps1` (leave it running)
5. Window 3: work the ALERTs. Order: rogue privileged group members → DCSync/AdminSDHolder ACEs → GPO tasks/scripts → services/tasks/Run keys → AS-REP / Kerberoast accounts → DNS zone settings
6. `.\harden.ps1` (answer one by one, watch Quotient DNS/LDAP/SMB checks)
7. Ex-IT team accounts: **disable** (don't delete), note them for the offboarding inject
8. Optional if time: install Sysmon (free, Microsoft) with a known config through the proxy

## CAI-WEB01 (Windows Server 2022), Windows lead or second person

1. Change local `admin` password. Create a break-glass local admin
2. `.\audit-on.ps1` → `.\hunt.ps1` → `.\baseline.ps1` → `.\backup.ps1` (backup **before** touching the web root)
3. `.\fim.ps1` in its own window, `.\logwatch.ps1` in another
4. Work the ALERTs: webshells in web roots → IIS modules → app pool identities → FTP anonymous write → share permissions → services/tasks/Run keys
5. Open the website locally in the browser. Check the HTTP and HTTPS checks in Quotient
6. Check the team mailbox (Roundcube) from this box's browser and tell the captain what's there
7. `.\harden.ps1`

## cai-db01 (Ubuntu 26.04), Linux lead

1. `passwd admin`. Make a break-glass sudo user (useradd + usermod -aG sudo)
2. Get the repo. `sudo bash linux/hunt.sh` → `baseline.sh` → `backup.sh` → `audit-on.sh`
3. Alt+F2 (or tmux): `sudo bash linux/logwatch.sh`. Alt+F3: `bash watch/svcwatch.sh -n <team>`
4. Work the ALERTs: UID 0 / empty password accounts → authorized_keys → sudoers → cron/systemd → Redis no-auth → DB users `%` → Deputy service user → SUID
5. Find what Deputy is: `systemctl list-units --type=service` + `ss -tulpn`, see who runs it, its config, which DB/Redis it talks to. Write it down (injects will ask)
6. Find the chat server (IRC) and the scored channel
7. `sudo bash linux/harden.sh`

## cai-mail01 (Rocky Linux 10), Linux lead or second person

1. `passwd admin`. Break-glass user in `wheel`
2. `hunt.sh` → `baseline.sh` → `backup.sh` → `audit-on.sh`
3. `logwatch.sh` on Alt+F2, `fim.sh` on Alt+F3
4. Work the ALERTs: open relay / always_bcc / sieve redirects → Dovecot master/static passdb → Roundcube webshells + installer/ → authorized_keys/cron/systemd → SELinux state
5. Send yourself a test mail (itops@ → itops@) and read it in Roundcube. SMTP + IMAP + webmail all work = good
6. `harden.sh`

## After a revert (-200): 5-minute re-harden

The machine comes back with **default passwords and every implant**.
1. Change admin password immediately (Red Team knows the default)
2. Re-download the repo (the box is fresh)
3. `hunt` → work ALERTs → `baseline --promote` once clean → `backup`
4. Re-apply PCR'd passwords? **No.** PCRs live in Quotient. But scored users on a reverted DC will have their *original* passwords again. Ticket White Team if unsure
5. Start logwatch again
