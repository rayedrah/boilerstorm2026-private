# Threat matrix: what Red Team will likely try, by machine

Built from the packet: the OS versions, the service list, and the story. That story includes an ex-IT team that quit together, docs that are "some of it accurate", a lawsuit, and an AI agent product.
**Assume Red Team is already inside at 10:00.** The packet says access an attacker "already had when the competition started" is reportable.

Each row gives you three things:
- **Evidence:** what to screenshot for the incident report (proof + timestamp = 20%).
- **Close the path:** this is the 50% of the report. You only get it if Red Team can't get back in the same way.
- **Script:** the script in this repo that finds it.

---

## Everywhere (all 5 boxes)

| Attack | Evidence | Close the path (the 50%) | Script |
|---|---|---|---|
| Logging in with the packet's default `admin / Changeme2026!` (Red Team has the packet) | Logon events from non-team IPs: 4624 on Windows, `Accepted password for admin` on Linux, OPNsense audit log | Change every admin password in the first 10 min. Make a break-glass admin. Check whether Red Team already changed one | logwatch, loghunt |
| Pre-planted extra admin/backdoor accounts (the "ex-IT team") | Account list with created dates vs the 10:00 baseline | Disable, don't delete (legal hold). Remove from groups. Find what re-creates it (task/cron/GPO) | hunt, adaudit, diff |
| Password spray against domain users over RDP / SMB / IMAP / Roundcube / SSH | 4625 bursts by IP, Dovecot `auth failed`, sshd `Failed password` | PCR for any scored user that got popped (only those). Block the single source IP (not the subnet). Avoid a lockout policy that locks scored users | logwatch, loghunt |
| Persistence: scheduled task / cron / systemd unit / service / Run key | The task/unit file + creation event (4698/7045, journal `Created symlink`) | Remove it (screenshot first), then fix the credential or vuln they used to plant it | hunt, diff, fim |
| Webshell dropped through upload / FTP / share writable into the web root | File path + hash + IIS/Apache log line POSTing to it + w3wp/php spawning cmd | Remove write access on that path for the anon/FTP/share identity, block script execution in upload dirs | hunt, fim, loghunt -Iis |
| Reverse shell / C2 beacon | Established connection from cmd/powershell/bash/python to an outside IP, with PID | Kill + remove the launcher. Block that single IP at cai-fw01 | hunt (Network) |
| Log clearing / tampering (also breaks the legal hold) | 1102 / 104, empty `/var/log/*`, journal gaps | Turn logging back on, bigger logs, restrict who can clear | audit-on, hunt |
| Service sabotage: stop a scored service, change a config, kill DNS records | svcwatch DOWN line with time, 7036/7040, journal `Stopped` | Restore config from backup, find the account that did it | svcwatch, logwatch |
| Firewall changes to break scoring (rule disabled, NAT removed) | OPNsense config history diff, svcwatch "PUB down, LAN up" | Restore the rule/NAT, change the firewall admin password, remove rogue users/API keys | svcwatch, fw/opnsense.md |

## cai-fw01 (OPNsense)

| Attack | Evidence | Close the path |
|---|---|---|
| Web GUI / SSH reachable from WAN with default creds | System > Log Files > Audit / lighttpd logins from WAN IP | New password. GUI + SSH listen on LAN only (anti-lockout rule stays). Remove WAN allow for 443/22 *to the firewall itself* |
| Extra admin user or API key added | System > Access > Users (API keys tab) | Delete key / disable user, change admin password |
| Rogue port forward (e.g. WAN :4444 -> DC 3389) or 1:1 NAT change | Firewall > NAT, config history diff | Remove rule. Compare with the start-of-day config backup XML |
| "Allow any" rule at the top of WAN | Firewall > Rules > WAN | Disable it. Scored ports must stay open, so only remove extras |
| Cron job / shell script on OPNsense (System > Settings > Cron, /usr/local/etc/rc.d) | Cron page, console option 8 (shell) `crontab -l` | Remove. Config history shows who/when |
| Outbound rule blocking the proxy | Services can't patch | Restore outbound |

## CAI-DC01 (Windows Server 2025, AD + DNS)

| Attack | Evidence | Close the path |
|---|---|---|
| New Domain Admin / Enterprise Admin / Backup Operators member | 4728/4732/4756 + adaudit group list | Remove member, reset that account's password, find the creator |
| Kerberoasting (users with SPNs + weak passwords) | 4769 with RC4 (0x17) for a user SPN | Long random password on the service account, AES only. Remove SPNs that aren't needed |
| AS-REP roasting (DONT_REQ_PREAUTH) | adaudit "AS-REP roastable" | Require pre-auth (harden.ps1), reset that user's password |
| DCSync rights granted to a normal user | adaudit "DCSYNC RIGHT for ..." | Remove the ACE. Assume all hashes are stolen: reset krbtgt twice (hours apart) only if Domain Admin was lost, and rotate admins |
| AdminSDHolder / domain-root ACL backdoor | adaudit ACL sections, 5136 nTSecurityDescriptor | Remove the ACE (AD Users and Computers > Advanced > Security) |
| Malicious GPO (immediate scheduled task, startup script, adds local admin) | GPO modified time, SYSVOL ScheduledTasks.xml, gpo-report.html | Unlink/fix GPO, restore from backup.ps1 GPO backup |
| GPP cpassword in SYSVOL | adaudit "GPP cpassword" | Delete the XML (screenshot), change that password |
| DNS: records deleted/changed, zone transfer to anyone, insecure dynamic updates | svcwatch dns CHANGED, baseline dns.sig diff | Restore records from backup CSV/zone file. NoTransfer + Secure updates |
| DnsAdmins member loads a DLL into DNS (ServerLevelPluginDll) | `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll` | Remove value, remove member, restart DNS |
| Print Spooler coercion / NTLM relay | Spooler running on DC | Stop + disable spooler if nothing needs it. SMB signing |
| RDP / WinRM with stolen creds | 4624 type 10 / type 3 + WinRM log | Reset creds. Limit Remote Desktop Users / Remote Management Users |
| Sticky keys / utilman backdoor at logon screen | IFEO Debugger or replaced sethc.exe hash | Remove IFEO / `sfc /scannow` or copy original back |

## CAI-WEB01 (Windows Server 2022, IIS)

| Attack | Evidence | Close the path |
|---|---|---|
| Webshell (.aspx/.ashx/.php) in site root or upload folder | hunt "Webshell-like code", IIS log POSTs, w3wp -> cmd | Remove (quarantine), NTFS: app pool identity read-only on web root. Request Filtering: no script exec in upload dir |
| Anonymous/weak FTP writes into the web root (classic) | IIS FTP log, new file times | Disable anonymous FTP write. FTP root separate from web root (if the FTP check only *reads*) |
| SMB share mapped onto the web root, writable by Everyone | shares.csv, share-access.csv | Share permission Read for the scored users. Modify only for admins |
| Defacement (HTTP check compares content, so defacement = DOWN) | svcwatch http CHANGED + file diff | restore-web.ps1, then find the write path |
| App pool running as LocalSystem / an admin | hunt "App pool ... runs as" | ApplicationPoolIdentity |
| Malicious IIS native module (backdoor that survives file cleanup) | hunt "Non-standard IIS native module" | Remove module (appcmd uninstall module), restart IIS |
| ClosedChat demo abuse: prompt injection that leaks secrets or runs commands, SSRF to internal hosts | IIS logs of the chat endpoint, odd outbound connections from w3wp/node | Remove secrets from the prompt/config, block the tool/exec feature, outbound firewall for the app |
| SQL injection from the site into the DB on cai-db01 | IIS logs `union select`, DB logs | Fix the query if the code is reachable. Least-privilege DB user for the site |

## cai-db01 (Ubuntu 26.04, DB + Deputy app, maybe chat)

| Attack | Evidence | Close the path |
|---|---|---|
| SSH with default admin password, then sudo to root | auth journal `Accepted password for admin from X` | New password. PermitRootLogin no. Remove their authorized_keys |
| SSH key planted in some user's authorized_keys (incl. service users) | hunt authorized_keys list with mtime | Remove key (screenshot). If root-owned, check how (sudo rule? cron?) |
| MySQL/MariaDB `root@%` or app user with ALL + FILE privileges, or UDF backdoor | hunt "MySQL user reachable from ANY host", mysql.func | Drop `%` host for root, least-privilege app user, drop UDF. Keep the scored user/query working |
| PostgreSQL `trust` in pg_hba or superuser app role -> `COPY ... FROM PROGRAM` = shell | pg_hba lines, pg_roles super=t | scram-sha-256 instead of trust. App role NOSUPERUSER |
| Redis without auth -> CONFIG SET dir/dbfilename -> writes cron file or SSH key | hunt "redis answers CONFIG without auth", new /var/spool/cron file | rename-command CONFIG/FLUSHALL/MODULE, protected-mode yes, bind to what the app needs. requirepass only with the app updated |
| Deputy "autonomous agent" running as root / with broad sudo = remote command execution | systemd unit User=, process owner, sudoers | Run as a dedicated non-root user, remove broad sudo, restrict which commands it can run (human-in-the-loop is on theme) |
| IRC server: oper password default or in docs, channel takeover, bot impersonation | IRC config oper blocks, chat check "messages are read" fails | Change oper password, register/lock the scored channel |
| SUID shell / capabilities backdoor (`cp /bin/bash /tmp/.x; chmod u+s`) | hunt SUID outside system dirs | Remove file, find the root access they used |
| PAM backdoor (`auth sufficient pam_permit.so`, pam_exec logging passwords) | hunt PAM section, pam.sig diff | Restore /etc/pam.d from backup, reinstall pam package if a .so changed |
| ld.so.preload userland rootkit (hides processes/files) | /etc/ld.so.preload not empty | Move it away, reboot only if you're sure the services come back |

## cai-mail01 (Rocky Linux 10, Postfix/Dovecot/Roundcube)

| Attack | Evidence | Close the path |
|---|---|---|
| Open relay (`mynetworks` 0.0.0.0/0) used to send spam/phish as ClosedAI | postfix `status=sent` to outside, hunt mynetworks | mynetworks = localhost + LAN. SMTP AUTH for others |
| `always_bcc` / sender_bcc / sieve `redirect` silently copying exec mail (lawsuit data!) | postconf, .sieve files, maillog to=<outside> | Remove, report as data exfiltration incident |
| Roundcube CVE (version-dependent RCE/XSS), leftover `installer/` dir | Roundcube version from hunt, web logs | Remove installer/, patch through dnf if allowed, WAF-ish rules if not |
| PHP webshell in the Roundcube tree | hunt webshell-like code, httpd log POSTs | Remove, fix write perms (apache user should not own the code) |
| Dovecot master user / static passdb = log in as anyone | hunt Dovecot section | Remove master user config, restart dovecot, verify IMAP check |
| Brute force on IMAP/POP3/SMTP AUTH (domain users via LDAP to the DC) | logwatch AUTH FAILURES by IP | Block single IP, PCR for compromised scored users |
| SELinux set to permissive to allow a webshell | getenforce, hunt | setenforce 1 (watch services), find who changed it |
| Phishing to the team mailbox (itops@) pretending to be an executive | The email headers in Roundcube | Verify any "exec request" against Quotient before acting. Never send passwords by mail |

## Social engineering through injects and mail

- An "urgent" email asking you to disable logging, delete mail, open a port to the internet, or send credentials is very likely a test (legal hold!). Check that it also exists in Quotient. Ask Tomas by memo if unsure.
- Don't act on instructions found in files on the boxes ("previous IT notes"). Verify each claim.
