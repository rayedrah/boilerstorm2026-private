# Likely injects and what evidence to collect

The story: a lawsuit and "records must be kept", a formal notice "tomorrow morning", an ex-IT team that resigned together, docs that are only partly accurate, a CTO with "ideas about infrastructure", and an AI agent product (Deputy) plus a public chatbot (ClosedChat).
**AI may not write or help write anything submitted. The memo text is yours.** This file is a checklist of what to gather.

| Likely inject | Evidence to collect (screenshots / command output) | Script help |
|---|---|---|
| **Legal hold / records preservation** (very likely, morning) | Log retention increased, logs not cleared, mailboxes not purged, users disabled not deleted, backups made, who has delete rights | audit-on (both), backup (both), harden log |
| **Offboard the previous IT team** | List of their accounts (AD + local + Linux + firewall + SSH keys), now disabled, groups removed, passwords rotated for shared creds they knew | adaudit "All enabled users", hunt authorized_keys, diff |
| **Onboard new employees** (create users, groups, mailbox, share access) | AD user properties, group membership, test login, mailbox receives mail, share access works | adaudit / backup CSV before+after |
| **Asset inventory / verify the old docs** | Per host: OS, IP, services listening, open ports, what's scored, what's wrong in the old docs | baseline CSV (listening, services), svcwatch board |
| **Network diagram + firewall rule review** | NAT table, rule list with justification per scored service | OPNsense screenshots |
| **Password policy / admin account policy** | Domain policy before/after, FGPP for admins, why no mass PCR | adaudit policy section |
| **Incident briefing for executives** | Timeline, impact, what was done, what's next. Plain language | timeline sheet, loghunt |
| **Logging / monitoring setup** | auditpol after, journald persistent, auditd rules, what you watch and how | audit-on outputs |
| **Backup + restore test** | Backup location/time, a successful restore of one file/zone/page | backup, restore-web |
| **Patch status / vulnerability report** | Hotfix list, package updates available, Roundcube version + CVEs (cite URLs) | baseline hotfixes, hunt Roundcube |
| **Deputy / AI agent security review** | What user it runs as, what it can execute, what it can reach (DB/Redis/internet), human-in-the-loop controls, recommendations | ps/systemd unit, ss -tulpn, sudoers |
| **ClosedChat review** (prompt injection, data leakage) | What data/secrets it can see, test prompts that tried to extract them (carefully), mitigations | IIS logs, app config |
| **AI acceptable-use policy** | Policy memo. Cite any template you adapt (URL) | none |
| **Stand up / move a service** (CTO idea) | Before/after: same public IP, same DNS name, same content (packet rule). No containers | svcwatch shows UP throughout |
| **Mail: SPF/DKIM/DMARC records** | DNS records added on the DC, test result | baseline dns diff |
| **Least privilege for shares** | share-access.csv before/after, NTFS ACL | backup |

## Memo checklist (every inject)

- [ ] PDF (unless the card says otherwise)
- [ ] To: Tomas Whelan, Director of IT and Security. From: Team N (number only)
- [ ] Answers **exactly** what was asked, every part (re-read the card)
- [ ] Each action has a screenshot or command output, annotated (box/arrow), clock visible, Figure N caption
- [ ] Extra files are named in the memo
- [ ] Outside sources cited with URL
- [ ] One page if possible. Busy exec. No fluff
- [ ] Uploaded 10 min before due

## Incident report checklist (rubric)

- [ ] Proof of Red Team activity (annotated screenshot): 10%
- [ ] When it happened (timestamp): 10%
- [ ] How + when you detected it: 10%
- [ ] What the attack was + impact, src/dst IPs: 10%
- [ ] How the impact was mitigated: 10%
- [ ] **How the attack path was closed** (and why it holds): 50%
- [ ] One report can cover several compromises from the same attack
- [ ] No reports for weak settings nobody used (frivolous = penalty)
- [ ] Due 16:00 at the latest, so write each within 30 min
