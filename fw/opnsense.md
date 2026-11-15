# cai-fw01 (OPNsense) notes

OPNsense is managed in the web UI (https://10.42.0.1 from a LAN box's browser) or from the Guacamole console menu.
Nothing in this repo runs on the firewall. These are checklists.

## Console menu (when you lock yourself out)

The Guacamole console shows the OPNsense menu after login:
- **2) Set interface IP address**: fix a broken LAN IP (don't change the assigned IPs, packet rule)
- **3) Reset the root password**
- **4) Reset to factory defaults**: NO. This kills the whole team
- **8) Shell**: `pfctl -d` disables packet filtering (emergency only: everything open), `pfctl -e` re-enables, `configctl filter reload` reloads rules
- **13) Restore a backup**: pick an earlier config from history

## Start-of-day checklist

1. System > Configuration > Backups → **Download configuration** (keep it on DC/WEB). History is under System > Configuration > History (diff view = evidence of Red Team changes)
2. System > Access > Users → change admin password, check for extra users, check **API keys** per user
3. System > Settings > Administration → Listen interfaces: LAN. SSH: LAN only or disabled. Keep the anti-lockout rule
4. Firewall > NAT → Port Forward, One-to-One, Outbound: write down the PUB→LAN mapping. Remove anything extra
5. Firewall > Rules > WAN → only the scored services to their hosts. Watch for rules **at the top** that allow any
6. Firewall > Rules > LAN → outbound to the proxy must work (patching)
7. System > Settings > Cron → nothing unexpected
8. Firewall > Diagnostics > States: who is connected right now (filter by a suspicious IP)
9. Firewall > Log Files > Live View: blocked/passed traffic, filter by IP

## Blocking a malicious IP (allowed: single IPs, NOT subnets)

1. Firewall > Aliases → create `BS_BLOCK` (Host(s)) and add the IP
2. Firewall > Rules > WAN → new rule at the **top**: Block, source `BS_BLOCK`, any destination. Log enabled
3. Firewall > Diagnostics > States → kill existing states for that IP
4. Screenshot the alias + rule + time for the incident report
5. Next time just add the IP to the alias

## Debugging "service down in Quotient"

- svcwatch: PUB down + LAN up = firewall/NAT. PUB + LAN down = the host/service
- Check the NAT rule still exists and is enabled, then the WAN rule, then the host firewall
- Firewall > Log Files > Live View filtered on the host's LAN IP while the check runs
