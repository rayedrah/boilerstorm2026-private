#!/usr/bin/env bash
# One-shot log analysis for incident reports: "what happened in the last N hours".
#   sudo bash loghunt.sh            # last 6 hours
#   sudo bash loghunt.sh 2          # last 2 hours
#   sudo bash loghunt.sh 6 10.100.0.66     # only lines mentioning that IP
#   sudo bash loghunt.sh 6 jdoe            # only lines mentioning that user
# Output: /root/bs/loghunt-*.txt  (screenshot the relevant section for the report)

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root

HOURS="${1:-6}"; FILTER="${2:-}"
BS_LOG="$BS_ROOT/loghunt-$(filestamp).txt"
TMP="$(mktemp)"; trap 'rm -f "$TMP" "$TMP.web"' EXIT
head_() { log HEAD "==== $1 ===="; }

log HEAD "Log hunt on $HOST_SHORT, last $HOURS hour(s) ${FILTER:+filter=$FILTER}"

# Collect journal + classic log files into one stream
if have journalctl; then journalctl --since "-${HOURS}h" -o short-iso --no-pager 2>/dev/null > "$TMP"; fi
SINCE_EPOCH=$(( $(date +%s) - HOURS*3600 ))
for f in "$(auth_log)" "$(mail_log)"; do
  [ -n "$f" ] && [ -f "$f" ] && [ "$(stat -c %Y "$f")" -ge "$SINCE_EPOCH" ] && cat "$f" >> "$TMP"
done
[ -n "$FILTER" ] && { grep -F -- "$FILTER" "$TMP" > "$TMP.f"; mv "$TMP.f" "$TMP"; }
log INFO "$(wc -l < "$TMP") log lines loaded"

ip_of() { grep -oE '(from|rhost=|rip=)[ ]?[0-9a-fA-F.:]+[0-9a-fA-F]|\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]' | sed -E 's/^(from ?|rhost=|rip=)//; s/[][]//g'; }

head_ 'Auth failures by source IP (ssh, pam, imap/pop3, smtp-auth)'
grep -E 'Failed password|Invalid user|authentication failure|auth failed|SASL [A-Z-]+ authentication failed|Password mismatch' "$TMP" | ip_of | sort | uniq -c | sort -rn | head -20 |
  while read -r n ip; do lvl=WARN; [ "$n" -ge 10 ] && lvl=ALERT; log "$lvl" "$(printf '%-18s %5s failures' "$ip" "$n")"; done

head_ 'Usernames tried (spray detection: many users from one IP)'
grep -oE '(Failed password for (invalid user )?[^ ]+|Invalid user [^ ]+|user=<[^>]*>.*auth failed)' "$TMP" | sed -E 's/Failed password for (invalid user )?//; s/Invalid user //; s/user=<([^>]*)>.*/\1/' | sort | uniq -c | sort -rn | head -20 |
  while read -r n u; do log INFO "$(printf '%-24s %5s' "$u" "$n")"; done

head_ 'Successful SSH logins'
grep -E 'sshd.*Accepted' "$TMP" | while read -r l; do
  lvl=WARN; case "$l" in *"for root "*) lvl=ALERT ;; esac
  log "$lvl" "$(echo "$l" | grep -oE '^[^ ]+') $(echo "$l" | grep -oE 'Accepted [a-z-]+ for [^ ]+ from [^ ]+ port [0-9]+')"
done

head_ 'Successful login AFTER failures from the same IP (guessed password?)'
grep -E 'Failed password|authentication failure|auth failed' "$TMP" | ip_of | sort | uniq -c | awk '$1>=3{print $2}' > "$TMP.web"
grep -E 'sshd.*Accepted|Login: user=<' "$TMP" | while read -r l; do
  ip="$(echo "$l" | ip_of | head -1)"
  [ -n "$ip" ] && grep -qxF "$ip" "$TMP.web" && log ALERT "SUCCESS after failures from $ip: $(echo "$l" | cut -c1-200)"
done

head_ 'sudo / su'
grep -E 'sudo:.*COMMAND=|sudo:.*(incorrect password|NOT in sudoers)|su(\[[0-9]+\])?: (FAILED|\(to )' "$TMP" | while read -r l; do
  lvl=INFO; echo "$l" | grep -qE "$BAD_CMD_RE|NOT in sudoers|incorrect|FAILED" && lvl=ALERT
  log "$lvl" "$(echo "$l" | cut -c1-220)"
done

head_ 'Account / group / password changes'
grep -E '(useradd|userdel|usermod|groupadd|gpasswd|chpasswd|chage)\[|new (user|group): name=|password changed' "$TMP" | while read -r l; do log ALERT "$(echo "$l" | cut -c1-220)"; done

head_ 'Cron edits and suspicious cron runs'
grep -E '(CRON|crond|crontab)\[[0-9]+\].*(REPLACE|BEGIN EDIT|END EDIT|DELETE)' "$TMP" | while read -r l; do log ALERT "$(echo "$l" | cut -c1-200)"; done
grep -E '(CRON|crond)\[[0-9]+\].*CMD' "$TMP" | grep -E "$BAD_CMD_RE" | while read -r l; do log ALERT "$(echo "$l" | cut -c1-220)"; done

head_ 'Units enabled / key services stopping'
grep -E 'Created symlink .*\.(service|timer|socket|path)' "$TMP" | while read -r l; do log ALERT "$(echo "$l" | cut -c1-220)"; done
grep -E 'systemd\[1\]: .*(Stopped|Failed to start|failed with result)' "$TMP" | grep -E '(postfix|dovecot|mysql|mariadb|postgres|redis|nginx|httpd|apache2|ssh|irc|vsftpd|php-fpm|sssd|deputy)' | while read -r l; do log WARN "$(echo "$l" | cut -c1-200)"; done

head_ 'SELinux denials (attack OR your own change breaking a service)'
grep -E 'avc: +denied' "$TMP" | grep -oE 'denied +\{[^}]*\}.*comm="[^"]*"|scontext=[^ ]+ tcontext=[^ ]+' | sort | uniq -c | sort -rn | head -10 | while read -r l; do log WARN "$l"; done

head_ 'Mail: relay attempts, outbound mail, top senders'
n=$(grep -c 'Relay access denied' "$TMP"); [ "$n" -gt 0 ] && log WARN "$n relay attempts blocked (top IPs below)"
grep 'Relay access denied' "$TMP" | ip_of | sort | uniq -c | sort -rn | head -5 | while read -r c ip; do log WARN "  relay attempts $c from $ip"; done
grep -E 'postfix/smtp\[.*status=sent' "$TMP" | grep -vE 'relay=(local|dovecot|private|127\.0\.0\.1|\[127|lmtp)' | grep -oE 'to=<[^>]*>' | sort | uniq -c | sort -rn | head -10 | while read -r c t; do log WARN "  sent OUT: $t x$c"; done
grep -oE 'sasl_username=[^ ,]+' "$TMP" | sort | uniq -c | sort -rn | head -10 | while read -r c u; do log INFO "  SMTP-auth $u x$c"; done

head_ 'Web access logs: attack-like requests, POSTs to scripts, top IPs'
: > "$TMP.web"
for f in /var/log/nginx/access.log* /var/log/httpd/*access_log* /var/log/apache2/access.log*; do
  [ -f "$f" ] || continue
  [ "$(stat -c %Y "$f")" -ge "$SINCE_EPOCH" ] || continue
  case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac >> "$TMP.web"
done
[ -n "$FILTER" ] && { grep -F -- "$FILTER" "$TMP.web" > "$TMP.f"; mv "$TMP.f" "$TMP.web"; }
if [ -s "$TMP.web" ]; then
  grep -E '(cmd=|exec=|command=|\.\./|%2e%2e|union(%20|\+| )+select|<script|%3cscript|/etc/passwd|base64|eval\(|whoami|/bin/(ba)?sh|phpinfo|\.env|/\.git/)' "$TMP.web" | tail -40 |
    while read -r l; do log ALERT "$(echo "$l" | cut -c1-220)"; done
  grep -E '"POST [^"]*\.(php|phtml|cgi|pl|py|jsp)' "$TMP.web" | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -15 | while read -r l; do log WARN "POST $l"; done
  awk '{print $1}' "$TMP.web" | sort | uniq -c | sort -rn | head -10 | while read -r c ip; do log INFO "$(printf '%-18s %6s requests' "$ip" "$c")"; done
  awk '$9 ~ /^[45]/{print $1}' "$TMP.web" | sort | uniq -c | sort -rn | head -5 | while read -r c ip; do log WARN "$(printf '%-18s %6s 4xx/5xx (scanner?)' "$ip" "$c")"; done
else
  log INFO 'no web access logs in range'
fi

head_ 'Current state (for the report)'
who 2>/dev/null | while read -r l; do log INFO "logged in now: $l"; done
last -n 15 -F 2>/dev/null | head -15 | while read -r l; do log INFO "last: $l"; done
lastb -n 10 -F 2>/dev/null | head -10 | while read -r l; do log INFO "lastb: $l"; done

log HEAD "Saved: $BS_LOG"
