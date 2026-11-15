#!/usr/bin/env bash
# Live log monitor for cai-db01 / cai-mail01. Leave it running on its own TTY (Alt+F2..F6) or tmux pane.
# Follows the systemd journal (+ auth/mail/web/audit log files) and prints one colored, timestamped
# line per interesting event: logins, brute force / spray per source IP, sudo, user/group changes,
# cron edits, new units, key services stopping, SELinux denials, web attacks, mail auth failures.
#   sudo bash logwatch.sh                 # from now on
#   sudo bash logwatch.sh --back 500      # replay the last 500 journal lines first
#   sudo bash logwatch.sh --file /var/log/nginx/access.log   # add more files to follow
# Saved to /root/bs/logwatch-*.txt

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root

BACK=0; EXTRA=(); TESTFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --test) TESTFILE="$2"; shift ;;   # replay a saved log file through the rules, then exit
    --back) BACK="${2:-200}"; shift ;;
    --file) EXTRA+=("$2"); shift ;;
  esac
  shift
done
OUT="$BS_ROOT/logwatch-$(filestamp).txt"

FILES=()
for f in "$(auth_log)" "$(mail_log)" /var/log/audit/audit.log \
         /var/log/nginx/access.log /var/log/httpd/access_log /var/log/httpd/ssl_access_log /var/log/apache2/access.log \
         /var/log/roundcubemail/errors.log /var/log/roundcube/errors.log /var/log/vsftpd.log /var/log/xferlog "${EXTRA[@]}"; do
  [ -n "$f" ] && [ -f "$f" ] && FILES+=("$f")
done

log HEAD "Logwatch on $HOST_SHORT. Journal + ${#FILES[@]} file(s): ${FILES[*]}" "$OUT"
log INFO "Reminder: White Team and the scoring engine log in too. Judge by account + source IP." "$OUT"

# mawk (Ubuntu default) buffers piped input in big blocks -> live lines would never show. Force line mode.
AWK_OPTS=()
if awk -W version 2>&1 | head -1 | grep -qi mawk; then AWK_OPTS=(-W interactive); fi

KEYSVC='(postfix|dovecot|mysql|mariadb|postgres|redis|valkey|nginx|httpd|apache2|sshd|ssh\.service|inspircd|unrealircd|ngircd|ergo|vsftpd|php-fpm|named|sssd|deputy|gunicorn|uwsgi|node|SplunkForwarder|splunk)'

{
  if [ -n "$TESTFILE" ]; then cat "$TESTFILE"; exit 0; fi
  if have journalctl; then
    journalctl -f -n "$BACK" -o short-iso --no-pager 2>/dev/null &
  fi
  if [ "${#FILES[@]}" -gt 0 ]; then
    tail -n0 -q -F "${FILES[@]}" 2>/dev/null &
  fi
  wait
} | awk "${AWK_OPTS[@]}" -v host="$HOST_SHORT" -v out="$OUT" -v bad="$BAD_CMD_RE" -v keysvc="$KEYSVC" -v tty="$([ -t 1 ] && echo 1 || echo 0)" '
function now(   c, t) { c = "date \"+%Y-%m-%d %H:%M:%S\""; c | getline t; close(c); return t }
function emit(lvl, msg,   line, col) {
  line = "[" now() "] [" host "] [" lvl "] " msg
  col = ""
  if (tty == 1) {
    if (lvl == "ALERT") col = "\033[31m"; else if (lvl == "WARN") col = "\033[33m"; else if (lvl == "OK") col = "\033[32m"; else col = "\033[90m"
    print col line "\033[0m"
  } else print line
  print line >> out
  fflush(); fflush(out)
}
function grab(s, re, skip,   r) { if (match(s, re)) { r = substr(s, RSTART + skip, RLENGTH - skip); return r } return "" }
function srcip(s,   ip) {
  ip = grab(s, "from [0-9a-fA-F.:]+[0-9a-fA-F]", 5); if (ip != "") return ip
  ip = grab(s, "rhost=[0-9a-fA-F.:]+[0-9a-fA-F]", 6); if (ip != "") return ip
  ip = grab(s, "rip=[0-9a-fA-F.:]+[0-9a-fA-F]", 4); if (ip != "") return ip
  ip = grab(s, "\\[[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\]", 1); if (ip != "") return substr(ip, 1, length(ip) - 1)
  return "?"
}
function fail(kind, s,   ip, n) {
  ip = srcip(s); n = ++fails[ip]
  if (n == 5 || n == 10 || n == 25 || n == 50 || n % 100 == 0)
    emit(n >= 10 ? "ALERT" : "WARN", "AUTH FAILURES x" n " from " ip " (latest: " kind ")" (n >= 10 ? "  <- BRUTE/SPRAY" : ""))
}
{ l = $0 }
# ---------------- ssh / login
l ~ /sshd.*Accepted (password|publickey|keyboard-interactive)/ {
  u = grab(l, "for [^ ]+", 4); m = grab(l, "Accepted [a-z-]+", 9)
  emit(u == "root" ? "ALERT" : "WARN", "SSH LOGIN " u " via " m " from " srcip(l) (fails[srcip(l)] > 3 ? "  <- AFTER FAILURES" : "")); next
}
l ~ /sshd.*(Failed password|Failed publickey|Invalid user|authentication failure|maximum authentication attempts)/ { fail("ssh", l); next }
l ~ /(dovecot|imap-login|pop3-login).*(auth failed|Disconnected.*auth failed|unknown user|Password mismatch|authentication failure)/ { fail("imap/pop3", l); next }
l ~ /(postfix|smtpd).*SASL [A-Z-]+ authentication failed/ { fail("smtp-auth", l); next }
l ~ /(imap|pop3)-login: Login: user=</ && l !~ /user=<itops@/ { if (logins++ % 20 == 0) emit("INFO", "mail logins flowing (sample): " substr(l, index(l, "user=<"), 60)); next }
l ~ /pam_unix\([^)]*\): authentication failure/ { fail("pam", l); next }
# ---------------- privilege
l ~ /sudo:.*COMMAND=/ {
  c = substr(l, index(l, "COMMAND=") + 8); u = grab(l, "sudo:[ ]+[^ ]+", 5); gsub(/^ +/, "", u)
  emit(c ~ bad ? "ALERT" : "WARN", "SUDO by " u ": " c); next
}
l ~ /sudo:.*(incorrect password|NOT in sudoers|authentication failure)/ { emit("ALERT", "SUDO FAILURE: " substr(l, index(l, "sudo:"))); next }
l ~ /su(\[[0-9]+\])?: (FAILED|\(to )/ || l ~ /su: pam_unix\(su(-l)?:session\): session opened/ { emit("WARN", "SU: " substr(l, index(l, "su"))); next }
# ---------------- accounts
l ~ /(useradd|userdel|usermod|groupadd|groupdel|groupmod|gpasswd|chpasswd|chage)\[[0-9]+\]/ || l ~ /new (user|group): name=/ || l ~ /passwd\[[0-9]+\].*password changed/ {
  emit("ALERT", "ACCOUNT CHANGE: " substr(l, length($1) + 2)); next
}
# ---------------- cron / units
l ~ /(CRON|crond|crontab)\[[0-9]+\].*(REPLACE|BEGIN EDIT|END EDIT|DELETE)/ { emit("ALERT", "CRONTAB EDITED: " substr(l, length($1) + 2)); next }
l ~ /(CRON|crond)\[[0-9]+\].*CMD/ { if (l ~ bad) emit("ALERT", "CRON RAN SUSPICIOUS: " substr(l, index(l, "CMD"))); next }
l ~ /systemd\[1\]: (Reloading|Reloaded)/ { emit("WARN", "systemd reloaded (unit files changed? run diff.sh)"); next }
l ~ /Created symlink .*(\.service|\.timer|\.socket|\.path)/ { emit("ALERT", "UNIT ENABLED: " substr(l, index(l, "Created symlink"))); next }
l ~ /systemd\[1\]: .*(Stopped|Failed to start|failed with result|Main process exited, code=killed)/ && l ~ keysvc { emit("ALERT", "KEY SERVICE: " substr(l, index(l, "systemd[1]:") + 12)); next }
l ~ /systemd\[1\]: Started .*/ && l !~ keysvc && l !~ /(Session|session-|user@|user-runtime|logrotate|man-db|apt|dnf|fwupd|motd|sysstat|update|Cleanup|Daily|PackageKit|snap)/ { emit("INFO", "started: " substr(l, index(l, "Started") + 8)) ; next }
# ---------------- kernel / selinux / audit
l ~ /avc: +denied/ { emit("WARN", "SELINUX DENIED: " grab(l, "\\{[^}]*\\}", 0) " comm=" grab(l, "comm=\"[^\"]*\"", 5) " " grab(l, "(name|path)=\"[^\"]*\"", 0)); next }
l ~ /segfault at/ { emit("WARN", "SEGFAULT: " substr(l, length($1) + 2)); next }
l ~ /type=EXECVE/ && l ~ bad { emit("ALERT", "AUDIT EXECVE: " substr(l, 1, 200)); next }
# ---------------- mail server abuse
l ~ /NOQUEUE: reject: RCPT.*Relay access denied/ { if (relay++ % 10 == 0) emit("WARN", "RELAY ATTEMPTS blocked (x" relay ") latest from " srcip(l)); next }
l ~ /postfix\/smtp\[[0-9]+\].*status=sent/ && l !~ /relay=(local|dovecot|private|127\.0\.0\.1|\[127|lmtp)/ { emit("WARN", "MAIL SENT OUT: " grab(l, "to=<[^>]*>", 0) " " grab(l, "relay=[^ ,]*", 0)); next }
# ---------------- web access logs
l ~ /(GET|POST|PUT|HEAD|DELETE|OPTIONS) / {
  if (l ~ /(cmd=|exec=|command=|\.\.\/|%2e%2e|union(%20|\+| )+select|<script|%3cscript|\/etc\/passwd|base64|eval\(|whoami|wget%20|curl%20|\/bin\/(ba)?sh|phpinfo|\.env|wp-login|\/\.git\/)/) emit("ALERT", "WEB ATTACK-LIKE: " substr(l, 1, 220))
  else if (l ~ /"POST [^"]*\.(php|phtml|cgi|pl|py|jsp)[^"]*" (200|500)/ && l !~ /roundcube|\/\?_task=|index\.php\?_task/) emit("WARN", "WEB POST to script: " substr(l, 1, 200))
  else if (l ~ /(sqlmap|nikto|gobuster|dirbuster|ffuf|feroxbuster|wfuzz|nuclei|masscan|Nmap Scripting)/) { if (scan++ % 25 == 0) emit("WARN", "SCANNER UA seen: " substr(l, 1, 160)) }
  next
}
# ---------------- generic bad stuff anywhere
l ~ bad { emit("ALERT", "SUSPICIOUS: " substr(l, 1, 220)); next }
'
