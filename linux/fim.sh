#!/usr/bin/env bash
# File integrity monitor. Run on its own TTY/tmux pane. Read-only.
# Watches persistence hot spots + web roots and prints ADDED / CHANGED / DELETED every N seconds.
#   sudo bash fim.sh            # every 30 s
#   sudo bash fim.sh 15 /opt/deputy /etc/inspircd     # interval + extra paths

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root
INTERVAL="${1:-30}"; shift 2>/dev/null
OUT="$BS_ROOT/fim-$(filestamp).txt"

PATHS="/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d /etc/ssh /etc/pam.d /etc/ld.so.preload /etc/ld.so.conf.d
/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system
/etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /etc/update-motd.d /etc/rc.local /root/.ssh /root/.bashrc /home
/usr/local/bin /usr/local/sbin /etc/postfix /etc/dovecot /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/sssd $WEB_DIRS $*"

state() {
  for p in $PATHS; do
    [ -e "$p" ] || continue
    find "$p" -xdev -type f -size -20M ! -path '*/cache/*' ! -path '*/sessions/*' ! -path '*/.cache/*' ! -path '*/Maildir/*' \
      ! -path '*/mdbox/*' ! -name '*.log' ! -name '*_history' ! -name '.viminfo' ! -name '.lesshst' -printf '%p|%s|%T@\n' 2>/dev/null
  done | LC_ALL=C sort
}

log HEAD "FIM on $HOST_SHORT, every ${INTERVAL}s" "$OUT"
A="$(mktemp)"; B="$(mktemp)"; trap 'rm -f "$A" "$B"' EXIT
state > "$A"
log OK "$(wc -l < "$A") files baselined" "$OUT"
while sleep "$INTERVAL"; do
  state > "$B"
  # path-only lists to classify
  LC_ALL=C join -t'|' -v2 <(cut -d'|' -f1 "$A") <(cut -d'|' -f1 "$B") | while read -r f; do
    log ALERT "ADDED   $f  ($(stat -c '%U %a' "$f" 2>/dev/null)) sha256:$(sha256sum "$f" 2>/dev/null | cut -c1-16)..." "$OUT"
  done
  LC_ALL=C join -t'|' -v1 <(cut -d'|' -f1 "$A") <(cut -d'|' -f1 "$B") | while read -r f; do log WARN "DELETED $f" "$OUT"; done
  LC_ALL=C comm -13 "$A" "$B" | cut -d'|' -f1 | while read -r f; do
    grep -q "^$(printf '%s' "$f" | sed 's/[][\.*^$/]/\\&/g')|" "$A" && log ALERT "CHANGED $f" "$OUT"
  done
  cp "$B" "$A"
done
