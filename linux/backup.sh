#!/usr/bin/env bash
# On-box backups BEFORE you harden anything. Nothing leaves the machine.
# /etc (whole), web roots, DB dumps (MySQL/MariaDB, PostgreSQL), Redis RDB, mail configs,
# firewall rules, crontabs, user list. Output: /root/bs/backup/<timestamp>/
#   sudo bash backup.sh
#   sudo bash backup.sh --no-db      # skip DB dumps (if they are huge)

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root
NODB=0; [ "${1:-}" = "--no-db" ] && NODB=1

DST="$BS_ROOT/backup/$(filestamp)"
mkdir -p "$DST"; chmod 700 "$BS_ROOT/backup"
BS_LOG="$DST/_backup-log.txt"
log HEAD "Backup -> $DST"

tar -C / -czpf "$DST/etc.tgz" etc 2>/dev/null && log OK "/etc archived (restore one file: tar -xzpf etc.tgz -C /tmp etc/path && compare)"

for d in $WEB_DIRS; do
  [ -d "$d" ] || continue
  sz=$(du -sm "$d" 2>/dev/null | awk '{print $1}')
  if [ "${sz:-0}" -lt 1500 ]; then
    name="$(echo "$d" | tr '/' '_' | sed 's/^_//')"
    tar -C / -czpf "$DST/web-$name.tgz" "${d#/}" 2>/dev/null && log OK "web dir $d archived (${sz} MB)"
  else
    log WARN "$d is ${sz} MB, skipped (archive the app subfolder by hand)"
  fi
done

# Deputy app guess: anything under /opt or /srv owned by a service user, and systemd units mentioning it
grep -rlE 'deputy|Deputy' /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system 2>/dev/null | while read -r f; do cp -a "$f" "$DST/" && log OK "unit saved: $f"; done

if [ "$NODB" -eq 0 ]; then
  if have mysqldump || have mariadb-dump; then
    D="$(command -v mariadb-dump || command -v mysqldump)"
    if timeout 300 "$D" --all-databases --single-transaction --routines --triggers --events > "$DST/mysql-all.sql" 2>"$DST/mysql-err.txt"; then
      gzip "$DST/mysql-all.sql"; log OK "MySQL/MariaDB dumped (restore: zcat mysql-all.sql.gz | mysql)"
    else log WARN "mysqldump failed: $(head -c 200 "$DST/mysql-err.txt") (try: $D -u root -p --all-databases > file)"; fi
  fi
  if have pg_dumpall && id postgres >/dev/null 2>&1; then
    if su - postgres -c "pg_dumpall" > "$DST/postgres-all.sql" 2>"$DST/pg-err.txt"; then
      gzip "$DST/postgres-all.sql"; log OK "PostgreSQL dumped (restore: zcat postgres-all.sql.gz | su - postgres -c psql)"
    else log WARN "pg_dumpall failed: $(head -c 200 "$DST/pg-err.txt")"; fi
  fi
  for rdb in /var/lib/redis/dump.rdb /var/lib/redis/*.rdb /var/lib/valkey/*.rdb; do
    [ -f "$rdb" ] && cp -a "$rdb" "$DST/" && log OK "Redis RDB copied: $rdb"
  done
fi

# mail
[ -d /var/spool/postfix ] && postconf -n > "$DST/postconf-n.txt" 2>/dev/null && log OK 'postconf -n saved'
have doveconf && doveconf -n > "$DST/doveconf-n.txt" 2>/dev/null && log OK 'doveconf -n saved'
log INFO 'Mailboxes are NOT copied (size). Legal hold: never delete mail. To snapshot one: tar the user maildir by hand.'

# firewall + cron + users
have nft && nft list ruleset > "$DST/nft-ruleset.nft" 2>/dev/null && log OK 'nft ruleset saved (restore: nft -f file, after nft flush ruleset)'
have firewall-cmd && firewall-cmd --list-all-zones > "$DST/firewalld-zones.txt" 2>/dev/null && log OK 'firewalld zones saved (real config is in etc.tgz: etc/firewalld)'
have ufw && ufw status numbered > "$DST/ufw.txt" 2>/dev/null
have iptables-save && iptables-save > "$DST/iptables.rules" 2>/dev/null
tar -C / -czpf "$DST/spool-cron.tgz" var/spool/cron 2>/dev/null
getent passwd > "$DST/passwd.txt"; getent group > "$DST/group.txt"
crontab -l > "$DST/root-crontab.txt" 2>/dev/null
ss -tulpn > "$DST/listening.txt" 2>/dev/null
systemctl list-unit-files --no-pager > "$DST/unit-files.txt" 2>/dev/null

chmod -R go-rwx "$DST"
log HEAD "Backup complete: $DST ($(du -sh "$DST" | awk '{print $1}'))"
