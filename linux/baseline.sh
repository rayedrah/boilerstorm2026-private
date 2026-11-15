#!/usr/bin/env bash
# Snapshot of everything Red Team likes to touch. Run once right at 10:00.
# First run also becomes the baseline (/root/bs/baseline). diff.sh compares against it.
#   sudo bash baseline.sh             # snapshot (becomes baseline if none exists)
#   sudo bash baseline.sh --promote   # make this snapshot the new baseline (after cleaning)
#   sudo bash baseline.sh --quiet     # used by diff.sh
# Each item is written as NAME.txt (detail for evidence) and NAME.sig (one line per item, for diff).

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root

PROMOTE=0; QUIET=0
for a in "$@"; do
  case "$a" in --promote) PROMOTE=1 ;; --quiet) QUIET=1 ;; esac
done

TS="$(filestamp)"
SNAP="$BS_ROOT/snap/$TS"
mkdir -p "$SNAP"
BS_LOG="$SNAP/_log.txt"

# save NAME  <- stdin becomes NAME.sig (sorted, unique, blank lines dropped)
save() {
  local name="$1"
  grep -v '^[[:space:]]*$' | LC_ALL=C sort -u > "$SNAP/$name.sig"
  [ "$QUIET" -eq 0 ] && log INFO "$(printf '%-16s %s items' "$name" "$(wc -l < "$SNAP/$name.sig")")"
}
# hash every file under the given paths: "path sha256"
hashes() {
  for p in "$@"; do
    [ -e "$p" ] || continue
    find "$p" -xdev -type f -size -20M 2>/dev/null -print0 | xargs -0 -r sha256sum 2>/dev/null | awk '{h=$1; $1=""; sub(/^ /,""); print $0" "h}'
  done
}

[ "$QUIET" -eq 0 ] && log HEAD "Snapshot -> $SNAP"

# ---------------------------------------------------------------- accounts
awk -F: '{print $1":"$3":"$4":"$6":"$7}' /etc/passwd | save users
awk -F: '$3==0{print $1}' /etc/passwd | save uid0
awk -F: '($2==""){print $1" EMPTY-PASSWORD"} ($2 !~ /^[!*]/ && $2!=""){print $1" has-password"}' /etc/shadow 2>/dev/null | save shadow-state
for g in sudo wheel adm admin root docker lxd disk shadow; do
  getent group "$g" | awk -F: -v g="$g" '{print g": "$4}'
done | save priv-groups
{ grep -hv '^[[:space:]]*#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/[[:space:]]\+/ /g'; } | save sudoers
cp -a /etc/sudoers /etc/sudoers.d "$SNAP/" 2>/dev/null

# ---------------------------------------------------------------- ssh keys
{
  getent passwd | awk -F: '{print $6}' | sort -u | while read -r home; do
    for f in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2; do
      [ -f "$f" ] || continue
      grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | awk -v f="$f" '{k=$0; n=split(k,a," "); print f" "a[1]" ..."substr(a[2],length(a[2])-15)" "a[n]}'
    done
  done
} | save ssh-keys
{ grep -hv '^[[:space:]]*#' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v '^[[:space:]]*$'; } | save sshd-config

# ---------------------------------------------------------------- network
if have ss; then
  ss -H -tulpn 2>/dev/null | awk '{proc=$7; gsub(/users:\(\("/,"",proc); gsub(/".*/,"",proc); print $1" "$5" "proc}' | save listening
  ss -H -tunp state established 2>/dev/null > "$SNAP/established.txt"
  awk '{proc=$NF; gsub(/users:\(\("/,"",proc); gsub(/".*/,"",proc); r=$(NF-1); sub(/:[0-9]+$/,"",r); print r" "proc}' "$SNAP/established.txt" | save established
fi

# ---------------------------------------------------------------- processes
ps -eo user=,pid=,ppid=,lstart=,args= > "$SNAP/processes.txt" 2>/dev/null
for p in /proc/[0-9]*; do
  exe="$(readlink "$p/exe" 2>/dev/null)" || continue
  u="$(stat -c %U "$p" 2>/dev/null)"
  echo "$u $exe"
done | sed 's/ (deleted)$/ (DELETED-BINARY)/' | save processes

# ---------------------------------------------------------------- services / timers / cron
if have systemctl; then
  systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1" "$2}' | save services
  systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | save services-running
  systemctl list-unit-files --type=timer --no-legend --no-pager 2>/dev/null | awk '{print $1" "$2}' | save timers
fi
hashes /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/systemd/user /root/.config/systemd | save unit-files
{
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
           /var/spool/cron/* /var/spool/cron/crontabs/* /etc/anacrontab; do
    [ -f "$f" ] || continue
    grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | sed "s|^|$f: |"
  done
} | save cron
if have atq; then atq 2>/dev/null | save at-jobs; fi

# ---------------------------------------------------------------- persistence hot spots
{ [ -f /etc/ld.so.preload ] && sed 's/^/ld.so.preload: /' /etc/ld.so.preload; cat /etc/ld.so.conf.d/*.conf 2>/dev/null; } | save preload
hashes /etc/pam.d | save pam
for d in /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib64/security /usr/lib64/security /lib/security; do
  [ -d "$d" ] && hashes "$d"
done | save pam-modules
hashes /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /etc/environment /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_logout \
       /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /etc/update-motd.d /etc/rc.local | save shell-init
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | save suid
if have getcap; then getcap -r /usr /bin /sbin /opt /home 2>/dev/null | save capabilities; fi
if have lsmod; then lsmod | awk 'NR>1{print $1}' | save kmods; fi
find /tmp /var/tmp /dev/shm -xdev -type f 2>/dev/null | grep -v "^$BS_ROOT" | save tmp-files
hashes /etc/apt/apt.conf.d /etc/dnf/plugins /etc/yum/pluginconf.d | save pkg-hooks

# ---------------------------------------------------------------- service configs
hashes /etc/ssh /etc/postfix /etc/dovecot /etc/mysql /etc/my.cnf /etc/my.cnf.d /etc/postgresql /var/lib/pgsql/data/pg_hba.conf \
       /etc/redis /etc/redis.conf /etc/valkey /etc/inspircd /etc/unrealircd /etc/ngircd /etc/ngircd.conf /etc/nginx /etc/httpd /etc/apache2 \
       /etc/php /etc/php.ini /etc/php-fpm.d /etc/sssd /etc/krb5.conf /etc/nsswitch.conf /etc/hosts /etc/resolv.conf /etc/vsftpd /etc/vsftpd.conf \
       /etc/samba /etc/roundcubemail /etc/sysconfig/selinux /etc/selinux/config | save configs

# ---------------------------------------------------------------- firewall
if have nft; then nft list ruleset 2>/dev/null > "$SNAP/nft-ruleset.txt"; grep -E '^\s*(chain|.*(accept|drop|reject))' "$SNAP/nft-ruleset.txt" | sed 's/^[[:space:]]*//' | save nft; fi
if have ufw; then ufw status verbose 2>/dev/null | save ufw; fi
if have firewall-cmd; then firewall-cmd --list-all-zones 2>/dev/null > "$SNAP/firewalld.txt"; grep -E '^(\S|  (services|ports|rich rules|sources|interfaces|target):)' "$SNAP/firewalld.txt" | save firewalld; fi
if have getenforce; then getenforce | save selinux; fi

# ---------------------------------------------------------------- web files
for d in $WEB_DIRS; do
  [ -d "$d" ] || continue
  find "$d" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.py' -o -name '*.js' -o -name '*.sh' -o -name '*.pl' -o -name '*.cgi' -o -name '*.html' -o -name '.htaccess' -o -name '*.inc' -o -name '*.jsp' \) \
    -size -5M 2>/dev/null -print0 | xargs -0 -r sha256sum 2>/dev/null | awk '{h=$1; $1=""; sub(/^ /,""); print $0" "h}'
done | save webfiles

# ---------------------------------------------------------------- promote
BASE="$BS_ROOT/baseline"
if [ "$PROMOTE" -eq 1 ] || [ ! -d "$BASE" ]; then
  [ -d "$BASE" ] && mv "$BASE" "$BS_ROOT/baseline-old-$TS"
  cp -a "$SNAP" "$BASE"
  log OK "Baseline set: $BASE (screenshot this moment: it is your 'before' evidence)"
fi
[ "$QUIET" -eq 0 ] && log OK "Done. Detail in $SNAP"
echo "$SNAP" > "$BS_ROOT/.last_snap"
