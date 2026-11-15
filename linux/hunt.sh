#!/usr/bin/env bash
# Persistence / backdoor / misconfig hunt for cai-db01 and cai-mail01. Read-only.
# Works without a baseline: the right first thing to run at 10:00.
#   sudo bash hunt.sh            # "recent" = last 2 days
#   sudo bash hunt.sh 1          # "recent" = last 1 day
#   sudo bash hunt.sh 2 --verify # also verify installed packages (rpm -Va / dpkg --verify), slow

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root

DAYS="${1:-2}"; VERIFY=0
for a in "$@"; do [ "$a" = "--verify" ] && VERIFY=1; done
BS_LOG="$BS_ROOT/hunt-$(filestamp).txt"
HITS=0
hit()  { HITS=$((HITS+1)); log "${2:-ALERT}" "$1"; }
head_() { log HEAD "==== $1 ===="; }

log HEAD "Hunt on $HOST_SHORT ($(os_id)), recent = last $DAYS day(s)"

# ---------------------------------------------------------------- accounts
head_ 'Accounts'
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do hit "UID 0 account that is not root: $u"; done
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do hit "Account with EMPTY password: $u"; done
awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1" uid="$3" shell="$7" home="$6}' /etc/passwd | while read -r l; do log INFO "login user: $l"; done
awk -F: '$3<1000 && $3!=0 && $7 ~ /(bash|sh|zsh)$/ {print $1" uid="$3" shell="$7}' /etc/passwd | while read -r l; do hit "System account with a login shell: $l" WARN; done
for g in sudo wheel adm docker lxd disk shadow; do
  m="$(getent group "$g" | cut -d: -f4)"; [ -n "$m" ] && log INFO "group $g: $m"
done
for g in docker lxd disk; do
  m="$(getent group "$g" | cut -d: -f4)"; [ -n "$m" ] && hit "Members of '$g' can get root: $m" WARN
done
find /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d -newermt "$DAYS days ago" 2>/dev/null | while read -r f; do hit "Recently modified: $f" WARN; done

head_ 'sudo'
grep -Hn -v '^[[:space:]]*#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E 'NOPASSWD|ALL[[:space:]]*=[[:space:]]*\(ALL' | while read -r l; do
  case "$l" in *'%sudo'*|*'%wheel'*|*'%admin'*|*'root'*ALL*) log INFO "sudo: $l" ;; *) hit "sudo rule: $l" ;; esac
done
grep -HnE '(vim|vi|less|more|find|awk|python|perl|bash|sh|tar|zip|nmap|tee|cp|mv|chmod|chown|env|systemctl|journalctl|docker)( |$|,)' /etc/sudoers.d/* 2>/dev/null | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' | while read -r l; do hit "sudo allows a shell-escape-capable binary: $l" WARN; done

# ---------------------------------------------------------------- ssh
head_ 'SSH'
find / -xdev \( -name authorized_keys -o -name authorized_keys2 \) -type f 2>/dev/null | while read -r f; do
  n="$(grep -cv '^[[:space:]]*\(#\|$\)' "$f" 2>/dev/null)"
  owner="$(stat -c %U "$f")"; mt="$(stat -c %y "$f" | cut -d. -f1)"
  hit "authorized_keys: $f owner=$owner keys=$n modified=$mt" WARN
  grep -nE '(command=|from=|environment=|no-pty)' "$f" 2>/dev/null | while read -r l; do hit "  key option in $f: ${l:0:120}"; done
done
SSHD="$(sshd -T 2>/dev/null)"
if [ -n "$SSHD" ]; then
  echo "$SSHD" | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|permitemptypasswords|allowusers|allowgroups|port|listenaddress|usepam|gatewayports|permittunnel|allowtcpforwarding) ' | while read -r l; do log INFO "sshd: $l"; done
  echo "$SSHD" | grep -qE '^permitrootlogin yes' && hit 'sshd PermitRootLogin yes' WARN
  echo "$SSHD" | grep -qE '^permitemptypasswords yes' && hit 'sshd PermitEmptyPasswords yes'
  echo "$SSHD" | grep -E '^authorizedkeysfile ' | grep -vqE '^authorizedkeysfile \.ssh/authorized_keys( \.ssh/authorized_keys2)?$' && hit "sshd custom AuthorizedKeysFile: $(echo "$SSHD" | grep '^authorizedkeysfile ')"
  echo "$SSHD" | grep -E '^authorizedkeyscommand ' | grep -vq ' none$' && hit "sshd AuthorizedKeysCommand set: $(echo "$SSHD" | grep '^authorizedkeyscommand ')"
fi

# ---------------------------------------------------------------- cron / systemd / at
head_ 'Scheduled execution'
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
  [ -f "$f" ] || continue
  grep -nEi "$BAD_CMD_RE" "$f" 2>/dev/null | while read -r l; do hit "cron $f: $l"; done
  if [ -n "$(find "$f" -newermt "$DAYS days ago" 2>/dev/null)" ]; then hit "Recently modified cron file: $f" WARN; fi
done
for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do
  [ -f "$f" ] && log WARN "user crontab: $f -> $(grep -v '^#' "$f" | grep -v '^$' | head -3 | tr '\n' ';')"
done
if have atq; then atq 2>/dev/null | while read -r l; do hit "at job: $l" WARN; done; fi
if have systemctl; then
  for f in $(find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/systemd/user /root/.config/systemd /home/*/.config/systemd -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -newermt "$DAYS days ago" 2>/dev/null); do
    hit "Recently created/modified unit: $f -> $(grep -E '^Exec' "$f" | head -2 | tr '\n' ' ')" WARN
  done
  grep -rlE "$BAD_CMD_RE|Exec[A-Za-z]*=.*(/tmp/|/dev/shm/|/var/tmp/|/home/)" /etc/systemd /usr/lib/systemd/system /lib/systemd/system 2>/dev/null | while read -r f; do
    hit "Suspicious ExecStart in $f: $(grep -E '^Exec' "$f" | head -1)"
  done
  systemctl list-timers --all --no-pager 2>/dev/null | sed 1d | head -40 | while read -r l; do log INFO "timer: $l"; done
fi

# ---------------------------------------------------------------- loader / PAM / shells
head_ 'Loader, PAM, shell startup'
if [ -s /etc/ld.so.preload ]; then hit "/etc/ld.so.preload is NOT empty: $(tr '\n' ' ' < /etc/ld.so.preload) (userland rootkit)"; fi
grep -rnE 'pam_exec|pam_script|pam_permit\.so' /etc/pam.d 2>/dev/null | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' | while read -r l; do
  case "$l" in
    *pam_permit.so*) case "$l" in *auth*sufficient*pam_permit*) hit "PAM auth 'sufficient pam_permit' = ANY password works: $l" ;; *) log INFO "pam: $l" ;; esac ;;
    *) hit "PAM exec/script hook: $l" ;;
  esac
done
for d in /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib64/security /usr/lib64/security; do
  [ -d "$d" ] && find "$d" -name '*.so' -newermt "$DAYS days ago" 2>/dev/null | while read -r f; do hit "Recently changed PAM module: $f"; done
done
for f in /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /etc/update-motd.d/* /etc/rc.local; do
  [ -f "$f" ] || continue
  grep -nEi "$BAD_CMD_RE|alias (sudo|su|ps|ss|netstat|who|w|last|lsof|top)=" "$f" 2>/dev/null | while read -r l; do hit "shell init $f: $l"; done
done

# ---------------------------------------------------------------- binaries
head_ 'Binaries'
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | grep -vE '^/(usr/)?(s?bin|lib|lib64|libexec)/' | while read -r f; do hit "SUID/SGID outside system dirs: $f"; done
for b in find vim vi nano less more python3 python perl bash sh dash env awk tar cp tee nmap; do
  p="$(command -v "$b" 2>/dev/null)"; [ -n "$p" ] || continue
  p="$(readlink -f "$p")"
  [ -u "$p" ] && hit "SUID set on $p (GTFOBins root shell)"
done
if have getcap; then getcap -r /usr /bin /sbin /opt /home /tmp 2>/dev/null | grep -E 'cap_setuid|cap_sys_admin|cap_dac_override|cap_sys_ptrace' | while read -r l; do hit "dangerous capability: $l"; done; fi
find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -xdev -type f -newermt "$DAYS days ago" 2>/dev/null | head -50 | while read -r f; do hit "Recently changed binary: $f" WARN; done
find /tmp /var/tmp /dev/shm -xdev -type f \( -perm -u+x -o -name '.*' \) 2>/dev/null | grep -v "^$BS_ROOT" | while read -r f; do hit "Executable or hidden file in temp: $f ($(stat -c '%U %y' "$f" | cut -d. -f1))"; done

# ---------------------------------------------------------------- processes + network
head_ 'Processes'
for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  exe="$(readlink "$p/exe" 2>/dev/null)" || continue
  cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
  case "$exe" in *' (deleted)') hit "Process running from DELETED binary: pid $pid $exe $cmd" ;; /tmp/*|/dev/shm/*|/var/tmp/*) hit "Process running from temp: pid $pid $exe $cmd" ;; esac
  if echo "$cmd" | grep -qE "$BAD_CMD_RE"; then hit "Suspicious command line: pid $pid user $(stat -c %U "$p") : ${cmd:0:200}"; fi
done
head_ 'Network'
if have ss; then
  ss -H -tulpn 2>/dev/null | awk '{print $1, $5, $7}' | while read -r l; do log INFO "LISTEN $l"; done
  ss -H -tulpn 2>/dev/null | grep -E '"(bash|sh|dash|python[0-9.]*|perl|nc|ncat|socat|php|ruby)"' | while read -r l; do hit "Shell/interpreter LISTENING: $l"; done
  ss -H -tnp state established 2>/dev/null | grep -E '"(bash|sh|dash|python[0-9.]*|perl|nc|ncat|socat|php|ruby)"' | while read -r l; do hit "Shell/interpreter with ESTABLISHED connection (reverse shell?): $l"; done
  ss -H -tnp state established 2>/dev/null | awk '{print $4, "->", $5, $6}' | while read -r l; do log INFO "ESTAB $l"; done
fi

# ---------------------------------------------------------------- web
head_ 'Web roots (webshells, recent changes)'
for d in $WEB_DIRS; do
  [ -d "$d" ] || continue
  find "$d" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.inc' -o -name '.htaccess' -o -name '*.cgi' -o -name '*.jsp' \) -size -2M 2>/dev/null |
  while read -r f; do
    m="$(grep -nEo ".{0,40}$WEBSHELL_RE.{0,40}" "$f" 2>/dev/null | head -1)"
    [ -n "$m" ] && hit "webshell-like code: $f :: ${m:0:140}" WARN
  done
  find "$d" -xdev -type f -newermt "$DAYS days ago" 2>/dev/null | grep -vE '/(cache|logs?|temp|sessions?)/' | head -40 | while read -r f; do hit "Recently modified in $d: $f" WARN; done
  find "$d" -xdev -type d -perm -0002 2>/dev/null | head -20 | while read -r f; do hit "World-writable dir in web tree: $f" WARN; done
done

# ---------------------------------------------------------------- services specific
head_ 'Databases / Redis / IRC / Mail / FTP'
if have redis-cli || [ -f /etc/redis/redis.conf ] || [ -f /etc/redis.conf ] || [ -d /etc/valkey ]; then
  RC="$(ls /etc/redis/redis.conf /etc/redis.conf /etc/valkey/valkey.conf 2>/dev/null | head -1)"
  if [ -n "$RC" ]; then
    grep -E '^(bind|protected-mode|requirepass|port|rename-command|enable-debug-command|aclfile|user )' "$RC" | while read -r l; do log INFO "redis: $l"; done
    grep -qE '^requirepass' "$RC" || [ -n "$(grep -E '^(user|aclfile)' "$RC")" ] || hit "Redis has NO requirepass/ACL in $RC (unauth write-to-disk = cron/ssh key backdoor)"
    grep -qE '^protected-mode no' "$RC" && hit "Redis protected-mode no"
  fi
  if have redis-cli; then
    out="$(timeout 3 redis-cli -h 127.0.0.1 CONFIG GET dir 2>&1 | tr '\n' ' ')"
    case "$out" in *NOAUTH*) log OK 'redis requires auth (NOAUTH)';; *dir*) hit "redis answers CONFIG without auth: $out" ;; esac
  fi
fi
if have mysql || have mariadb; then
  M="$(command -v mariadb || command -v mysql)"
  q="$(timeout 5 "$M" -NBe "SELECT CONCAT(user,'@',host,' plugin=',plugin) FROM mysql.user" 2>&1)"
  if echo "$q" | grep -q 'ERROR'; then log WARN "mysql: cannot query as root via socket ($q)"; else
    echo "$q" | while read -r l; do case "$l" in *'@%'*) hit "MySQL user reachable from ANY host: $l" WARN ;; *) log INFO "mysql user: $l" ;; esac; done
    timeout 5 "$M" -NBe "SELECT CONCAT(grantee,' ',privilege_type) FROM information_schema.user_privileges WHERE privilege_type IN ('SUPER','FILE','GRANT OPTION','CREATE USER','SHUTDOWN')" 2>/dev/null | sort -u | while read -r l; do log WARN "mysql priv: $l"; done
    timeout 5 "$M" -NBe "SHOW VARIABLES WHERE Variable_name IN ('bind_address','secure_file_priv','local_infile','skip_networking','port','plugin_dir')" 2>/dev/null | while read -r l; do log INFO "mysql var: $l"; done
    timeout 5 "$M" -NBe "SELECT name,dl FROM mysql.func" 2>/dev/null | while read -r l; do hit "MySQL UDF installed (code exec backdoor?): $l"; done
  fi
fi
if have psql && id postgres >/dev/null 2>&1; then
  su - postgres -c "psql -Atc \"SELECT rolname||' super='||rolsuper||' login='||rolcanlogin FROM pg_roles WHERE rolname !~ '^pg_'\"" 2>/dev/null | while read -r l; do case "$l" in *'super=t'*) log WARN "postgres role: $l" ;; *) log INFO "postgres role: $l" ;; esac; done
  HBA="$(su - postgres -c "psql -Atc 'SHOW hba_file'" 2>/dev/null)"
  [ -f "$HBA" ] && grep -nE '^[^#].*(trust|0\.0\.0\.0/0|::/0|all[[:space:]]+all[[:space:]]+all)' "$HBA" | while read -r l; do hit "pg_hba.conf permissive: $l" WARN; done
  su - postgres -c "psql -Atc 'SHOW listen_addresses'" 2>/dev/null | while read -r l; do log INFO "postgres listen_addresses=$l"; done
fi
for c in /etc/inspircd/inspircd.conf /etc/unrealircd/unrealircd.conf /etc/ngircd/ngircd.conf /etc/ngircd.conf /etc/ergo/ircd.yaml /etc/ircd/ircd.conf; do
  [ -f "$c" ] && { log INFO "IRC config: $c"; grep -niE 'oper|password|pass ' "$c" | grep -v '^\s*#' | head -15 | while read -r l; do log WARN "irc: $l"; done; }
done
if have postconf; then
  mn="$(postconf -h mynetworks 2>/dev/null)"; log INFO "postfix mynetworks = $mn"
  case "$mn" in *0.0.0.0/0*|*'::/0'*) hit "Postfix mynetworks allows everyone: OPEN RELAY" ;; esac
  log INFO "postfix smtpd_relay_restrictions = $(postconf -h smtpd_relay_restrictions 2>/dev/null)"
  log INFO "postfix relayhost = $(postconf -h relayhost 2>/dev/null)   always_bcc = $(postconf -h always_bcc 2>/dev/null)"
  [ -n "$(postconf -h always_bcc 2>/dev/null)" ] && hit "Postfix always_bcc is set (all mail copied to: $(postconf -h always_bcc))"
  for k in sender_bcc_maps recipient_bcc_maps; do v="$(postconf -h $k 2>/dev/null)"; [ -n "$v" ] && hit "Postfix $k = $v (mail copying)" WARN; done
fi
if have doveconf; then
  doveconf -n 2>/dev/null | grep -E '^(auth_mechanisms|disable_plaintext_auth|ssl |passdb|userdb|  driver|  args|auth_master)' | while read -r l; do log INFO "dovecot: $l"; done
  doveconf -n 2>/dev/null | grep -qE 'driver = static|nopassword' && hit 'Dovecot passdb static/nopassword (auth bypass?)'
  doveconf -n 2>/dev/null | grep -qE 'auth_master_user_separator|master = yes' && hit 'Dovecot MASTER user configured (login as anyone)' WARN
fi
find / -xdev \( -name '.forward' -o -name '*.sieve' -o -name '.dovecot.sieve' \) -type f 2>/dev/null | head -30 | while read -r f; do
  grep -qiE 'redirect|forward|^[^#]*@' "$f" && hit "Mail forwarding rule: $f :: $(grep -iE 'redirect|@' "$f" | head -1)" WARN
done
for rc in /usr/share/roundcubemail /var/www/roundcube /var/www/html/roundcube /var/lib/roundcube; do
  [ -d "$rc" ] || continue
  v="$(grep -hoE "RCMAIL_VERSION'?, *'[0-9.]+" "$rc"/program/include/iniset.php "$rc"/index.php 2>/dev/null | grep -oE '[0-9.]+$' | head -1)"
  log WARN "Roundcube at $rc version ${v:-unknown}: look up CVEs for this version (search engine in the env is allowed)"
  [ -d "$rc/installer" ] && hit "Roundcube installer/ directory still present: $rc/installer"
done
for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
  [ -f "$f" ] && grep -E '^(anonymous_enable|anon_upload_enable|write_enable|chroot_local_user|anon_mkdir_write_enable)' "$f" | while read -r l; do case "$l" in anonymous_enable=YES|anon_upload_enable=YES) hit "vsftpd $l" ;; *) log INFO "vsftpd $l" ;; esac; done
done

# ---------------------------------------------------------------- security controls
head_ 'Security controls'
have getenforce && { s="$(getenforce)"; [ "$s" = "Enforcing" ] && log OK "SELinux $s" || hit "SELinux is $s (should be Enforcing on Rocky)" WARN; }
have systemctl && for s in auditd rsyslog systemd-journald splunk SplunkForwarder; do
  st="$(systemctl is-active "$s" 2>/dev/null)"; [ "$st" = "unknown" ] || [ -z "$st" ] || log INFO "service $s: $st"
done
journalctl --list-boots --no-pager 2>/dev/null | tail -3 | while read -r l; do log INFO "boot: $l"; done
for f in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog /var/log/maillog; do
  [ -f "$f" ] && [ ! -s "$f" ] && hit "Log file is EMPTY: $f (cleared?)" WARN
done
[ -L /root/.bash_history ] && hit "/root/.bash_history is a symlink ($(readlink /root/.bash_history)) (history hiding)"

if [ "$VERIFY" -eq 1 ]; then
  head_ 'Package integrity (changed files owned by packages)'
  if have rpm; then rpm -Va 2>/dev/null | grep -E '^..5' | grep -vE ' c /' | head -60 | while read -r l; do hit "rpm verify: $l" WARN; done; fi
  if have dpkg; then dpkg --verify 2>/dev/null | grep -E '^..5' | grep -vE ' c /' | head -60 | while read -r l; do hit "dpkg verify: $l" WARN; done; fi
fi

HITS="$(grep -cE '\[(ALERT|WARN)\]' "$BS_LOG")"
log HEAD "$HITS finding(s) (ALERT+WARN). Saved: $BS_LOG"
log INFO 'Before removing anything: screenshot (clock visible), log it on the incident timeline, then close the entry point.'
