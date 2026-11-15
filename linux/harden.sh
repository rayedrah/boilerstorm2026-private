#!/usr/bin/env bash
# Interactive quick hardening for cai-db01 / cai-mail01.
# Every item shows the CURRENT state and asks y/N. Only changes that should not break scored
# services are offered. Before/after is logged to /root/bs/harden-*.txt for inject evidence.
#   sudo bash harden.sh
#   sudo bash harden.sh --report     # show state only, change nothing

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root
REPORT=0; [ "${1:-}" = "--report" ] && REPORT=1
BS_LOG="$BS_ROOT/harden-$(filestamp).txt"
Q="$BS_ROOT/quarantine/$(filestamp)"; mkdir -p "$Q"

ask() {  # ask "title" "current" "risk" ; returns 0 if user said yes
  log HEAD "$1  | current: $2"
  [ -n "$3" ] && log WARN "   risk: $3"
  [ "$REPORT" -eq 1 ] && return 1
  read -r -p "   apply? [y/N] " a
  case "$a" in y|Y|yes) return 0 ;; *) log INFO '   skipped'; return 1 ;; esac
}
done_() { log OK "   APPLIED: $1"; }

# 1 sshd drop-in (first value wins in OpenSSH, so 00- sorts before distro files)
if [ -d /etc/ssh/sshd_config.d ] && grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d' /etc/ssh/sshd_config; then
  cur="$(sshd -T 2>/dev/null | grep -E '^(permitrootlogin|permitemptypasswords|maxauthtries|x11forwarding|allowagentforwarding|permituserenvironment) ' | tr '\n' ' ')"
  if ask 'sshd: no root login, no empty passwords, MaxAuthTries 4, no X11/agent forwarding' "$cur" 'scoring logs in as a normal user over SSH, so root login off is fine. Keep your Guacamole console open while testing'; then
    cp -a /etc/ssh "$Q/ssh"
    cat > /etc/ssh/sshd_config.d/00-bs.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
X11Forwarding no
AllowAgentForwarding no
PermitUserEnvironment no
EOF
    if sshd -t 2>>"$BS_LOG"; then
      systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
      done_ "sshd drop-in /etc/ssh/sshd_config.d/00-bs.conf (undo: rm it + reload)"
    else
      rm -f /etc/ssh/sshd_config.d/00-bs.conf; log ALERT '   sshd -t failed, change removed'
    fi
  fi
fi

# 2 ld.so.preload
if [ -s /etc/ld.so.preload ]; then
  if ask 'Neutralize /etc/ld.so.preload (rootkit loader). File is moved to quarantine, not deleted' "$(tr '\n' ' ' < /etc/ld.so.preload)" 'screenshot it first for the incident report'; then
    mv /etc/ld.so.preload "$Q/ld.so.preload"; done_ "moved to $Q"
  fi
fi

# 3 extra UID 0 accounts
for u in $(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd); do
  if ask "Lock UID-0 backdoor account '$u' (password lock + nologin shell)" "$(getent passwd "$u")" 'screenshot first'; then
    cp -a /etc/passwd /etc/shadow "$Q/" ; usermod -L -s /usr/sbin/nologin "$u" 2>/dev/null || usermod -L -s /sbin/nologin "$u"; done_ "locked $u"
  fi
done

# 4 SUID on shell-capable binaries
for b in find vim vim.basic vi nano less more python3 python perl bash sh dash env awk gawk mawk tar cp tee nmap base64 xxd; do
  p="$(command -v "$b" 2>/dev/null)"; [ -n "$p" ] || continue; p="$(readlink -f "$p")"
  if [ -u "$p" ]; then
    if ask "Remove SUID bit from $p" "$(stat -c '%A %U' "$p")" ''; then chmod u-s "$p"; done_ "chmod u-s $p"; fi
  fi
done

# 5 Postfix open relay
if have postconf; then
  mn="$(postconf -h mynetworks)"
  case "$mn" in *0.0.0.0/0*|*'::/0'*)
    if ask 'Postfix: close open relay (mynetworks = localhost + LAN)' "$mn" 'internal servers on 10.42.0.0/24 can still relay; outside clients must SMTP-AUTH'; then
      cp -a /etc/postfix "$Q/postfix"; postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128 10.42.0.0/24'; postfix check && systemctl reload postfix; done_ 'mynetworks fixed'
    fi ;;
  esac
  ab="$(postconf -h always_bcc)"
  if [ -n "$ab" ] && ask 'Postfix: remove always_bcc (silent copy of ALL mail)' "$ab" 'screenshot first'; then
    cp -a /etc/postfix "$Q/postfix-bcc"; postconf -e 'always_bcc ='; systemctl reload postfix; done_ 'always_bcc cleared'
  fi
fi

# 6 SELinux (Rocky)
if have getenforce; then
  s="$(getenforce)"
  if [ "$s" != "Enforcing" ] && ask 'SELinux -> Enforcing (runtime; set /etc/selinux/config too)' "$s" 'if a service was only working because SELinux was off, it will break: watch Quotient, check: ausearch -m avc -ts recent'; then
    cp -a /etc/selinux/config "$Q/"; setenforce 1; sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; done_ 'SELinux enforcing'
  fi
fi

# 7 kernel knobs
cur="ptrace=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null) kptr=$(sysctl -n kernel.kptr_restrict 2>/dev/null) dmesg=$(sysctl -n kernel.dmesg_restrict 2>/dev/null) redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)"
if ask 'Kernel: ptrace_scope=1, kptr/dmesg restrict, no ICMP redirects, log martians' "$cur" ''; then
  cat > /etc/sysctl.d/90-bs.conf <<'EOF'
kernel.yama.ptrace_scope = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
  sysctl -p /etc/sysctl.d/90-bs.conf >/dev/null 2>&1; done_ '/etc/sysctl.d/90-bs.conf'
fi

# 8 cron restricted to root + listed users
if [ ! -f /etc/cron.allow ]; then
  if ask 'Create /etc/cron.allow with root only (other users cannot add crontabs)' 'no cron.allow' 'if an app user legitimately uses crontab, add it to the file'; then
    echo root > /etc/cron.allow; chmod 600 /etc/cron.allow; done_ '/etc/cron.allow'
  fi
fi

# 9 Redis: report only (changing auth breaks the app that uses it)
RC="$(ls /etc/redis/redis.conf /etc/redis.conf /etc/valkey/valkey.conf 2>/dev/null | head -1)"
if [ -n "$RC" ]; then
  log HEAD "Redis ($RC): $(grep -E '^(bind|protected-mode|requirepass|rename-command)' "$RC" | tr '\n' ' ')"
  log WARN '   NOT auto-changed: adding requirepass breaks every client (Deputy app, scoring). Do it by hand: set password in redis AND in the app config, restart both, then check Quotient. Safer first step: rename-command CONFIG "" and FLUSHALL "" (blocks the classic write-a-cron-file attack).'
fi

log HEAD "Done. Before/after log: $BS_LOG   Originals: $Q"
