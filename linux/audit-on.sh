#!/usr/bin/env bash
# Turn on the logging you need for detection AND evidence (also supports a legal hold inject).
# - journald persistent storage (logs survive reboot) and bigger size
# - auditd rules: every command executed + watches on accounts, sudoers, ssh, cron, systemd, PAM, preload
# Safe for scoring: no service or access changes.
#   sudo bash audit-on.sh
#   sudo bash audit-on.sh --install     # install auditd through the proxy if missing

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root
BS_LOG="$BS_ROOT/audit-on-$(filestamp).txt"

# journald
mkdir -p /etc/systemd/journald.conf.d /var/log/journal
cat > /etc/systemd/journald.conf.d/90-bs.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=2G
EOF
systemctl restart systemd-journald && log OK 'journald: persistent, 2G'

if ! have auditctl; then
  if [ "${1:-}" = "--install" ]; then
    if have apt-get; then apt-get install -y auditd >/dev/null 2>&1; else dnf install -y audit >/dev/null 2>&1; fi
  else
    log WARN 'auditd not installed. Re-run with --install (uses the proxy) or skip; logwatch.sh still works with the journal.'
  fi
fi

if have auditctl; then
  mkdir -p /etc/audit/rules.d
  cat > /etc/audit/rules.d/90-bs.rules <<'EOF'
## BoilerStorm detection rules (search: ausearch -k <key> -i)
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k sshkeys
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/lib/systemd/system/ -p wa -k systemd
-w /etc/pam.d/ -p wa -k pam
-w /etc/ld.so.preload -p wa -k preload
-w /etc/hosts -p wa -k hosts
-w /usr/bin/ -p a -k binperm
-w /usr/sbin/ -p a -k binperm
-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k usercmd
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
EOF
  systemctl enable --now auditd >/dev/null 2>&1
  if have augenrules; then augenrules --load >/dev/null 2>&1; else auditctl -R /etc/audit/rules.d/90-bs.rules >/dev/null 2>&1; fi
  log OK "auditd rules loaded: $(auditctl -l 2>/dev/null | wc -l) rules (ausearch -k rootcmd -ts recent -i)"
fi

# keep bash history from every root shell, with timestamps
cat > /etc/profile.d/zz-bs-history.sh <<'EOF'
export HISTTIMEFORMAT='%F %T '
export HISTSIZE=100000
export HISTFILESIZE=100000
shopt -s histappend 2>/dev/null
PROMPT_COMMAND="history -a${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
EOF
log OK 'bash history: timestamps + append on every prompt (new shells)'
log HEAD "Done. Screenshot as evidence of logging/retention. Log: $BS_LOG"
