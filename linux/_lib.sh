#!/usr/bin/env bash
# Shared helpers, sourced by every script in this folder.
# Output root: /root/bs (stays on the box, never copy it out)
# Works on Ubuntu 26.04 (cai-db01) and Rocky Linux 10 (cai-mail01).

BS_ROOT="${BS_ROOT:-/root/bs}"
mkdir -p "$BS_ROOT" 2>/dev/null
chmod 700 "$BS_ROOT" 2>/dev/null

HOST_SHORT="$(hostname 2>/dev/null || cat /etc/hostname)"

if [ -t 1 ]; then
  C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'; C_CYN=$'\e[36m'; C_DIM=$'\e[90m'; C_OFF=$'\e[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_CYN=''; C_DIM=''; C_OFF=''
fi

stamp()     { date '+%Y-%m-%d %H:%M:%S'; }
filestamp() { date '+%Y%m%d-%H%M%S'; }

# log LEVEL "message" [logfile]
log() {
  local lvl="$1" msg="$2" file="${3:-$BS_LOG}" color
  case "$lvl" in
    ALERT) color="$C_RED" ;; WARN) color="$C_YEL" ;; OK) color="$C_GRN" ;; HEAD) color="$C_CYN" ;; *) color="$C_DIM" ;;
  esac
  local line
  line="[$(stamp)] [$HOST_SHORT] [$lvl] $msg"
  printf '%s%s%s\n' "$color" "$line" "$C_OFF"
  [ -n "$file" ] && printf '%s\n' "$line" >> "$file"
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash $0 $*" >&2
    exit 1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

os_id() { . /etc/os-release 2>/dev/null; echo "${ID:-unknown}"; }

# Auth log location differs per distro; journal is the fallback
auth_log() {
  if [ -f /var/log/auth.log ]; then echo /var/log/auth.log
  elif [ -f /var/log/secure ]; then echo /var/log/secure
  else echo ""; fi
}
mail_log() {
  if [ -f /var/log/maillog ]; then echo /var/log/maillog
  elif [ -f /var/log/mail.log ]; then echo /var/log/mail.log
  else echo ""; fi
}

# Directories that commonly hold web apps / Roundcube / the Deputy app
WEB_DIRS="/var/www /usr/share/roundcubemail /etc/roundcubemail /var/lib/roundcube /usr/share/nginx /srv /opt"

# Patterns that show up in reverse shells, droppers and webshells
BAD_CMD_RE='(/dev/tcp/|/dev/udp/|bash -i|sh -i|nc -e|ncat -e|nc .*-c |mkfifo|socat |python[0-9.]* -c|perl -e|ruby -e|php -r|base64 -d|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|curl .*-o /tmp|wget .*-O /tmp|chmod \+x /tmp|/dev/shm/|xmrig|chisel|ngrok|msfvenom|meterpreter)'
WEBSHELL_RE='(eval[[:space:]]*\(|assert[[:space:]]*\(|base64_decode|gzinflate|str_rot13|shell_exec|passthru|system[[:space:]]*\(|proc_open|popen[[:space:]]*\(|pcntl_exec|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(|preg_replace.*/e)'
