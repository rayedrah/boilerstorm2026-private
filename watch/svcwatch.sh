#!/usr/bin/env bash
# Network / service watcher. Run it on cai-db01 or cai-mail01 in its own TTY (Alt+F2) or tmux pane.
# Every cycle it checks every line of targets.conf in parallel against the PUBLIC (10.100.N.x) and
# LAN (10.42.0.x) addresses and redraws a status board. State changes (UP->DOWN, page content changed,
# DNS answer changed) are logged with timestamps to /root/bs/svcwatch-*.txt for incident reports.
#
#   bash svcwatch.sh -n 7                       # team 7, default 60 s cycle
#   bash svcwatch.sh -n 7 -i 30 -c my.conf      # 30 s cycle, custom targets file
#   bash svcwatch.sh -n 7 --relearn             # forget remembered page/DNS fingerprints
#
# Notes:
# - If PUB.x fails but LAN.x works, suspect NAT/rules on cai-fw01 (or hairpin NAT from inside). Quotient is the truth.
# - This does NOT log in to anything and never tries to recognize the scoring engine (that is against the rules).
# - Bypasses the internet proxy for these internal checks (--noproxy).

DIR="$(cd "$(dirname "$0")" && pwd)"
TEAM=""; INTERVAL=60; CONF="$DIR/targets.conf"; RELEARN=0; TIMEOUT=4
while [ $# -gt 0 ]; do
  case "$1" in
    -n) TEAM="$2"; shift ;;
    -i) INTERVAL="$2"; shift ;;
    -c) CONF="$2"; shift ;;
    -t) TIMEOUT="$2"; shift ;;
    --relearn) RELEARN=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
  esac
  shift
done
if [ -z "$TEAM" ]; then read -r -p "Team number N (10.100.N.x): " TEAM; fi
[ -f "$CONF" ] || { echo "targets file not found: $CONF"; exit 1; }

ROOT="${BS_ROOT:-$HOME/bs}"; mkdir -p "$ROOT/svcwatch-state"
STATE="$ROOT/svcwatch-state"
[ "$RELEARN" -eq 1 ] && rm -f "$STATE"/*.fp
LOG="$ROOT/svcwatch-$(date +%Y%m%d-%H%M%S).txt"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
HOSTN="$(hostname 2>/dev/null)"

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; D=$'\e[90m'; C=$'\e[36m'; B=$'\e[1m'; O=$'\e[0m'; else R=; G=; Y=; D=; C=; B=; O=; fi
stamp() { date '+%Y-%m-%d %H:%M:%S'; }
logline() { printf '[%s] [%s] [%s] %s\n' "$(stamp)" "$HOSTN" "$1" "$2" >> "$LOG"; }

resolve_host() {
  case "$1" in
    PUB.*) echo "10.100.$TEAM.${1#PUB.}" ;;
    LAN.*) echo "10.42.0.${1#LAN.}" ;;
    *) echo "$1" ;;
  esac
}

tcp_open() { timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# Each check prints:  STATUS|detail|fingerprint   (STATUS = UP or DOWN)
check_one() {
  local host="$1" kind="$2" arg="$3" out code fp body ans
  case "$kind" in
    ping)
      if ping -c1 -W2 "$host" >/dev/null 2>&1; then echo "UP|icmp ok|"; else echo "DOWN|no icmp reply|"; fi ;;
    tcp)
      if tcp_open "$host" "$arg"; then echo "UP|port $arg open|"; else echo "DOWN|port $arg closed/filtered|"; fi ;;
    banner)
      out="$(timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$host/$arg; head -c 120 <&3" 2>/dev/null | tr -d '\r' | head -1)"
      if [ -n "$out" ]; then
        case "$out" in
          220*|'* OK'*|+OK*|SSH-*) echo "UP|${out:0:60}|" ;;
          *) echo "UP|odd banner: ${out:0:50}|" ;;
        esac
      elif tcp_open "$host" "$arg"; then echo "UP|port $arg open, no banner|"
      else echo "DOWN|port $arg closed/filtered|"; fi ;;
    http|https)
      local path="${arg%%,*}" nohash=0
      case "$arg" in *,nohash) nohash=1 ;; esac
      body="$WORK/body.$$.$RANDOM"
      code="$(curl --noproxy '*' -sk -m "$TIMEOUT" -o "$body" -w '%{http_code}' "$kind://$host$path" 2>/dev/null)"
      if [ -z "$code" ] || [ "$code" = "000" ]; then echo "DOWN|no HTTP response|"; rm -f "$body"; return; fi
      # fingerprint ignores numbers and long tokens so dynamic pages (CSRF tokens, dates) do not flap
      fp="$(sed -E 's/[0-9a-fA-F]{16,}//g; s/[0-9]+//g' "$body" 2>/dev/null | sha256sum | cut -c1-12)"
      local size; size="$(wc -c < "$body")"; rm -f "$body"
      [ "$nohash" -eq 1 ] && fp=""
      case "$code" in
        2*|3*|401) echo "UP|HTTP $code, ${size}B|$fp" ;;
        *) echo "DOWN|HTTP $code, ${size}B|$fp" ;;
      esac ;;
    dns)
      if command -v dig >/dev/null 2>&1; then ans="$(dig +short +time=2 +tries=1 @"$host" "$arg" A 2>/dev/null | grep -E '^[0-9.]+$' | sort | tr '\n' ' ')"
      elif command -v host >/dev/null 2>&1; then ans="$(timeout "$TIMEOUT" host -t A "$arg" "$host" 2>/dev/null | grep -oE 'has address [0-9.]+' | awk '{print $3}' | sort | tr '\n' ' ')"
      elif command -v nslookup >/dev/null 2>&1; then ans="$(timeout "$TIMEOUT" nslookup "$arg" "$host" 2>/dev/null | awk '/^Name:/{f=1} f&&/^Address/{print $2}' | sort | tr '\n' ' ')"
      else echo "DOWN|no dig/host/nslookup installed|"; return; fi
      if [ -n "$ans" ]; then echo "UP|$arg -> $ans|$ans"; else echo "DOWN|$arg: no answer|"; fi ;;
    *) echo "DOWN|unknown check $kind|" ;;
  esac
}

declare -A STATUS SINCE EVERUP
mapfile -t LINES < <(grep -vE '^[[:space:]]*(#|$)' "$CONF")
logline HEAD "svcwatch started: team $TEAM, ${#LINES[@]} checks, every ${INTERVAL}s, conf $CONF"

while true; do
  cycle_start=$(date +%s)
  i=0
  for line in "${LINES[@]}"; do
    read -r name hostspec kind arg <<< "$line"
    host="$(resolve_host "$hostspec")"
    ( check_one "$host" "$kind" "$arg" > "$WORK/r.$i" ) &
    i=$((i+1))
  done
  wait

  board="$WORK/board"; : > "$board"
  up=0; down=0; i=0
  for line in "${LINES[@]}"; do
    read -r name hostspec kind arg <<< "$line"
    host="$(resolve_host "$hostspec")"
    IFS='|' read -r st detail fp < "$WORK/r.$i"; i=$((i+1))
    shown="$st"; color="$G"

    # fingerprint compare (page content / DNS answer)
    if [ "$st" = "UP" ] && [ -n "$fp" ]; then
      fpf="$STATE/$name.fp"
      if [ ! -f "$fpf" ]; then echo "$fp" > "$fpf"; logline INFO "$name learned fingerprint: $fp"
      elif [ "$(cat "$fpf")" != "$fp" ]; then
        shown="CHANGED"; color="$Y"; detail="$detail (was $(cat "$fpf"))"
        [ "${STATUS[$name]}" != "CHANGED" ] && logline ALERT "$name $host $kind $arg CONTENT/ANSWER CHANGED: $detail  (defaced? DNS tampered? if intended: --relearn)"
      fi
    fi

    if [ "$st" = "UP" ]; then EVERUP[$name]=1; up=$((up+1)); else down=$((down+1)); fi
    if [ "$st" = "DOWN" ]; then
      if [ -z "${EVERUP[$name]}" ]; then shown="NEVER-UP"; color="$D"; else color="$R"; fi
    fi

    prev="${STATUS[$name]}"
    if [ "$prev" != "$shown" ]; then
      SINCE[$name]="$(date '+%H:%M:%S')"
      if [ -n "$prev" ]; then
        lvl=INFO; [ "$shown" = "DOWN" ] && lvl=ALERT; [ "$shown" = "UP" ] && lvl=OK
        logline "$lvl" "$name $host $kind $arg: $prev -> $shown ($detail)"
      else
        logline INFO "$name $host $kind $arg: $shown ($detail)"
      fi
    fi
    STATUS[$name]="$shown"
    printf '%s%-16s %-15s %-7s %-6s %-9s %-8s %s%s\n' "$color" "$name" "$host" "$kind" "${arg%%,*}" "$shown" "${SINCE[$name]}" "${detail:0:60}" "$O" >> "$board"
  done

  clear 2>/dev/null || printf '\n\n'
  printf '%s%sSVCWATCH team %s  %s  on %s   up:%s  down:%s   next in %ss   log: %s%s\n' "$B" "$C" "$TEAM" "$(stamp)" "$HOSTN" "$up" "$down" "$INTERVAL" "$LOG" "$O"
  printf '%s%-16s %-15s %-7s %-6s %-9s %-8s %s%s\n' "$B" NAME HOST CHECK ARG STATUS SINCE DETAIL "$O"
  cat "$board"
  echo
  echo "${D}PUB down + LAN up => firewall/NAT. CHANGED => compare page/DNS with backup. NEVER-UP => maybe not a real service; edit targets.conf.${O}"
  echo "${D}Recent events:${O}"
  grep -E '\[(ALERT|OK)\]' "$LOG" | tail -6

  elapsed=$(( $(date +%s) - cycle_start ))
  sleep $(( INTERVAL > elapsed ? INTERVAL - elapsed : 1 ))
done
