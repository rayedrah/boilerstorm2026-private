#!/usr/bin/env bash
# Takes a fresh snapshot and prints ONLY what changed since the baseline.
# "+ ADDED" lines are what Red Team usually leaves behind. Screenshot them.
#   sudo bash diff.sh                      # compare to /root/bs/baseline
#   sudo bash diff.sh /root/bs/snap/X      # compare to a specific snapshot
#   sudo bash diff.sh --loop 120           # repeat every 120 s

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
. "$DIR/_lib.sh"
need_root

AGAINST="$BS_ROOT/baseline"; LOOP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --loop) LOOP="${2:-120}"; shift ;;
    *) AGAINST="$1" ;;
  esac
  shift
done

# Changes here are almost always worth a look
HOT=" users uid0 shadow-state priv-groups sudoers ssh-keys sshd-config listening services timers unit-files cron at-jobs preload pam pam-modules shell-init suid capabilities kmods tmp-files pkg-hooks configs webfiles nft ufw firewalld selinux "

run_diff() {
  if [ ! -d "$AGAINST" ]; then log ALERT "No baseline at $AGAINST. Run baseline.sh first."; return; fi
  bash "$DIR/baseline.sh" --quiet >/dev/null
  local snap; snap="$(cat "$BS_ROOT/.last_snap")"
  BS_LOG="$BS_ROOT/diff-$(filestamp).txt"
  log HEAD "Diff: $AGAINST  vs  $snap"
  local n=0 name lvl
  for f in "$snap"/*.sig; do
    name="$(basename "$f" .sig)"
    local old="$AGAINST/$name.sig"
    [ -f "$old" ] || old=/dev/null
    case "$HOT" in *" $name "*) lvl=ALERT ;; *) lvl=WARN ;; esac
    while IFS= read -r l; do log "$lvl" "[$name] + ADDED   $l"; n=$((n+1)); done < <(LC_ALL=C comm -13 "$old" "$f")
    while IFS= read -r l; do log WARN "[$name] - REMOVED $l"; n=$((n+1)); done < <(LC_ALL=C comm -23 "$old" "$f")
  done
  if [ "$n" -eq 0 ]; then log OK "No changes since baseline."; else log HEAD "$n change(s). Detail: $snap   Saved: $BS_LOG"; fi
  log INFO "processes/established/services-running are noisy; users, ssh-keys, cron, unit-files, sudoers, webfiles, pam are not."
}

if [ "$LOOP" -gt 0 ]; then
  while true; do run_diff; sleep "$LOOP"; done
else
  run_diff
fi
