#!/usr/bin/env bash
set -uo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CORE="$BASE/apache-autoban.sh"
CONFIG=/etc/apache-autoban/config.conf
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 1; }
export LC_ALL=C.UTF-8
source "$BASE/config.sh"
load_config || exit 1
load_lang() { case "$AUTOBAN_LANG" in ru|uk|en) ;; *) AUTOBAN_LANG=en;; esac; source "$BASE/lang/$AUTOBAN_LANG.lang"; }
load_lang
BLUE='' GREEN='' RED='' RESET=''
if [[ -t 1 && -n ${TERM:-} && $TERM != dumb && ! -v NO_COLOR ]]; then
    BLUE=$'\e[36m'; GREEN=$'\e[32m'; RED=$'\e[31m'; RESET=$'\e[0m'
fi
ask() { local val; read -r -p "$1${2:+ [$2]}: " val || return 1; printf '%s' "${val:-${2:-}}"; }
confirm() { local answer; read -r -p "$CONFIRM [y/N]: " answer && [[ "$answer" == y || "$answer" == Y ]]; }
report() { local rc=0; "$@" || rc=$?; local color=$GREEN; (( rc == 0 )) || color=$RED; printf '\n%s%s: %s%s\n' "$color" "$RESULT" "$rc" "$RESET"; }
run() { printf '%s%s%s\n' "$BLUE" "$BUSY" "$RESET"; report "$CORE" "$@"; }
edit() { touch "$1" && "${EDITOR:-vi}" "$1"; }
while true; do
 printf '\n%s========== RISH Apache AutoBan v1.0.0 ==========%s\n%s: %s | %s: %s %s\n\n' "$BLUE" "$RESET" "$THRESHOLD" "$MIN_REQUESTS" "$DURATION" "$BAN_TIME" "$SECONDS_LABEL"
 for ((i=1;i<=19;i++)); do key=M$i; printf '%s%2d.%s %s\n' "$GREEN" "$i" "$RESET" "${!key}"; done
 printf ' 0. %s\n\n' "$EXIT"
 read -r -p "$SELECT: " choice || exit 0
 case "$choice" in
 0) exit 0;;
 1) run --dry-run;;
 2) confirm && run --ban;;
 3) v=$(ask "$PERIOD" "$(LC_ALL=C date '+%d/%b/%Y')") && [[ -n "$v" ]] && run --dry-run "$v";;
 4) run --list;;
 5) report tail -100 "$BAN_LOG";;
 6) v=$(ask "$IP") && [[ -n "$v" ]] && confirm && run --unban "$v";;
 7) edit "$STOPWORDS";; 8) edit "$WHITELIST";;
 9) report firewall-cmd --state; report firewall-cmd --get-active-zones; report firewall-cmd --get-default-zone;;
 10) v=$(ask "$IP") && [[ -n "$v" ]] && confirm && run --manual-ban "$v";;
 11) v=$(ask "$IP") && [[ -n "$v" ]] && run --inspect "$v";;
 12|13|14) case "$choice" in 12) m=--top-ip;; 13) m=--top-sites;; *) m=--top-urls;; esac
    v=$(ask "$PERIOD_ANY" "")
    if [[ -n "$v" ]]; then run "$m" "$v"; else run "$m"; fi;;
 15) v=$(ask "$THRESHOLD" "$MIN_REQUESTS") && if [[ "$v" =~ ^[1-9][0-9]{0,5}$ ]] && setting MIN_REQUESTS "$v"; then export MIN_REQUESTS="$v"; else echo "$INVALID"; fi;;
 16) confirm && run --clear-bans;;
 17) printf '1. Русский\n2. Українська\n3. English\n'; read -r -p "$SELECT: " v || exit 0; case "$v" in 1) v=ru;; 2) v=uk;; 3) v=en;; *) echo "$INVALID"; continue;; esac; if setting AUTOBAN_LANG "$v"; then export AUTOBAN_LANG="$v"; load_lang; fi;;
 18) v=$(ask "$DURATION ($SECONDS_LABEL; 1..31536000)" "$BAN_TIME") && if validate_setting BAN_TIME "$v" && setting BAN_TIME "$v"; then export BAN_TIME="$v"; else echo "$INVALID"; fi;;
 19) v=$(ask "$M19" "${ZONE:-auto}") || exit 0
    if [[ "$v" == auto ]]; then v=''; elif [[ ! "$v" =~ ^[A-Za-z0-9_.-]+$ ]]; then echo "$INVALID"; continue; fi
    if setting ZONE "$v"; then ZONE="$v"; export ZONE; fi;;
 *) echo "$UNKNOWN";;
 esac
 read -r -p "$PAUSE" _ || exit 0
 done
