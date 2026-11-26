#!/bin/bash
# Delegate temporary firewall rule changes to the RISH module.
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset RISH_FIREWALL_TEST_MODE RISH_FIREWALL_STATE_DIR RISH_FIREWALL_LIST_DIR RISH_FW_WHITELIST_SOURCE
[[ $EUID == 0 && $# == 4 ]] || exit 1
[[ $2 =~ ^[A-Za-z0-9_.-]+$ ]] || exit 1
ip=$(python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); assert a.is_global and not a.is_multicast and "%" not in sys.argv[1]; print(a)' "$3") || exit 1
[[ -r /root/rish/scripts/firewall_management.sh ]] || { echo 'RISH module missing' >&2; exit 1; }
source /root/rish/scripts/firewall_management.sh || exit 1
RISH_FW_ZONE=$2
rish_fw_require || exit 1
case "$1" in
 add) [[ -n ${SSH_CONNECTION:-${SSH_CLIENT:-}} ]] || { echo 'RISH requires real SSH context; automatic bans unavailable from cron' >&2; exit 1; }; rish_fw_temporary_add "$ip" "$4" monitor ;;
 remove) rish_fw_temporary_remove "$ip" ;;
 *) exit 1 ;;
esac
