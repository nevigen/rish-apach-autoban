#!/usr/bin/env bash
# Remove the installed Apache AutoBan program and its entry points.
set -euo pipefail
umask 077

[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ $# == 0 ]] || { echo 'Usage: bash uninstall.sh' >&2; exit 2; }

install_dir=/opt/apache-autoban
launcher=/usr/local/sbin/apache-autoban
logrotate_config=/etc/logrotate.d/apache-autoban

exec 9>>/run/apache-autoban.lock
flock -n 9 || { echo 'Apache AutoBan is busy. Try again when the current operation finishes.' >&2; exit 75; }

if [[ -L "$install_dir" || -L "$install_dir/lang" ]]; then
    echo 'Unexpected symlink in the Apache AutoBan installation directories.' >&2
    exit 1
fi

if [[ -L "$launcher" && $(readlink -- "$launcher") == "$install_dir/apache-autoban.sh" ]]; then
    rm -f -- "$launcher"
elif [[ -e "$launcher" || -L "$launcher" ]]; then
    printf 'Kept %s because it is not the Apache AutoBan installer symlink.\n' "$launcher" >&2
fi

rm -f -- "$logrotate_config" \
    "$install_dir/"{apache-autoban.sh,menu.sh,rish-bridge.sh,config.sh,config.py,uninstall.sh,tui.py} \
    "$install_dir/lang/"{en,ru,uk}.{json,lang} "$install_dir/lang/"ui-{en,ru,uk}.json

for dir in "$install_dir/lang" "$install_dir"; do
    if [[ -d "$dir" ]]; then
        rmdir --ignore-fail-on-non-empty -- "$dir"
    fi
done

printf '%s\n' 'Apache AutoBan uninstalled. Configuration, logs, local state and RISH rules were kept.'
