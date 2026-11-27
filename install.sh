#!/usr/bin/env bash
# Install Apache AutoBan files on a server with RISH.
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v python3 >/dev/null || { echo "Python 3 is required; no packages installed." >&2; exit 1; }
exec 9>>/run/apache-autoban.lock
flock -n 9 || { echo 'Apache AutoBan is busy. Try again when the current operation finishes.' >&2; exit 75; }
install -d -m 700 /opt/apache-autoban /opt/apache-autoban/lang /etc/apache-autoban
install -m 700 apache-autoban.sh menu.sh rish-bridge.sh config.sh config.py uninstall.sh /opt/apache-autoban/
rm -f /opt/apache-autoban/tui.py /opt/apache-autoban/lang/ui-{ru,uk,en}.json
install -m 600 lang/* /opt/apache-autoban/lang/
[[ -e /etc/apache-autoban/config.conf ]] || install -m 600 config.conf /etc/apache-autoban/config.conf
[[ -e /root/apache-stopwords.txt ]] || install -m 600 defaults/apache-stopwords.txt /root/apache-stopwords.txt
[[ -e /root/apache-whitelist.txt ]] || install -m 600 /dev/null /root/apache-whitelist.txt
install -m 644 apache-autoban.logrotate /etc/logrotate.d/apache-autoban
ln -sfn /opt/apache-autoban/apache-autoban.sh /usr/local/sbin/apache-autoban
printf '%s\n' 'Installed. Run: apache-autoban' \
  'Stopwords: /root/apache-stopwords.txt (example words are commented out: remove # to enable)' \
  'Cron (report only): /opt/apache-autoban/apache-autoban.sh --dry-run' \
  'Bans need a root SSH session (RISH safety check).' \
  'Uninstall: bash /opt/apache-autoban/uninstall.sh'
if [[ ! -r /root/rish/scripts/firewall_management.sh ]]; then
    echo 'WARNING: /root/rish/scripts/firewall_management.sh not found. Scans work, but bans will fail until RISH is installed.' >&2
fi
