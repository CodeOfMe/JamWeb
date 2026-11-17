#!/bin/sh
# Install JamWeb (Python + SQLite CMS) on OpenWrt.
#
# Requires: python3-light and python3-sqlite3 (+ python3-logging, python3-email
# if you use the tiny bundled HTTP server's defaults).
#
#   opkg update
#   opkg install python3-light python3-sqlite3 python3-logging python3-email
#   ./install.sh
#
# Env overrides: JAMWEB_PORT (default 8080), JAMWEB_USER, JAMWEB_TITLE,
#                JAMWEB_DB (default /etc/jamweb/jamweb.db)
set -e

SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/usr/lib/jamweb
DB=${JAMWEB_DB:-/etc/jamweb/jamweb.db}
PORT=${JAMWEB_PORT:-8080}

command -v python3 >/dev/null 2>&1 || {
  echo "python3 not found. Run: opkg install python3-light" >&2
  exit 1
}

python3 - <<'PY' || {
import sys
try:
    import sqlite3
except Exception:
    sys.exit(1)
PY
  echo "python3-sqlite3 not available. Run: opkg install python3-sqlite3" >&2
  exit 1
}

mkdir -p "$DEST" "$(dirname "$DB")"
cp "$SRC/app.py" "$DEST/app.py"
chmod 755 "$DEST/app.py"

# bundled front-end assets (KaTeX, highlight.js, jamweb.js)
mkdir -p "$DEST/site"
cp -r "$SRC/site/static" "$DEST/site/static"

cp "$SRC/init.d/jamweb" /etc/init.d/jamweb
chmod 755 /etc/init.d/jamweb

if [ ! -f "$DB" ]; then
  python3 "$DEST/app.py" --db "$DB" init \
    --user "${JAMWEB_USER:-admin}" \
    --title "${JAMWEB_TITLE:-JamWeb}"
fi

/etc/init.d/jamweb enable
/etc/init.d/jamweb restart

echo
echo "JamWeb installed."
echo "  site:  http://<router-ip>:${PORT}/"
echo "  admin: http://<router-ip>:${PORT}/admin"
echo "  db:    ${DB}"
if [ -n "$JAMWEB_PASSWORD" ]; then
  python3 "$DEST/app.py" --db "$DB" passwd --user "${JAMWEB_USER:-admin}" --password "$JAMWEB_PASSWORD"
fi

# Open the port if a firewall is active.
if command -v uci >/dev/null 2>&1; then
  uci -q get firewall.jamweb >/dev/null 2>&1 || {
    uci set firewall.jamweb=rule
    uci set firewall.jamweb.name='Allow-JamWeb'
    uci set firewall.jamweb.src='lan'
    uci set firewall.jamweb.dest_port="$PORT"
    uci set firewall.jamweb.proto='tcp'
    uci set firewall.jamweb.target='ACCEPT'
    uci commit firewall
    /etc/init.d/firewall reload >/dev/null 2>&1 || true
  }
fi

exit 0
