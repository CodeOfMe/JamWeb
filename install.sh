#!/bin/sh
# Install JamWeb on OpenWrt (or any Linux).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
DEST="${DEST:-/usr/share/jamweb}"
SITE="${SITE:-/etc/jamweb/site}"

[ -f "$HERE/jamweb.jar" ] || { echo "build first: ./build.sh"; exit 1; }

mkdir -p "$DEST" "$SITE/posts"
cp "$HERE/jamweb.jar" "$DEST/"
cp "$HERE/run.sh" "$DEST/run.sh"
chmod +x "$DEST/run.sh"
# seed sample site if empty
if [ ! -f "$SITE/posts/hello.txt" ]; then
	cp -r "$HERE/site/." "$SITE/" 2>/dev/null || true
fi
# init script (procd on OpenWrt)
if [ -d /etc/init.d ]; then
	cp "$HERE/init.d/jamweb" /etc/init.d/jamweb
	chmod +x /etc/init.d/jamweb
	/etc/init.d/jamweb enable 2>/dev/null || true
	/etc/init.d/jamweb restart 2>/dev/null || true
fi
echo "Installed. Open http://<router>:8080/"
