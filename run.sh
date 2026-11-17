#!/bin/sh
# Run JamWeb using JamVM if present, else a standard java launcher.
JAR="${JAMWEB_JAR:-/usr/share/jamweb/jamweb.jar}"
PORT="${PORT:-8080}"
ROOT="${ROOT:-/etc/jamweb/site}"
TITLE="${TITLE:-JamWeb}"
ARGS="--port $PORT --root $ROOT --title $TITLE"
if command -v jamvm >/dev/null 2>&1; then
	exec jamvm -cp "$JAR" JamWeb $ARGS
elif command -v java >/dev/null 2>&1; then
	exec java -cp "$JAR" JamWeb $ARGS
else
	echo "JamWeb: neither jamvm nor java found" >&2
	exit 1
fi
