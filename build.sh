#!/bin/sh
# Build JamWeb into jamweb.jar.
# For JamVM we need old bytecode (class file 49 = Java 5). ECJ can target 1.5
# even on a modern JDK; plain javac on JDK 17 cannot, so it is the fallback.
set -e
cd "$(dirname "$0")"
rm -rf out
mkdir -p out

if command -v ecj >/dev/null 2>&1; then
  ecj -source 1.5 -target 1.5 -encoding UTF-8 -d out src/JamWeb.java
  echo "compiled with ecj (Java 5 bytecode)"
elif [ -f ecj.jar ]; then
  java -jar ecj.jar -source 1.5 -target 1.5 -encoding UTF-8 -d out src/JamWeb.java 2>/dev/null
  echo "compiled with ecj.jar (Java 5 bytecode)"
elif javac -source 1.5 -target 1.5 -encoding UTF-8 -d out src/JamWeb.java 2>/dev/null; then
  echo "compiled with javac -source 1.5"
else
  javac -encoding UTF-8 -d out src/JamWeb.java
  echo "NOTE: compiled with default javac; modern bytecode may not run on JamVM."
  echo "      Use ECJ (see README) to produce Java 5 bytecode."
fi

jar cf jamweb.jar -C out .
echo "built: $(pwd)/jamweb.jar"
