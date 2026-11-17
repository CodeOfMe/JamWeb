# JamWeb

A minimal **Java blog / HTTP server** designed to run on very small JVMs such as
**JamVM + GNU Classpath** (Java 5 level). One source file, one tiny jar, no
external libraries, no servlet container, no NIO.

It turns a directory of text/HTML files into a simple blog:

- `GET /` — index listing all posts (first line of each file is the title)
- `GET /p/<slug>` — render a post (`posts/<slug>.txt` or `.html`)
- everything else — served as static files from the site root

## Why

Running a full Java CMS (Jetty + Pebble, Tomcat, etc.) needs ~80–250 MB and a
modern JRE — far too big for 32/64 MB embedded routers. JamWeb plus a small JVM
gives you a working Java blog in a few hundred KB of bytecode and a few MB of
runtime, which can fit on constrained OpenWrt devices.

## Requirements

- Any Java runtime. Best for tiny devices: **JamVM** (1.5.4 / 2.0.0) with
  **GNU Classpath**, or any Java 5+ runtime, or a normal OpenJDK 8+.
- No other dependencies.

> JamVM/Classpath are not in every OpenWrt feed. On devices without a Java
> runtime you must supply one (build JamVM/Classpath, or use a musl OpenJDK if
> you have enough storage).

## Build

```sh
./build.sh          # -> jamweb.jar
```

### Producing JamVM-compatible bytecode

JamVM runs old class files (Java 5, class version 49). Modern `javac` (JDK 17+)
can no longer target 1.5, so use the Eclipse compiler which can:

```sh
curl -L -o ecj.jar \
  https://repo1.maven.org/maven2/org/eclipse/jdt/ecj/3.33.0/ecj-3.33.0.jar
./build.sh          # auto-detects ./ecj.jar and emits Java 5 bytecode
```

## Run

```sh
./run.sh            # uses jamvm if present, else java
# or explicitly:
java -cp jamweb.jar JamWeb --port 8080 --root /etc/jamweb/site --title "My Blog"
```

Port / root / title can also come from env vars `PORT`, `ROOT`, `TITLE`.

## Install on OpenWrt

```sh
./build.sh
DEST=/usr/share/jamweb SITE=/etc/jamweb/site ./install.sh
# then open http://<router>:8080/
```

The install script copies the jar, a procd init script (`/etc/init.d/jamweb`),
and seeds a sample site at `/etc/jamweb/site/posts/`.

## Writing posts

Drop `.txt` (plain, HTML-escaped) or `.html` (rendered as-is) files into
`/etc/jamweb/site/posts/`. The first line becomes the title. Files are listed
newest-first by filename.

## Footprint

| Component | Size |
|---|---|
| `jamweb.jar` (this app) | ~15 KB |
| JamVM | ~200 KB |
| GNU Classpath | ~2–5 MB |

Total runtime fits in a few MB — small enough for modest embedded flash.

## Security

- Path traversal is blocked (`..`, canonical path check).
- Bound to all interfaces on the chosen port; run behind your router firewall.
- No authentication / no write API in this minimal build (read-only blog).

## License

MIT. See `LICENSE`.
