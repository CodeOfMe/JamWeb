# JamWeb

A tiny **CMS** for small machines: one Python file, one SQLite file, no
dependencies beyond the Python 3 standard library. It runs comfortably on an
OpenWrt router with `python3-light` + `python3-sqlite3` (a few MB), or on any
Linux box.

Originally a JamVM/Java experiment; rewritten in Python because that is the
runtime that actually fits on a 32 MB router.

## Features

- SQLite storage (WAL mode), single file, trivial to back up
- Write posts in Markdown (headings, lists, quotes, code fences, links, images)
- Drafts vs published, tags, search, pagination
- RSS feed at `/feed.xml`
- Admin UI: dashboard, editor, settings, password change, one-click backup
- Secure defaults: PBKDF2 password hashing, HMAC-signed session cookies,
  CSRF tokens, HTML escaping, strict slug validation, login throttling
- Zero third-party packages; ~40 KB of Python

## Quick start (any Linux / macOS)

```sh
python3 app.py --db data/jamweb.db init --user admin --title "My Blog"
python3 app.py --db data/jamweb.db serve --port 8080
# open http://localhost:8080/  (admin at /admin)
```

`init` prints a generated password unless you pass `--password`.

## Install on OpenWrt

```sh
opkg update
opkg install python3-light python3-sqlite3 python3-logging python3-email
./install.sh
```

`install.sh` copies the app to `/usr/lib/jamweb`, creates
`/etc/jamweb/jamweb.db`, installs the procd service, opens the LAN firewall
port, and starts it on **8080**.

Useful environment variables:

| Variable | Meaning |
|---|---|
| `JAMWEB_PORT` | listen port (default `8080`) |
| `JAMWEB_DB` | database path (default `/etc/jamweb/jamweb.db`) |
| `JAMWEB_USER` / `JAMWEB_PASSWORD` | admin account created on install |
| `JAMWEB_BASE` | URL prefix when behind a reverse proxy, e.g. `/blog` |
| `JAMWEB_PUBLIC_URL` | absolute site URL used in the RSS feed |
| `JAMWEB_SITE` | directory for `static/` assets |

Example: serve under `http://router/blog/` through nginx:

```
location /blog/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
}
```

and start the service with `JAMWEB_BASE=/blog`.

### HTTPS

The app speaks plain HTTP; terminate TLS in front of it. `deploy/nginx-8443.conf`
is a ready-made nginx server block that proxies `https://host:8443/` to
`127.0.0.1:8080` and forwards `X-Forwarded-Proto` (which makes the session
cookie `Secure`).

On OpenWrt:

```sh
cp deploy/nginx-8443.conf /etc/nginx/conf.d/jamweb.conf
nginx -t -c /etc/nginx/uci.conf && nginx -s reload -c /etc/nginx/uci.conf
```

## CLI

```
app.py init    [--user NAME] [--password PW] [--title TITLE]
app.py serve   [--host H] [--port N]
app.py passwd  [--user NAME] [--password PW]
app.py backup  [--out FILE]
app.py import  DIR
```

`import` loads a directory of `.md` files (first `# heading` becomes the
title, filename becomes the slug). Handy for moving an existing blog in.

## Routes

There are two entrances: **visitors** use `/` (public posts) and the
**administrator** uses `/admin` (login or dashboard). The public nav shows an
`Admin` link unless you tick *Hide the Admin link* in Settings, in which case
`/admin` is reachable by URL only. Logged-in admins get an extra *View site*
link back to the public pages.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | post list, `?page=N` |
| GET | `/p/<slug>` | single post |
| GET | `/tag/<tag>` | posts by tag |
| GET | `/search?q=` | title/body search |
| GET | `/feed.xml` | RSS 2.0 |
| GET | `/static/<file>` | files from `site/static` |
| GET | `/admin` | dashboard / login |
| GET | `/admin/edit?id=N` | editor (`?new=1` for new) |
| GET | `/admin/settings`, `/admin/password`, `/admin/backup` | admin tools |
| POST | `/admin/save`, `/admin/delete`, `/admin/settings`, `/admin/password`, `/admin/login`, `/admin/logout` | mutations |

## Layout

```
app.py            the whole CMS (server + CLI)
install.sh        OpenWrt installer
init.d/jamweb     procd service
site/static/      optional static assets
data/             default database location (gitignored)
```

## Security notes

- All rendering escapes user content first; only a small Markdown subset is
  converted, and URLs are restricted to `http(s)`, `mailto` and local paths.
- Sessions are `HttpOnly`, `SameSite=Lax`, signed with a per-install secret and
  valid for 7 days. Forms carry per-session CSRF tokens.
- Run it behind your router firewall. If you expose it to the WAN, put TLS in
  front (nginx/caddy) and set `Secure` on the cookie.

## License

MIT
