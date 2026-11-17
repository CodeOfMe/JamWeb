#!/usr/bin/env python3
"""
JamWeb - a tiny, dependency-free CMS built on Python 3 stdlib + SQLite.

Public routes
  GET  /                     post list (paged)
  GET  /p/<slug>             single post
  GET  /tag/<tag>            posts by tag
  GET  /search?q=...         title/body search
  GET  /feed.xml             RSS 2.0 feed
  GET  /static/<file>        files from <site>/static

Admin routes (cookie session)
  GET  /admin                dashboard
  GET  /admin/edit?id=N      editor (?new=1 for a blank one)
  POST /admin/save           create / update
  POST /admin/delete         delete
  GET  /admin/settings       site settings
  POST /admin/settings
  GET  /admin/password
  POST /admin/password
  GET  /admin/backup         download a consistent SQLite backup
  POST /admin/login
  POST /admin/logout

CLI
  app.py init     [--user NAME] [--password PW] [--title TITLE]
  app.py serve    [--host H] [--port N]
  app.py passwd   [--user NAME] [--password PW]
  app.py backup   [--out FILE]
  app.py import   DIR

Only the standard library is used, so it runs on OpenWrt's python3-light plus
python3-sqlite3. Tested with Python 3.8+.
"""

import argparse
import getpass
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = "JamWeb"
VERSION = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))
SITE_DIR = os.environ.get("JAMWEB_SITE", os.path.join(HERE, "site"))
DEFAULT_DB = os.path.join(HERE, "data", "jamweb.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT NOT NULL UNIQUE,
  pw_hash    TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  slug       TEXT NOT NULL UNIQUE,
  title      TEXT NOT NULL,
  body       TEXT NOT NULL DEFAULT '',
  tags       TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'published',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS posts_created ON posts(created_at DESC);
"""

DEFAULTS = {
    "site_title": "JamWeb",
    "tagline": "A tiny Python + SQLite CMS",
    "footer": "Powered by JamWeb",
    "per_page": "10",
    "secret": "",
}


# --------------------------------------------------------------------------
# database helpers
# --------------------------------------------------------------------------
def connect(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(conn, title=None):
    conn.executescript(SCHEMA)
    for k, v in DEFAULTS.items():
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?,?)", (k, v))
    if title:
        set_setting(conn, "site_title", title)
    if not get_setting(conn, "secret"):
        set_setting(conn, "secret", secrets.token_hex(32))
    conn.commit()


def get_setting(conn, key, default=""):
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key, value):
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


# --------------------------------------------------------------------------
# passwords / sessions
# --------------------------------------------------------------------------
def _pbkdf2_sha256(password, salt, rounds, dklen=32):
    """PBKDF2-HMAC-SHA256 in pure Python.

    OpenWrt's python3-light ships hashlib without pbkdf2_hmac, so fall back to
    this. It is slower but only runs on login and init.
    """
    mac = hmac.new(password, b"", hashlib.sha256)
    out = b""
    block = 1
    while len(out) < dklen:
        u = mac.copy()
        u.update(salt + block.to_bytes(4, "big"))
        t = u.digest()
        acc = bytearray(t)
        for _ in range(rounds - 1):
            u = mac.copy()
            u.update(t)
            t = u.digest()
            for i in range(len(acc)):
                acc[i] ^= t[i]
        out += bytes(acc)
        block += 1
    return out[:dklen]


def _pbkdf2(password, salt, rounds, dklen=32):
    fn = getattr(hashlib, "pbkdf2_hmac", None)
    if fn is not None:
        return fn("sha256", password, salt, rounds, dklen)
    return _pbkdf2_sha256(password, salt, rounds, dklen)


def hash_password(password):
    salt = secrets.token_bytes(16)
    # hashlib.pbkdf2_hmac is a C loop and cheap; the pure-Python fallback costs
    # ~65 us per round on a router, so use fewer rounds there. The chosen count
    # is stored in the hash, so both kinds verify fine.
    rounds = 120000 if hasattr(hashlib, "pbkdf2_hmac") else 20000
    digest = _pbkdf2(password.encode(), salt, rounds)
    return "pbkdf2$%d$%s$%s" % (rounds, salt.hex(), digest.hex())


def verify_password(password, stored):
    try:
        algo, rounds, salt, digest = stored.split("$")
        if algo != "pbkdf2":
            return False
        got = _pbkdf2(password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(got.hex(), digest)
    except (ValueError, TypeError):
        return False


def sign(secret, msg):
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def parse_session(secret, value, now=None):
    """Return username for a valid session cookie value, else None."""
    now = now or int(time.time())
    try:
        ver, user, exp, sig = value.split(".", 3)
        if ver != "v1" or int(exp) < now or not user:
            return None
        if not hmac.compare_digest(sig, sign(secret, "v1.%s.%s" % (user, exp))):
            return None
        return user
    except (ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------
# markdown (small, safe subset)
# --------------------------------------------------------------------------
SAFE_URL = re.compile(r"^(?:https?://|mailto:|/|#|\.{0,2}/)")


def safe_url(u):
    u = u.strip()
    if SAFE_URL.match(u):
        return html.escape(u, quote=True)
    return "#"


def _inline(s):
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(
        r"!\[([^\]]*)\]\(([^)\s]+)\)",
        lambda m: '<img src="%s" alt="%s" loading="lazy">' % (safe_url(m.group(2)), m.group(1)),
        s,
    )
    s = re.sub(
        r"\[([^\]]+)\]\(([^)\s]+)\)",
        lambda m: '<a href="%s">%s</a>' % (safe_url(m.group(2)), m.group(1)),
        s,
    )
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", s)
    s = re.sub(r"~~([^~]+)~~", r"<del>\1</del>", s)
    return s


def render_md(text):
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    out = []
    i = 0
    n = len(lines)

    def is_block_start(s):
        return bool(
            re.match(r"^(#{1,6}\s|```|>|[-*+]\s|\d+\.\s|---+\s*$|\*\*\*\s*$)", s)
        )

    while i < n:
        line = lines[i]

        if not line.strip():
            i += 1
            continue

        fence = re.match(r"^```\s*([\w+-]*)\s*$", line)
        if fence:
            lang = fence.group(1)
            i += 1
            buf = []
            while i < n and not re.match(r"^```\s*$", lines[i]):
                buf.append(lines[i])
                i += 1
            i += 1
            cls = ' class="language-%s"' % lang if lang else ""
            out.append("<pre><code%s>%s</code></pre>" % (cls, html.escape("\n".join(buf))))
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            out.append("<h%d>%s</h%d>" % (level, _inline(html.escape(m.group(2))), level))
            i += 1
            continue

        if re.match(r"^(---+|\*\*\*+)\s*$", line):
            out.append("<hr>")
            i += 1
            continue

        if line.startswith(">"):
            buf = []
            while i < n and lines[i].startswith(">"):
                buf.append(re.sub(r"^>\s?", "", lines[i]))
                i += 1
            out.append("<blockquote>%s</blockquote>" % render_md("\n".join(buf)))
            continue

        if re.match(r"^[-*+]\s+", line):
            items = []
            while i < n and re.match(r"^[-*+]\s+", lines[i]):
                items.append("<li>%s</li>" % _inline(html.escape(re.sub(r"^[-*+]\s+", "", lines[i]))))
                i += 1
            out.append("<ul>%s</ul>" % "".join(items))
            continue

        if re.match(r"^\d+\.\s+", line):
            items = []
            while i < n and re.match(r"^\d+\.\s+", lines[i]):
                items.append("<li>%s</li>" % _inline(html.escape(re.sub(r"^\d+\.\s+", "", lines[i]))))
                i += 1
            out.append("<ol>%s</ol>" % "".join(items))
            continue

        para = []
        while i < n and lines[i].strip() and not is_block_start(lines[i]):
            para.append(lines[i])
            i += 1
        out.append("<p>%s</p>" % _inline(html.escape(" ".join(para))))

    return "\n".join(out)


def plain(text, limit=200):
    text = re.sub(r"```.*?```", " ", text or "", flags=re.S)
    text = re.sub(r"[#>*_`\[\]()!~-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


# --------------------------------------------------------------------------
# html
# --------------------------------------------------------------------------
def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


CSS = """
*{box-sizing:border-box}
body{margin:0;font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,
 "PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;color:#1f2328;background:#fff}
a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}
header.site,main,footer.site{max-width:760px;margin:0 auto;padding:0 20px}
header.site{padding-top:28px;padding-bottom:8px}
header.site h1{margin:0;font-size:26px}
header.site .tag{color:#6a737d;font-size:14px;margin-top:4px}
nav.top{margin-top:14px;font-size:14px}
nav.top a{margin-right:14px;color:#57606a}
main{padding-top:22px;padding-bottom:40px}
article.post{border-bottom:1px solid #eaecef;padding:18px 0}
article.post:last-child{border-bottom:0}
article.post h2{margin:0 0 4px;font-size:20px}
article.post h2 a{color:#1f2328}
.meta{color:#6a737d;font-size:13px}
.meta .taglink{background:#f1f3f5;border-radius:4px;padding:1px 6px;margin-right:6px}
.summary{color:#444;margin:8px 0 0}
h1.title{font-size:30px;margin:0 0 6px}
pre{background:#f6f8fa;border-radius:8px;padding:14px;overflow:auto;font-size:13.5px}
code{background:#f1f3f5;border-radius:4px;padding:1px 4px;font-size:90%}
pre code{background:none;padding:0}
blockquote{margin:16px 0;padding:2px 16px;border-left:4px solid #dfe2e5;color:#57606a}
img{max-width:100%;height:auto;border-radius:6px}
hr{border:0;border-top:1px solid #eaecef;margin:24px 0}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;border-bottom:1px solid #eaecef;padding:8px 6px}
footer.site{color:#6a737d;font-size:13px;padding:24px 20px 40px;border-top:1px solid #eaecef}
.pager{display:flex;justify-content:space-between;margin-top:24px;font-size:14px}
form{margin:0}
label{display:block;font-size:13px;color:#57606a;margin:14px 0 5px}
input[type=text],input[type=password],input[type=search],select,textarea{
 width:100%;font:inherit;padding:8px 10px;border:1px solid #d0d7de;border-radius:6px;background:#fff}
textarea{min-height:340px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13.5px}
button,.btn{display:inline-block;margin-top:16px;margin-right:8px;padding:8px 16px;font:inherit;
 border:1px solid #d0d7de;border-radius:6px;background:#f6f8fa;cursor:pointer}
button.primary{background:#1f883d;border-color:#1a7f37;color:#fff}
button.danger{background:#fff;border-color:#cf222e;color:#cf222e}
.flash{background:#ddf4ff;border:1px solid #b6e3ff;border-radius:6px;padding:10px 12px;margin-bottom:16px}
.err{background:#fff5f5;border:1px solid #ffcecb;color:#a40e26;border-radius:6px;padding:10px 12px;margin-bottom:16px}
.row{display:flex;gap:16px;flex-wrap:wrap}
.row>div{flex:1;min-width:220px}
.actions a{margin-right:12px;font-size:13px}
.login{max-width:360px;margin:40px auto}
"""


def layout(srv, conn, title, body, user=None, flash="", error="", url=None):
    site = get_setting(conn, "site_title", "JamWeb")
    tagline = get_setting(conn, "tagline", "")
    footer = get_setting(conn, "footer", "")
    u = url or (lambda p: srv.base + p)
    nav = ['<a href="%s">Home</a>' % u("/")]
    nav.append('<a href="%s">Feed</a>' % u("/feed.xml"))
    if user:
        nav.append('<a href="%s">Admin</a>' % u("/admin"))
        nav.append('<a href="%s">New post</a>' % u("/admin/edit?new=1"))
        nav.append('<a href="%s">Log out</a>' % u("/admin/logout"))
    else:
        nav.append('<a href="%s">Log in</a>' % u("/admin"))
    head = site if not title else "%s · %s" % (esc(title), esc(site))
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>%s</title>" % head,
        "<style>%s</style>" % CSS,
        "</head><body>",
        '<header class="site"><h1><a href="%s" style="color:inherit">%s</a></h1>' % (u("/"), esc(site)),
    ]
    if tagline:
        parts.append('<div class="tag">%s</div>' % esc(tagline))
    parts.append('<nav class="top">%s</nav></header>' % "".join(nav))
    parts.append("<main>")
    if flash:
        parts.append('<div class="flash">%s</div>' % esc(flash))
    if error:
        parts.append('<div class="err">%s</div>' % esc(error))
    parts.append(body)
    parts.append("</main>")
    parts.append('<footer class="site">%s</footer>' % esc(footer))
    parts.append("</body></html>")
    return "".join(parts)


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------
class Config:
    def __init__(self, db, host="0.0.0.0", port=8080, base=""):
        self.db = db
        self.host = host
        self.port = int(port)
        self.base = base.rstrip("/")


class Handler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (APP, VERSION)
    protocol_version = "HTTP/1.1"
    max_body = 1024 * 1024

    # ---- plumbing --------------------------------------------------------
    @property
    def srv(self):
        return self.server.cfg

    def url(self, path):
        return self.srv.base + path

    def db(self):
        return connect(self.srv.db)

    def secret(self, conn):
        return get_setting(conn, "secret") or os.environ.get("JAMWEB_SECRET", "")

    def current_user(self, conn):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get("jw_session")
        if not morsel:
            return None
        user = parse_session(self.secret(conn), morsel.value)
        if not user:
            return None
        row = conn.execute("SELECT username FROM users WHERE username=?", (user,)).fetchone()
        return row["username"] if row else None

    def csrf(self, conn, user):
        exp = int(time.time()) + 86400
        return "%d.%s" % (exp, sign(self.secret(conn), "csrf.%s.%d" % (user, exp)))

    def check_csrf(self, conn, user, token):
        try:
            exp, sig = token.split(".", 1)
            if int(exp) < int(time.time()):
                return False
            return hmac.compare_digest(sig, sign(self.secret(conn), "csrf.%s.%s" % (user, exp)))
        except (ValueError, AttributeError):
            return False

    def send_html(self, code, body, extra=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src * data:; style-src 'unsafe-inline'; base-uri 'none'",
        )
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, location, extra=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def page(self, conn, title, body, user=None, code=200, flash="", error=""):
        self.send_html(code, layout(self.srv, conn, title, body, user=user, flash=flash, error=error,
                                    url=self.url))

    def not_found(self, conn, user=None):
        self.page(conn, "Not found", "<h1 class='title'>404</h1><p>Nothing here.</p>", user=user, code=404)

    def parse(self):
        raw = self.path
        if self.srv.base and raw.startswith(self.srv.base):
            raw = raw[len(self.srv.base):] or "/"
        parsed = urllib.parse.urlsplit(raw)
        return parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def form(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > self.max_body:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- GET -------------------------------------------------------------
    def do_GET(self):
        path, qs = self.parse()
        conn = self.db()
        try:
            user = self.current_user(conn)
            if path == "/" or path == "":
                return self.view_index(conn, qs, user)
            if path.startswith("/p/"):
                return self.view_post(conn, urllib.parse.unquote(path[3:]), user)
            if path.startswith("/tag/"):
                return self.view_tag(conn, urllib.parse.unquote(path[5:]), qs, user)
            if path == "/search":
                return self.view_search(conn, qs, user)
            if path == "/feed.xml":
                return self.view_feed(conn)
            if path.startswith("/static/"):
                return self.view_static(path[8:])
            if path == "/healthz":
                return self.send_html(200, "ok")
            if path == "/favicon.ico":
                return self.send_html(204, "")
            if path == "/admin":
                if not user:
                    return self.view_login(conn, qs)
                return self.view_admin(conn, user, qs)
            if path == "/admin/edit":
                return self.require_login(conn, user, lambda: self.view_edit(conn, user, qs))
            if path == "/admin/settings":
                return self.require_login(conn, user, lambda: self.view_settings(conn, user, qs))
            if path == "/admin/password":
                return self.require_login(conn, user, lambda: self.view_password(conn, user, qs))
            if path == "/admin/backup":
                return self.require_login(conn, user, lambda: self.view_backup(conn))
            if path == "/admin/logout":
                return self.redirect(self.url("/admin"),
                                     [("Set-Cookie", "jw_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")])
            return self.not_found(conn, user)
        finally:
            conn.close()

    def require_login(self, conn, user, fn):
        if not user:
            return self.redirect(self.url("/admin"))
        return fn()

    # ---- views -----------------------------------------------------------
    def view_index(self, conn, qs, user):
        per = max(1, min(50, int(get_setting(conn, "per_page", "10") or 10)))
        page = max(1, int((qs.get("page") or ["1"])[0] or 1))
        total = conn.execute("SELECT COUNT(*) c FROM posts WHERE status='published'").fetchone()["c"]
        rows = conn.execute(
            "SELECT * FROM posts WHERE status='published' ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (per, (page - 1) * per),
        ).fetchall()
        body = []
        if not rows:
            body.append("<p>No posts yet.</p>")
        for r in rows:
            body.append(
                '<article class="post"><h2><a href="%s">%s</a></h2>'
                '<div class="meta">%s%s</div><p class="summary">%s</p></article>'
                % (
                    self.url("/p/" + urllib.parse.quote(r["slug"])),
                    esc(r["title"]),
                    self.date_html(r["created_at"]),
                    self.tags_html(r["tags"]),
                    esc(plain(r["body"], 220)),
                )
            )
        body.append(self.pager(page, per, total, "/"))
        self.page(conn, "", "".join(body), user=user)

    def view_post(self, conn, slug, user):
        r = conn.execute("SELECT * FROM posts WHERE slug=?", (slug,)).fetchone()
        if not r or (r["status"] != "published" and not user):
            return self.not_found(conn, user)
        actions = ""
        if user:
            actions = '<div class="actions"><a href="%s">Edit</a></div>' % self.url(
                "/admin/edit?id=%d" % r["id"]
            )
        body = (
            '<article><h1 class="title">%s</h1>'
            '<div class="meta">%s%s%s</div>%s<div class="post-body">%s</div></article>'
            % (
                esc(r["title"]),
                self.date_html(r["created_at"]),
                self.tags_html(r["tags"]),
                "" if r["status"] == "published" else ' <span class="taglink">draft</span>',
                actions,
                render_md(r["body"]),
            )
        )
        self.page(conn, r["title"], body, user=user)

    def view_tag(self, conn, tag, qs, user):
        rows = conn.execute(
            "SELECT * FROM posts WHERE status='published' AND (','||lower(tags)||',') LIKE ? "
            "ORDER BY created_at DESC, id DESC",
            ("%," + tag.lower() + ",%",),
        ).fetchall()
        body = ['<h1 class="title">Tag: %s</h1>' % esc(tag)]
        for r in rows:
            body.append(
                '<article class="post"><h2><a href="%s">%s</a></h2>'
                '<div class="meta">%s</div><p class="summary">%s</p></article>'
                % (
                    self.url("/p/" + urllib.parse.quote(r["slug"])),
                    esc(r["title"]),
                    self.date_html(r["created_at"]),
                    esc(plain(r["body"], 200)),
                )
            )
        if not rows:
            body.append("<p>No posts with that tag.</p>")
        self.page(conn, "Tag: " + tag, "".join(body), user=user)

    def view_search(self, conn, qs, user):
        q = (qs.get("q") or [""])[0].strip()
        body = [
            '<h1 class="title">Search</h1>',
            '<form method="get" action="%s"><input type="search" name="q" value="%s" '
            'placeholder="Search posts"><button class="primary" type="submit">Search</button></form>'
            % (self.url("/search"), esc(q)),
        ]
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            rows = conn.execute(
                "SELECT * FROM posts WHERE status='published' AND (title LIKE ? ESCAPE '\\' "
                "OR body LIKE ? ESCAPE '\\') ORDER BY created_at DESC",
                (like, like),
            ).fetchall()
            body.append("<p class='meta'>%d result(s) for “%s”</p>" % (len(rows), esc(q)))
            for r in rows:
                body.append(
                    '<article class="post"><h2><a href="%s">%s</a></h2>'
                    '<div class="meta">%s</div><p class="summary">%s</p></article>'
                    % (
                        self.url("/p/" + urllib.parse.quote(r["slug"])),
                        esc(r["title"]),
                        self.date_html(r["created_at"]),
                        esc(plain(r["body"], 200)),
                    )
                )
        self.page(conn, "Search", "".join(body), user=user)

    def view_feed(self, conn):
        site = get_setting(conn, "site_title", "JamWeb")
        base = os.environ.get("JAMWEB_PUBLIC_URL", "http://localhost").rstrip("/") + self.srv.base
        rows = conn.execute(
            "SELECT * FROM posts WHERE status='published' ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        items = []
        for r in rows:
            link = base + "/p/" + urllib.parse.quote(r["slug"])
            items.append(
                "<item><title>%s</title><link>%s</link><guid isPermaLink=\"false\">%s</guid>"
                "<pubDate>%s</pubDate><description>%s</description></item>"
                % (
                    esc(r["title"]),
                    esc(link),
                    esc(r["slug"]),
                    self.rfc822(r["created_at"]),
                    esc(plain(r["body"], 300)),
                )
            )
        xml = (
            '<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel>'
            "<title>%s</title><link>%s</link><description>%s</description>%s</channel></rss>"
            % (esc(site), esc(base), esc(get_setting(conn, "tagline", "")), "".join(items))
        )
        data = xml.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/rss+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def view_static(self, name):
        base = os.path.join(SITE_DIR, "static")
        target = os.path.join(base, os.path.basename(name))
        if not os.path.isfile(target):
            return self.send_html(404, "not found")
        ctype = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".txt": "text/plain; charset=utf-8",
        }.get(os.path.splitext(target)[1].lower(), "application/octet-stream")
        with open(target, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def view_login(self, conn, qs):
        error = "Wrong username or password." if qs.get("e") else ""
        body = (
            '<div class="login"><h1 class="title">Log in</h1>'
            '<form method="post" action="%s">'
            '<label>Username</label><input type="text" name="username" autocomplete="username" autofocus>'
            '<label>Password</label><input type="password" name="password" autocomplete="current-password">'
            '<button class="primary" type="submit">Log in</button></form></div>' % self.url("/admin/login")
        )
        self.page(conn, "Log in", body, code=200 if not error else 401, error=error)

    def view_admin(self, conn, user, qs):
        rows = conn.execute("SELECT * FROM posts ORDER BY created_at DESC, id DESC").fetchall()
        trs = []
        for r in rows:
            trs.append(
                "<tr><td><a href='%s'>%s</a>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='actions'>"
                "<a href='%s'>Edit</a></td></tr>"
                % (
                    self.url("/p/" + urllib.parse.quote(r["slug"])),
                    esc(r["title"]),
                    "" if r["status"] == "published" else " <em>(draft)</em>",
                    self.date_html(r["created_at"]),
                    esc(r["tags"]),
                    esc(r["status"]),
                    self.url("/admin/edit?id=%d" % r["id"]),
                )
            )
        body = (
            '<h1 class="title">Posts</h1><p class="meta">%d total</p>'
            '<table><thead><tr><th>Title</th><th>Date</th><th>Tags</th><th>Status</th><th></th></tr></thead>'
            "<tbody>%s</tbody></table>"
            '<div class="btn-row"><a class="btn" href="%s">New post</a>'
            '<a class="btn" href="%s">Settings</a><a class="btn" href="%s">Password</a>'
            '<a class="btn" href="%s">Backup</a></div>'
            % (
                len(rows),
                "".join(trs) or "<tr><td colspan='5'>No posts yet.</td></tr>",
                self.url("/admin/edit?new=1"),
                self.url("/admin/settings"),
                self.url("/admin/password"),
                self.url("/admin/backup"),
            )
        )
        self.page(conn, "Admin", body, user=user, flash=(qs.get("ok") or [""])[0])

    def view_edit(self, conn, user, qs):
        pid = (qs.get("id") or [""])[0]
        r = None
        if pid.isdigit():
            r = conn.execute("SELECT * FROM posts WHERE id=?", (int(pid),)).fetchone()
            if not r:
                return self.not_found(conn, user)
        token = self.csrf(conn, user)
        body = (
            '<h1 class="title">%s</h1><form method="post" action="%s">'
            '<input type="hidden" name="csrf" value="%s">'
            '<input type="hidden" name="id" value="%s">'
            '<label>Title</label><input type="text" name="title" value="%s" required>'
            '<div class="row"><div><label>Slug</label><input type="text" name="slug" value="%s" '
            'placeholder="auto from title"></div>'
            '<div><label>Tags (comma separated)</label><input type="text" name="tags" value="%s"></div>'
            '<div><label>Status</label><select name="status">'
            '<option value="published"%s>published</option><option value="draft"%s>draft</option>'
            "</select></div></div>"
            '<label>Body (Markdown)</label><textarea name="body">%s</textarea>'
            '<button class="primary" type="submit">Save</button>'
            '<a class="btn" href="%s">Cancel</a>'
            "</form>"
            "%s"
            % (
                "Edit post" if r else "New post",
                self.url("/admin/save"),
                esc(token),
                "" if not r else r["id"],
                "" if not r else esc(r["title"]),
                "" if not r else esc(r["slug"]),
                "" if not r else esc(r["tags"]),
                ' selected' if (r and r["status"] == "published") else "",
                ' selected' if (r and r["status"] == "draft") else "",
                "" if not r else esc(r["body"]),
                self.url("/admin"),
                ""
                if not r
                else '<form method="post" action="%s" onsubmit="return confirm(\'Delete this post?\')">'
                '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%d">'
                '<button class="danger" type="submit">Delete</button></form>'
                % (self.url("/admin/delete"), esc(token), r["id"]),
            )
        )
        self.page(conn, "Edit", body, user=user)

    def view_settings(self, conn, user, qs):
        token = self.csrf(conn, user)
        body = (
            '<h1 class="title">Settings</h1><form method="post" action="%s">'
            '<input type="hidden" name="csrf" value="%s">'
            '<label>Site title</label><input type="text" name="site_title" value="%s">'
            '<label>Tagline</label><input type="text" name="tagline" value="%s">'
            '<label>Footer</label><input type="text" name="footer" value="%s">'
            '<label>Posts per page (1-50)</label><input type="text" name="per_page" value="%s">'
            '<button class="primary" type="submit">Save</button></form>'
            % (
                self.url("/admin/settings"),
                esc(token),
                esc(get_setting(conn, "site_title")),
                esc(get_setting(conn, "tagline")),
                esc(get_setting(conn, "footer")),
                esc(get_setting(conn, "per_page", "10")),
            )
        )
        self.page(conn, "Settings", body, user=user, flash=(qs.get("ok") or [""])[0])

    def view_password(self, conn, user, qs):
        token = self.csrf(conn, user)
        body = (
            '<h1 class="title">Change password</h1><form method="post" action="%s">'
            '<input type="hidden" name="csrf" value="%s">'
            '<label>Current password</label><input type="password" name="current">'
            '<label>New password (min 8 chars)</label><input type="password" name="new">'
            '<label>Repeat new password</label><input type="password" name="repeat">'
            '<button class="primary" type="submit">Update</button></form>'
            % (self.url("/admin/password"), esc(token))
        )
        self.page(conn, "Password", body, user=user, flash=(qs.get("ok") or [""])[0])

    def view_backup(self, conn):
        tmp = tempfile.NamedTemporaryFile(prefix="jamweb-", suffix=".db", delete=False)
        tmp.close()
        dest = sqlite3.connect(tmp.name)
        try:
            conn.backup(dest)
        finally:
            dest.close()
        with open(tmp.name, "rb") as fh:
            data = fh.read()
        os.unlink(tmp.name)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="jamweb-%s.db"' % stamp)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- POST ------------------------------------------------------------
    def do_POST(self):
        path, qs = self.parse()
        conn = self.db()
        try:
            user = self.current_user(conn)
            form = self.form()

            if path == "/admin/login":
                return self.post_login(conn, form)
            if path == "/admin/logout":
                return self.redirect(self.url("/admin"),
                                     [("Set-Cookie", "jw_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")])

            if not user:
                return self.redirect(self.url("/admin"))
            if not self.check_csrf(conn, user, form.get("csrf", "")):
                return self.page(conn, "Bad request",
                                 "<h1 class='title'>Bad request</h1><p>Invalid or expired form token.</p>",
                                 user=user, code=400)

            if path == "/admin/save":
                return self.post_save(conn, user, form)
            if path == "/admin/delete":
                return self.post_delete(conn, user, form)
            if path == "/admin/settings":
                return self.post_settings(conn, user, form)
            if path == "/admin/password":
                return self.post_password(conn, user, form)
            return self.not_found(conn, user)
        finally:
            conn.close()

    def post_login(self, conn, form):
        ip = self.client_address[0]
        now = time.time()
        count, until = self.server.fails.get(ip, (0, 0))
        if until > now:
            return self.page(conn, "Log in",
                             "<h1 class='title'>Log in</h1><p>Too many attempts. Try again shortly.</p>", code=429)
        row = conn.execute(
            "SELECT * FROM users WHERE username=?", (form.get("username", ""),)
        ).fetchone()
        if not row or not verify_password(form.get("password", ""), row["pw_hash"]):
            self.server.fails[ip] = (count + 1, now + (300 if count >= 4 else 0))
            return self.redirect(self.url("/admin?e=1"))
        self.server.fails.pop(ip, None)
        exp = int(now) + 7 * 86400
        value = "v1.%s.%d.%s" % (row["username"], exp, sign(self.secret(conn), "v1.%s.%d" % (row["username"], exp)))
        self.redirect(
            self.url("/admin"),
            [("Set-Cookie",
              "jw_session=%s; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax" % value)],
        )

    def post_save(self, conn, user, form):
        title = (form.get("title") or "").strip()
        body = form.get("body") or ""
        tags = self.norm_tags(form.get("tags") or "")
        status = "draft" if form.get("status") == "draft" else "published"
        slug = (form.get("slug") or "").strip().lower()
        pid = form.get("id", "")
        if not title:
            return self.page(conn, "Edit", "<p>Title is required.</p>", user=user, code=400)
        if slug and not re.match(r"^[a-z0-9][a-z0-9-]{0,80}$", slug):
            return self.page(conn, "Edit", "<p>Slug must be lowercase letters, digits or dashes.</p>",
                             user=user, code=400)
        if not slug:
            slug = slugify(title)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if pid.isdigit():
            slug = self.unique_slug(conn, slug, int(pid))
            conn.execute(
                "UPDATE posts SET slug=?, title=?, body=?, tags=?, status=?, updated_at=? WHERE id=?",
                (slug, title, body, tags, status, stamp, int(pid)),
            )
        else:
            slug = self.unique_slug(conn, slug, None)
            conn.execute(
                "INSERT INTO posts(slug,title,body,tags,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (slug, title, body, tags, status, stamp, stamp),
            )
        conn.commit()
        return self.redirect(self.url("/admin?ok=Saved"))

    def post_delete(self, conn, user, form):
        pid = form.get("id", "")
        if pid.isdigit():
            conn.execute("DELETE FROM posts WHERE id=?", (int(pid),))
            conn.commit()
        return self.redirect(self.url("/admin?ok=Deleted"))

    def post_settings(self, conn, user, form):
        set_setting(conn, "site_title", (form.get("site_title") or "JamWeb").strip()[:80])
        set_setting(conn, "tagline", (form.get("tagline") or "").strip()[:160])
        set_setting(conn, "footer", (form.get("footer") or "").strip()[:160])
        try:
            per = max(1, min(50, int(form.get("per_page") or 10)))
        except ValueError:
            per = 10
        set_setting(conn, "per_page", str(per))
        conn.commit()
        return self.redirect(self.url("/admin/settings?ok=Saved"))

    def post_password(self, conn, user, form):
        current = form.get("current") or ""
        new = form.get("new") or ""
        repeat = form.get("repeat") or ""
        row = conn.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone()
        if not row or not verify_password(current, row["pw_hash"]):
            return self.page(conn, "Password",
                             "<p>Current password is wrong.</p>", user=user, code=400)
        if len(new) < 8:
            return self.page(conn, "Password",
                             "<p>New password must be at least 8 characters.</p>", user=user, code=400)
        if new != repeat:
            return self.page(conn, "Password",
                             "<p>The two new passwords do not match.</p>", user=user, code=400)
        conn.execute("UPDATE users SET pw_hash=? WHERE username=?", (hash_password(new), user))
        conn.commit()
        return self.redirect(self.url("/admin/password?ok=Password updated"))

    # ---- small helpers ----------------------------------------------------
    def date_html(self, stamp):
        return '<time datetime="%s">%s</time> ' % (esc(stamp), esc((stamp or "")[:10]))

    def tags_html(self, tags):
        parts = []
        for tag in [t.strip() for t in (tags or "").split(",") if t.strip()]:
            parts.append(
                '<a class="taglink" href="%s">%s</a>'
                % (self.url("/tag/" + urllib.parse.quote(tag.lower())), esc(tag))
            )
        return "".join(parts)

    def pager(self, page, per, total, base):
        pages = max(1, (total + per - 1) // per)
        if pages <= 1:
            return ""
        prev = (
            '<a href="%s">‹ Newer</a>' % self.url("%s?page=%d" % (base, page - 1)) if page > 1 else "<span></span>"
        )
        nxt = (
            '<a href="%s">Older ›</a>' % self.url("%s?page=%d" % (base, page + 1))
            if page < pages
            else "<span></span>"
        )
        return '<div class="pager">%s<span class="meta">page %d / %d</span>%s</div>' % (prev, page, pages, nxt)

    def rfc822(self, stamp):
        try:
            dt = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")
        except (ValueError, TypeError):
            return ""

    def norm_tags(self, raw):
        seen, out = set(), []
        for t in re.split(r"[,\s]+", raw):
            t = t.strip()[:32]
            if t and t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
        return ",".join(out)

    def unique_slug(self, conn, base, pid):
        base = base or "post"
        slug = base
        n = 2
        while True:
            row = conn.execute("SELECT id FROM posts WHERE slug=?", (slug,)).fetchone()
            if not row or (pid and row["id"] == pid):
                return slug
            slug = "%s-%d" % (base, n)
            n += 1


def slugify(title):
    s = (title or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or "post-" + secrets.token_hex(3)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def ensure_user(conn, username, password):
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if row:
        conn.execute("UPDATE users SET pw_hash=? WHERE username=?", (hash_password(password), username))
    else:
        conn.execute(
            "INSERT INTO users(username, pw_hash, created_at) VALUES(?,?,?)",
            (username, hash_password(password), stamp),
        )
    conn.commit()


def cmd_init(args):
    conn = connect(args.db)
    init_db(conn, title=args.title)
    password = args.password or secrets.token_urlsafe(9)
    ensure_user(conn, args.user, password)
    conn.commit()
    print("database: %s" % os.path.abspath(args.db))
    print("admin user: %s" % args.user)
    print("admin password: %s" % password)
    if not args.password:
        print("(generated - change it with: %s %s passwd --db %s)" % (sys.argv[0], os.path.basename(__file__), args.db))
    conn.close()


def cmd_passwd(args):
    conn = connect(args.db)
    init_db(conn)
    password = args.password or getpass.getpass("New password: ")
    ensure_user(conn, args.user, password)
    conn.close()
    print("password updated for %s" % args.user)


def cmd_backup(args):
    conn = connect(args.db)
    out = args.out or ("jamweb-%s.db" % datetime.now().strftime("%Y%m%d-%H%M%S"))
    dest = sqlite3.connect(out)
    with dest:
        conn.backup(dest)
    dest.close()
    conn.close()
    print("backup written to %s" % os.path.abspath(out))


def cmd_import(args):
    conn = connect(args.db)
    init_db(conn)
    count = 0
    for name in sorted(os.listdir(args.dir)):
        if not name.lower().endswith((".md", ".markdown", ".txt")):
            continue
        path = os.path.join(args.dir, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        base = os.path.splitext(name)[0]
        title = base
        m = re.search(r"^#\s+(.+)$", text, re.M)
        if m:
            title = m.group(1).strip()
            text = text[: m.start()] + text[m.end():]
        slug = slugify(base)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            conn.execute(
                "INSERT INTO posts(slug,title,body,tags,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (slug, title, text.strip(), "", "published", stamp, stamp),
            )
            count += 1
        except sqlite3.IntegrityError:
            print("skip (exists): %s" % base)
    conn.commit()
    conn.close()
    print("imported %d post(s)" % count)


def cmd_serve(args):
    if not os.path.exists(args.db):
        sys.exit("database not found: %s\nrun: python3 app.py init --db %s" % (args.db, args.db))
    cfg = Config(args.db, args.host, args.port, os.environ.get("JAMWEB_BASE", ""))
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    httpd.cfg = cfg
    httpd.fails = {}
    print("%s %s serving on http://%s:%d%s (db %s)" %
          (APP, VERSION, cfg.host, cfg.port, cfg.base, os.path.abspath(cfg.db)))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="jamweb", description="Tiny Python + SQLite CMS")
    ap.add_argument("--db", default=os.environ.get("JAMWEB_DB", DEFAULT_DB), help="SQLite database path")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="create database and admin user")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="")
    p.add_argument("--title", default="")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("serve", help="run the HTTP server")
    p.add_argument("--host", default=os.environ.get("JAMWEB_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.environ.get("JAMWEB_PORT", "8080")))
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("passwd", help="set an admin password")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="")
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("backup", help="write a consistent copy of the database")
    p.add_argument("--out", default="")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("import", help="import a directory of markdown files")
    p.add_argument("dir")
    p.set_defaults(func=cmd_import)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
