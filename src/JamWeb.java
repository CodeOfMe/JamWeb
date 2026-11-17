/*
 * JamWeb - a minimal Java blog / HTTP server designed to run on very small
 * JVMs such as JamVM + GNU Classpath (Java 5 level). No external libraries,
 * no servlet container, no NIO. One file, one jar.
 *
 * Serves a tiny file-based blog from <root>/posts/*.txt|*.html plus static
 * files from <root>/.
 *
 * Usage:  java JamWeb [--port 8080] [--root /etc/jamweb/site]
 */
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;

public class JamWeb {

    static String docroot = "/etc/jamweb/site";
    static int port = 8080;
    static String title = "JamWeb";

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < args.length - 1; i++) {
            if ("--port".equals(args[i])) {
                try { port = Integer.parseInt(args[i + 1]); } catch (Exception e) {}
            } else if ("--root".equals(args[i])) {
                docroot = args[i + 1];
            } else if ("--title".equals(args[i])) {
                title = args[i + 1];
            }
        }
        File root = new File(docroot);
        if (!root.isDirectory()) {
            System.err.println("docroot not found: " + docroot);
        }
        ServerSocket ss = new ServerSocket(port);
        System.out.println("JamWeb v1.0 listening on :" + port + " root=" + docroot);
        while (true) {
            Socket s = ss.accept();
            try {
                Thread t = new Thread(new Handler(s));
                t.setDaemon(true);
                t.start();
            } catch (Throwable e) {
                try { s.close(); } catch (Exception e2) {}
            }
        }
    }

    static class Handler implements Runnable {
        private final Socket sock;
        Handler(Socket s) { this.sock = s; }

        public void run() {
            try {
                sock.setSoTimeout(15000);
                InputStream in = sock.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(in, "UTF-8"));
                String reqLine = br.readLine();
                if (reqLine == null) { sock.close(); return; }
                // consume headers
                String line;
                int contentLength = 0;
                while ((line = br.readLine()) != null) {
                    if (line.length() == 0) break;
                    if (line.toLowerCase().startsWith("content-length:")) {
                        try { contentLength = Integer.parseInt(line.substring(15).trim()); } catch (Exception e) {}
                    }
                }
                String[] parts = reqLine.split(" ");
                String method = parts.length > 0 ? parts[0] : "GET";
                String rawPath = parts.length > 1 ? parts[1] : "/";
                String path = rawPath;
                int q = path.indexOf('?');
                if (q >= 0) path = path.substring(0, q);
                path = URLDecoder.decode(path, "UTF-8");

                // drain body (we do not support forms in this minimal build)
                for (int i = 0; i < contentLength; i++) { try { in.read(); } catch (Exception e) { break; } }

                // route
                if ("/".equals(path) || "/index.html".equals(path)) {
                    serveIndex();
                } else if (path.startsWith("/p/")) {
                    servePost(path.substring(3));
                } else if ("/robots.txt".equals(path)) {
                    sendText(200, "text/plain", "User-agent: *\nDisallow:\n");
                } else {
                    serveStatic(path);
                }
            } catch (Throwable e) {
                try { sendText(500, "text/plain", "error: " + e); } catch (Throwable e2) {}
            } finally {
                try { sock.close(); } catch (Exception e) {}
            }
        }

        private void serveIndex() throws Exception {
            File dir = new File(docroot, "posts");
            File[] files = dir.listFiles();
            ArrayList list = new ArrayList();
            if (files != null) {
                for (int i = 0; i < files.length; i++) {
                    String n = files[i].getName();
                    if (files[i].isFile() && (n.endsWith(".txt") || n.endsWith(".html"))) list.add(files[i]);
                }
            }
            Collections.sort(list, new Comparator() {
                public int compare(Object a, Object b) {
                    return ((File) b).getName().compareTo(((File) a).getName()); // newest (by name) first
                }
            });
            StringBuffer sb = new StringBuffer();
            sb.append(pageHead(title));
            sb.append("<h1>").append(esc(title)).append("</h1>\n");
            sb.append("<p class=\"muted\">").append(list.size()).append(" posts</p>\n<ul class=\"posts\">\n");
            for (int i = 0; i < list.size(); i++) {
                File f = (File) list.get(i);
                String name = f.getName();
                String slug = name.substring(0, name.length() - 4);
                sb.append("<li><a href=\"/p/").append(escUrl(slug)).append("\">")
                  .append(esc(postTitle(f, slug))).append("</a></li>\n");
            }
            sb.append("</ul>\n").append(pageFoot());
            sendText(200, "text/html; charset=utf-8", sb.toString());
        }

        private void servePost(String slug) throws Exception {
            // prevent traversal
            if (slug.indexOf("..") >= 0 || slug.indexOf('/') >= 0) { sendText(400, "text/plain", "bad request"); return; }
            File f = new File(new File(docroot, "posts"), slug + ".txt");
            boolean html = false;
            if (!f.isFile()) { f = new File(new File(docroot, "posts"), slug + ".html"); html = true; }
            if (!f.isFile()) { sendText(404, "text/plain", "post not found"); return; }
            String body = readFile(f);
            StringBuffer sb = new StringBuffer();
            sb.append(pageHead(postTitle(f, slug)));
            sb.append("<p class=\"muted\"><a href=\"/\">&larr; index</a></p>\n");
            sb.append("<h1>").append(esc(postTitle(f, slug))).append("</h1>\n");
            if (html) {
                sb.append(body);
            } else {
                sb.append("<pre class=\"post\">").append(esc(body)).append("</pre>");
            }
            sb.append(pageFoot());
            sendText(200, "text/html; charset=utf-8", sb.toString());
        }

        private void serveStatic(String path) throws Exception {
            if (path.indexOf("..") >= 0) { sendText(400, "text/plain", "bad request"); return; }
            if (path.endsWith("/")) path = path + "index.html";
            File f = new File(docroot + path);
            String canon = f.getCanonicalPath();
            String rootCanon = new File(docroot).getCanonicalPath();
            if (!canon.startsWith(rootCanon)) { sendText(403, "text/plain", "forbidden"); return; }
            if (f.isDirectory()) f = new File(f, "index.html");
            if (!f.isFile()) { sendText(404, "text/plain", "not found"); return; }
            byte[] data = readBytes(f);
            String ct = guessType(f.getName());
            OutputStream out = new BufferedOutputStream(sock.getOutputStream());
            PrintWriter h = new PrintWriter(new OutputStreamWriter(out, "UTF-8"));
            h.print("HTTP/1.1 200 OK\r\n");
            h.print("Content-Type: " + ct + "\r\n");
            h.print("Content-Length: " + data.length + "\r\n");
            h.print("Connection: close\r\n\r\n");
            h.flush();
            out.write(data);
            out.flush();
        }

        private void sendText(int code, String ct, String body) throws Exception {
            byte[] data = body.getBytes("UTF-8");
            OutputStream out = new BufferedOutputStream(sock.getOutputStream());
            PrintWriter h = new PrintWriter(new OutputStreamWriter(out, "UTF-8"));
            String reason = code == 200 ? "OK" : (code == 404 ? "Not Found" : (code == 400 ? "Bad Request" : (code == 403 ? "Forbidden" : "Error")));
            h.print("HTTP/1.1 " + code + " " + reason + "\r\n");
            h.print("Content-Type: " + ct + "\r\n");
            h.print("Content-Length: " + data.length + "\r\n");
            h.print("Connection: close\r\n\r\n");
            h.flush();
            out.write(data);
            out.flush();
        }
    }

    // ---- helpers ----
    static String postTitle(File f, String slug) {
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"));
            String first = r.readLine();
            r.close();
            if (first != null) {
                first = first.trim();
                if (first.startsWith("#")) first = first.substring(1).trim();
                if (first.length() > 0) return first;
            }
        } catch (Exception e) {}
        return slug;
    }

    static String readFile(File f) throws Exception {
        StringBuffer sb = new StringBuffer();
        BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"));
        String line;
        while ((line = r.readLine()) != null) sb.append(line).append('\n');
        r.close();
        return sb.toString();
    }

    static byte[] readBytes(File f) throws Exception {
        FileInputStream in = new FileInputStream(f);
        byte[] buf = new byte[(int) f.length()];
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) break;
            off += n;
        }
        in.close();
        return buf;
    }

    static String guessType(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".html") || n.endsWith(".htm")) return "text/html; charset=utf-8";
        if (n.endsWith(".css")) return "text/css";
        if (n.endsWith(".js")) return "application/javascript";
        if (n.endsWith(".json")) return "application/json";
        if (n.endsWith(".png")) return "image/png";
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
        if (n.endsWith(".gif")) return "image/gif";
        if (n.endsWith(".svg")) return "image/svg+xml";
        if (n.endsWith(".txt")) return "text/plain; charset=utf-8";
        return "application/octet-stream";
    }

    static String esc(String s) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '&') sb.append("&amp;");
            else if (c == '<') sb.append("&lt;");
            else if (c == '>') sb.append("&gt;");
            else if (c == '"') sb.append("&quot;");
            else sb.append(c);
        }
        return sb.toString();
    }

    static String escUrl(String s) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') sb.append(c);
            else sb.append('_');
        }
        return sb.toString();
    }

    static String pageHead(String t) {
        return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            + "<title>" + esc(t) + "</title><style>"
            + "body{font:16px/1.6 system-ui,-apple-system,Segoe UI,PingFang SC,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#1b2330}"
            + "a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}"
            + "h1{font-size:24px}.muted{color:#6b7a90;font-size:14px}"
            + "ul.posts{list-style:none;padding:0}ul.posts li{padding:10px 0;border-bottom:1px solid #e6ebf2}"
            + "pre.post{white-space:pre-wrap;background:#f6f8fb;padding:14px;border-radius:10px;border:1px solid #e6ebf2}"
            + "</style></head><body>\n";
    }

    static String pageFoot() {
        return "\n<hr><p class=\"muted\">Powered by JamWeb (minimal Java blog for JamVM)</p></body></html>\n";
    }
}
