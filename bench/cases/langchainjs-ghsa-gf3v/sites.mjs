// Two loopback-only HTTP servers inside the target container (--network none: no interfaces but lo).
//  * 127.0.0.1:8080 plays the public docs site the app crawls (docs.example.test). Its front page is
//    /tmp/site/index.html, written by the driver from the arm's input (the attacker-authored page).
//  * 127.0.0.1:9999 plays an internal-only service; it logs every request path to /tmp/internal_hits.
import http from "node:http";
import fs from "node:fs";

http.createServer((req, res) => {
  let body = "<html><body><p>docs page</p></body></html>";
  if (req.url === "/") {
    try { body = fs.readFileSync("/tmp/site/index.html", "utf-8"); } catch {}
  }
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(body);
}).listen(8080, "127.0.0.1");

http.createServer((req, res) => {
  fs.appendFileSync("/tmp/internal_hits", req.url + "\n");
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("internal-admin-data");
}).listen(9999, "127.0.0.1");
