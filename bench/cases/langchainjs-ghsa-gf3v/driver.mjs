// The app: ingest a public docs site with RecursiveUrlLoader (default options, preventOutside on).
// The attacker authored a page on that site (inputs/<arm>.html). Run with --import /case/dns-stub.mjs.
import fs from "node:fs";
import { RecursiveUrlLoader } from "/src/libs/langchain-community/src/document_loaders/web/recursive_url.ts";

const [, , arm, nonce] = process.argv;
fs.mkdirSync("/tmp/site", { recursive: true });
fs.writeFileSync(
  "/tmp/site/index.html",
  fs.readFileSync(`/case/inputs/${arm}.html`, "utf-8").replaceAll("{{NONCE}}", nonce)
);
const loader = new RecursiveUrlLoader("http://docs.example.test:8080/", { maxDepth: 2, timeout: 5000 });
const docs = await loader.load();
console.log(JSON.stringify(docs.map((d) => [d.metadata.source, d.pageContent.slice(0, 30)])));
