# mcp-remote GHSA-6xpm-ggf7-wc3p / CVE-2025-6514 (Path 7: malicious MCP server -> client)

## The public advisory

`mcp-remote` is a client-side bridge that lets a local MCP (stdio) client talk to a remote MCP
server. When the remote server advertises OAuth, `mcp-remote` runs the authorization-code flow: it
reads the server's authorization-server metadata, builds the authorization URL, and opens it in the
user's browser so they can approve the client.

The `authorization_endpoint` in that metadata is **chosen by the remote server**. In vulnerable
versions (0.0.5–0.1.15) `mcp-remote` passes the resulting URL straight to the npm `open` package:

- sink: `src/lib/node-oauth-client-provider.ts:175`, method `redirectToAuthorization`
  (vuln SHA `2a0665de6c5a0cec0695effe592aec7a34c5f215`):
  `await open(authorizationUrl.toString())`
- `open` dependency: `^10.1.0`.

`open` hands the URL to the operating system's URL opener. A **malicious MCP server** can therefore
choose a URL that makes the victim's host launch a program, with no code injection and no user
interaction beyond connecting. The GitHub/CVE record rates this critical (CVE-2025-6514, fixed in
0.1.16).

## The fix

Fix `783bf8656952a9590eacfda50db485edbd13aff8` wraps the sink with a new `sanitizeUrl()`
(`src/lib/utils.ts`):

```ts
export function sanitizeUrl(raw: string) {
  const url = new URL(raw)
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`Invalid url to pass to open(): ${url}`)
  }
  url.hostname = encodeURIComponent(url.hostname)
  url.pathname = url.pathname.slice(0, 1) + encodeURIComponent(url.pathname.slice(1))
  url.search  = url.search.slice(0, 1)  + Array.from(url.searchParams.entries()).map(sanitizeParam).join('&')
  url.hash    = url.hash.slice(0, 1)    + encodeURIComponent(url.hash.slice(1))
  return url.href
}
```

Two guards: (1) **reject any scheme other than `http`/`https`**, and (2) percent-encode the host,
path, every query key/value and the fragment (closing the Windows PowerShell `$(...)` injection in
the sibling report). A follow-up (`607b226`) also encodes the userinfo. This case exercises guard (1).

## Why this exact path, and why it is the Linux-reachable one

The original JFrog write-up (Or Peles, 2025-07-09) proved *shell command* execution only on
**Windows**, where `open` embeds the URL in a double-quoted PowerShell string and a `$(...)`
subexpression executes. It states that on **macOS and Linux** the same bug yields *"execution of
arbitrary executables ... no shell is invoked"* — i.e. the URL opener launches a locally registered
application for the URL, the attacker just does not get a shell.

On Linux, `open@10.1.0` spawns its bundled `xdg-open` with the URL as a single `argv` element (no
shell — verified against the package source). For a URL whose **scheme has a registered handler**,
`xdg-open`'s `open_generic` → `open_generic_xdg_x_scheme_handler` launches that handler with the full
URL as the `.desktop` `%u` field. Custom URL-scheme handlers are ubiquitous on real desktops
(`vscode://`, `slack://`, `zoommtg://`, `discord://`, …), so an attacker-chosen
`authorization_endpoint` of the form `someapp://…` launches that local application on an ordinary
desktop Linux victim. That is the Linux instance of the advisory's "open an attacker-chosen URL"
primitive, and it is precisely what fix guard (1) blocks by refusing every non-http(s) scheme.

We therefore model a desktop Linux victim: the image registers a handler for a stand-in scheme
`avbexec` (a `.desktop` whose `Exec` runs `/home/app/bin/avb-runner %u`). `DISPLAY` is set at run
time so `xdg-open`'s `has_display` is true and the scheme-handler branch is taken; no X server is
contacted (xdg-mime queries the MIME database only). We do **not** inject a shell command — faithful
to the advisory, the Linux primitive is "launch a locally registered application for the URL".

## The three arms

The driver (`driver.mjs`) plays the malicious server: it builds the attacker URL (attacker-chosen
endpoint + the OAuth query parameters the MCP SDK appends) and calls the **real**
`NodeOAuthClientProvider.redirectToAuthorization` imported from the checked-out source, so vuln and
fix differ only in their own code.

- **ATTACK** (vuln image, `avbexec://authorize/?…&avbnonce=<nonce>`): `redirectToAuthorization`
  calls `open(url)`; `xdg-open` launches the registered handler, which writes
  `/tmp/avb_canary_<nonce>` containing `pwned-<nonce>`. → 5/5 hits.
- **CONTROL** (vuln image, benign `https://127.0.0.1/authorize?…`): `open` is called, but no handler
  is registered for `https` in the headless image, so nothing launches. → 0/5.
- **FIX** (fix image, same `avbexec://…` attack URL): `redirectToAuthorization` calls
  `open(sanitizeUrl(url))`; `sanitizeUrl` throws `Invalid url to pass to open()` on the non-http(s)
  scheme, the method logs *"Could not open browser automatically"*, and `open` is never called. The
  failure is attributable to the fix's scheme check, not a crash. → 0/5.

Run: `python bench/run.py mcp-remote-ghsa-6xpm` → ATTACK 5/5, CONTROL 0/5, FIX 0/5, `--network none`.

## Attacker model and scope note

Attacker = `malicious-mcp-server` (controls only the authorization URL). The case assumes an
ordinary desktop Linux victim with at least one registered custom URL-scheme handler, which is the
documented Linux attack surface. A tool scoring this benchmark may, under a strict threat model,
treat "opens any scheme the OS is willing to handle" as the whole defect regardless of which handler
happens to be installed; the fix agrees, and simply refuses non-http(s) schemes.
