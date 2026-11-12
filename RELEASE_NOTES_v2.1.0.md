# burp-agent-bridge 2.1.0

A complete MCP bridge for Burp Suite Pro: scanner orchestration, HTTP/1.1 and
HTTP/2, WebSocket history, a persistent saved-request library with notes, focused
editor access, and three transports. It covers every tool in PortSwigger's
official MCP Server and swgee/BurpMCP, and adds the scanner and site-map control
neither of them has.

## Highlights

- **Scanner orchestration.** Start, poll, and delete passive or active audits,
  seed the site map, and set target scope. Extension scanner checks run and their
  findings are merged into `scan_issues`.
- **HTTP/1.1 and HTTP/2.** `http_send`, batch send, Repeater, Intruder, and saved
  replay. HTTP/2 builds real pseudo-headers and lowercases field names. `viaProxy`
  puts requests in front of proxy-listener extensions such as Param Miner.
- **Traffic history.** Proxy HTTP history and WebSocket history, with `contains`
  and Java `regex` filters plus `meta:true` pagination
  (`total`, `hasMore`, `nextOffset`).
- **Saved requests.** Right-click any request in Burp and choose **Send to
  AgentBridge saved requests**. The library persists to
  `~/.BurpSuite/agent-bridge-saved.json` across reloads and restarts, with notes
  and find/replace replay.
- **Focused editor access.** `editor_get` reads the message editor the tester is
  working in; `editor_set` replaces or appends text and returns the previous
  length. This is the human-in-the-loop hand-off primitive.
- **Codec and random strings.** URL, Base64, Base64url, and hex; `SecureRandom`
  with `alnum`, `alpha`, `digits`, and `hex`.
- **Three transports.** stdio by default; `--transport http` serves Streamable
  HTTP at `/mcp` and legacy SSE at `/sse`, with optional bearer auth.
- **Operations.** `doctor.py` verifies the install and prints client config.
  Bearer token required by default, outbound host allowlist (`allowlist`,
  `prompt`, or `open`), credential masking on config export, and an audit log.
- **49 tools, 50 endpoints.**

## Verified in this build

- Live feature matrix against Burp Suite Pro: **139/139** checks.
  Covers HTTP/2 against a local nginx h2 server, a real WebSocket conversation
  recorded through the proxy, saved-request lifecycle and persistence, editor
  read/write, regex and pagination, task-engine pause/resume, and the allowlist
  refusing an off-scope host.
- Adapter contract suite: **66/66** checks over all 49 tools
  (schema, dispatch, error contracts, 401 on unauthenticated calls).
- Clean-room check of the extracted release zip, including the HTTP transport:
  **29/29**.

## Behaviour you should know

- **Token.** The extension writes `~/.BurpSuite/agent-bridge.token` (mode 600) on
  first start and requires `Authorization: Bearer <token>`. `server.py` and
  `doctor.py` read it automatically. If Burp runs as a different user (common on
  Kali, where Burp is started with sudo), set `AGENT_BRIDGE_TOKEN` to one value in
  both environments.
- **Host policy.** Default is an allowlist: loopback, `AGENT_BRIDGE_ALLOW_HOSTS`
  entries (globs or IPv4 CIDR), and URLs already in Burp scope. A public target
  must be in scope before the agent can send to it. `AGENT_BRIDGE_POLICY=prompt`
  asks in a Burp dialog (30-second auto-deny); `open` disables the check.
- **HTTP/2 is direct only.** Burp's proxy path is HTTP/1.1, so `http2` and
  `viaProxy` are mutually exclusive and rejected together.
- **Editor tools follow keyboard focus.** There is no API to address a specific
  tab, so the tester focuses the editor they want the agent to read or edit.
- **In-memory audit log.** 500 entries, reset on extension reload.

## Install

1. Load `ext/agent-bridge-v2.jar` in Burp: Extensions > Installed > Add > Java.
   The extension listens on `127.0.0.1:9877` and writes its token.
2. Run `python3 doctor.py`. It checks the bridge, token, and feature flags, and
   prints the config snippet for your client.
3. Register the server:

   ```
   claude mcp add burp -- python3 /absolute/path/to/burp-agent-bridge/src/server.py
   ```

   or, for HTTP clients:

   ```
   python3 /absolute/path/to/burp-agent-bridge/src/server.py --transport http --port 9878
   ```

4. Ask the client for `health`. Expect
   `{"ok":true,"extension":"AgentBridge","version":"2.1.0"}`.

Requirements: Burp Suite Pro 2026.3 or newer (scanner, Collaborator, and Burp AI
tools need Pro) and Python 3.8 or newer.

## Checksums

See `SHA256SUMS` in the release assets. The shipped jar is
`ext/agent-bridge-v2.jar`, SHA-256
`da754dace306a60da01343dd59e5fcc5c7045a210b09c7575cf03c2c2cd1bf4e`.
