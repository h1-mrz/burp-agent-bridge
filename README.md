# burp-agent-bridge

MCP server for Burp Suite Pro. It gives an AI client control of the scanner, the
site map, proxy and WebSocket history, Repeater, Intruder, HTTP/1.1 and HTTP/2
requests, Collaborator, Organizer, saved requests, and the focused message
editor. The bridge exposes 49 tools and 50 HTTP endpoints, with a Python server
that speaks MCP over stdio, Streamable HTTP, or SSE.

## Quick start

1. Download `burp-agent-bridge-v2.1.0.zip` from the Releases page of this
   repository and unzip it.
2. In Burp: Extensions > Installed > Add > Java, then select
   `ext/agent-bridge-v2.jar`.
3. From the extracted folder, run `python3 doctor.py`. It checks the bridge and
   prints the config snippet for your client.
4. Add that snippet to your MCP client and ask it for `health`.

No build step is needed. The jar contains everything it needs, including the
JavaScript engine used by `script_run`.

## Download and install

### 1. Get the package

Download the latest release zip and verify it:

```bash
sha256sum burp-agent-bridge-v2.1.0.zip
```

Compare the output with the value in `release/SHA256SUMS` in the repository. The
zip also contains its own `SHA256SUMS` for the files inside.

### 2. Load the extension

In Burp Suite Pro, open Extensions > Installed, click Add, choose Java, and pick
`ext/agent-bridge-v2.jar`. The extension log should show:

```
AgentBridge v2.1.0 listening on 127.0.0.1:9877
```

If port 9877 is busy, remove any older AgentBridge copy and reload the
extension.

### 3. Check the install

From the extracted folder:

```bash
python3 doctor.py
```

It reports the bridge version, endpoint count, feature flags, and token state,
then prints the client configuration. If Burp runs as a different user from your
shell, doctor tells you to set `AGENT_BRIDGE_TOKEN` in both places.

### 4. Connect your MCP client

OpenCode has a command that writes the entry for you:

```bash
opencode mcp add --global burp -- python3 /absolute/path/to/burp-agent-bridge/src/server.py
```

Or edit `opencode.json` directly:

```json
{
  "mcp": {
    "servers": {
      "burp": {
        "type": "local",
        "command": ["python3", "/absolute/path/to/burp-agent-bridge/src/server.py"],
        "enabled": true
      }
    }
  }
}
```

Claude Code:

```bash
claude mcp add burp -- python3 /absolute/path/to/burp-agent-bridge/src/server.py
```

Clients that connect over HTTP can run the built-in transport instead:

```bash
python3 /absolute/path/to/burp-agent-bridge/src/server.py --transport http --port 9878
```

The Streamable HTTP endpoint is `http://127.0.0.1:9878/mcp`. Legacy SSE clients
use `/sse` and `/messages`.

### 5. Confirm the connection

Ask the client for `health`:

```json
{"ok":true,"extension":"AgentBridge","version":"2.1.0"}
```

Or call the bridge directly:

```bash
curl -s -H "Authorization: Bearer $(cat ~/.BurpSuite/agent-bridge.token)" \
     http://127.0.0.1:9877/health
```

## Requirements

- Burp Suite Pro 2026.3 or newer. The jar is compiled against Montoya 2026.7 and
  tested on 2026.3. Scanner, Collaborator, and Burp AI need Pro.
- Python 3.8 or newer on the same machine as Burp.
- An MCP client that can start a local process (stdio) or connect over HTTP.

## What it can do

The extension holds the Burp API surface. The Python server translates MCP calls
into HTTP requests to `127.0.0.1:9877` and formats the replies. It uses the
Python standard library only.

```
AI client
    |  stdio / Streamable HTTP / SSE
    v
src/server.py            49 MCP tools
    |  HTTP + JSON on 127.0.0.1:9877, bearer token
    v
ext/agent-bridge-v2.jar  Burp extension, Montoya 2026.7
    v
Burp Suite Pro
```

## Tool reference

MCP clients often prefix tool names with the server name, so `health` may appear
as `burp_health`. These are the names `tools/list` returns.

| Tool | What it does |
|---|---|
| `health` | Bridge liveness check. |
| `extension_info` | Details of the loaded extension. |
| `bridge_meta` | Version, endpoints, and feature flags. |
| `version` | Burp version and command line arguments. |
| `sitemap_list` | Site map entries with URL, method, and status. |
| `sitemap_add` | Send a request through Burp and add the result to the site map. |
| `issues_list` | Audit issues by URL prefix and severity, paged with `limit`, `offset`, `meta`. |
| `scope_check` | Test whether a URL is in target scope. |
| `scope_set` | Add or remove URL prefixes in target scope. |
| `proxy_history` | Proxy history, newest first. `contains`, `regex`, `meta`. |
| `ws_history` | WebSocket messages, newest first. `contains`, `regex`, `meta`. |
| `intercept_state` | Read the interception state. |
| `intercept_enable` | Turn interception on. |
| `intercept_disable` | Turn interception off. |
| `repeater_send` | Send a raw request to a Repeater tab. `http2` builds an HTTP/2 request for it. |
| `intruder_send` | Send a raw request to Intruder. |
| `http_send` | Send one request. `viaProxy` for proxy listeners, `http2` for HTTP/2. |
| `http_batch_send` | Send many requests in parallel. Supports the proxy and per-request HTTP/2. |
| `scan_start` | Start a passive or active audit on a URL. |
| `scan_status` | Progress of audits started by the agent. |
| `scan_issues` | Issues from one audit, including extension findings held in the site map. |
| `scan_delete` | Delete an audit task. |
| `collaborator_payload` | Generate a Collaborator payload. |
| `collaborator_interactions` | List Collaborator interactions. |
| `organizer_send` | Send a request to Organizer. |
| `organizer_items` | Organizer entries with `contains`, `regex`, `limit`, `offset`, `meta`. |
| `bambda_import` | Import a Bambda into the library. |
| `ai_status` | Whether Burp AI is enabled. |
| `ai_prompt` | Ask Burp AI a question (uses AI credits). |
| `settings_export_user` | Export user settings, optionally one section, credentials masked. |
| `settings_export_project` | Export project settings, credentials masked. |
| `settings_import_user` | Import user settings JSON. |
| `settings_import_project` | Import project settings JSON. |
| `extensions_list` | Extensions registered with Burp (read-only). |
| `task_engine` | Read or set Burp's task engine state. Setting it needs `confirm`. |
| `codec` | Encode or decode URL, Base64, Base64url, and hex. |
| `random_string` | Cryptographically random string. |
| `audit_list` | Recent bridge calls with target, status, and duration. |
| `policy_info` | Effective host policy and token requirement. |
| `saved_list` | Saved requests, newest first. |
| `saved_get` | One saved request, including raw HTTP text. |
| `saved_save` | Save a request for later replay. |
| `saved_note` | Attach or replace a note on a saved request. |
| `saved_delete` | Delete a saved request. |
| `saved_resend` | Replay one saved request, with optional find/replace, proxy, or HTTP/2. |
| `editor_get` | Read the focused Burp message editor. |
| `editor_set` | Replace or append text in the focused editor. |
| `shutdown` | Shut Burp down. Requires `confirm:true`. |
| `script_run` | Run sandboxed JavaScript inside Burp. |

## How this compares

Compared with PortSwigger's official MCP Server extension (27 tools, BApp) and
swgee/BurpMCP (10 tools), counting only shipped behavior:

| Capability | This bridge | PortSwigger MCP | swgee/BurpMCP |
|---|---|---|---|
| Start, poll, and delete scans | Yes | No, reads issues only | No |
| Add to site map, set scope | Yes | No | No |
| Batch send in one call | Yes | No | No |
| Traffic visible to proxy listeners (`viaProxy`) | Yes | No | No |
| HTTP/2 send | Yes, direct only | Yes | Yes |
| WebSocket history | Yes | Yes | No |
| Regex history filters | Yes | Yes | No |
| Active editor read and write | Yes | Yes | No |
| Task engine pause and resume | Yes | Yes | No |
| Encoding and random-string tools | Yes | Yes | No |
| Saved requests with notes | Yes | No | Yes |
| Credential filtering on config export | Yes, default on | Yes, configurable | No |
| Sandboxed script runner | Yes | No | No |
| Bambda import | Yes | No | No |
| Burp AI prompt | Yes | No | No |
| Structured JSON results | Yes | Text | Text |
| Streamable HTTP and SSE | Yes | Yes | Yes, SSE |
| Bearer token on the local API | Yes | No, interactive approval | No |
| Host allowlist before send | Yes | Interactive approval | No |
| Audit log of tool calls | Yes | No | No |

All three send HTTP/1.1 and HTTP/2 requests and use Collaborator. Proxy and
WebSocket history are here and in the official server; swgee has neither. Only
this bridge starts scans, manages the site map, sends batches, and routes traffic
through Burp's proxy. Only this bridge and swgee keep a saved-request library.
Governance differs too: this bridge ships a bearer token, a host allowlist, and
an audit log, while the official extension relies on interactive approval.

Where the others are stronger: the official extension is maintained by
PortSwigger, distributed through the BApp Store, and updated automatically.
swgee's server is smaller and quicker to read end to end. This project is
maintained by one author.

## Extensions

The bridge does not install, refresh, disable, or remove extensions. It can list
what Burp has loaded with `extensions_list`. Install BApps in the Burp UI.

How much an extension can do for a request depends on how it hooks Burp:

Scanner checks: `scan_start` launches a Burp audit, so passive and active checks
from extensions run against the scanned URL. Their findings land in the site map
and are returned by `scan_issues` and `issues_list`, including checks that do not
attach issues to the audit handle.

Proxy listeners: `http_send` and `http_batch_send` accept `viaProxy:true` with an
optional `proxyPort` (default 8080). Requests then pass through Burp's proxy
listener, which is what Param Miner's auto-miner and custom loggers need. Without
`viaProxy`, requests use Burp's network stack directly.

Manual actions: Some extensions only expose a tab or a right-click menu item.
Montoya has no API for one extension to call another, so those actions have to be
started in the Burp UI. The bridge can still read the resulting issues and traffic.

`viaProxy` needs Burp's proxy listening on loopback at the configured port, with
interception off. Otherwise the request waits for a manual release and times out.

Both hooks were tested live with small extensions: a passive check registered by
an extension ran during `scan_start` and its issue came back from `scan_issues`,
and a proxy listener saw requests sent with `viaProxy`.

Param Miner only guesses for traffic it decides to mine. Enable auto-mining once
in its UI, or start a mine and then send requests with `viaProxy:true`. Findings
show up as scanner issues.

JS Miner registers a scanner check through the legacy Extender API, the same hook
the test probe used. In testing it loaded without error but produced no findings
on a controlled JavaScript asset, while the probe's check ran on the same
response. If you rely on it, check its tab settings and Extender output, and drive
it from its UI while the bridge reads the results.

Removing an extension, or changing the extender configuration, can reload
AgentBridge and clear its in-memory audit list. Audit IDs from before the change
stop resolving. Findings already recorded remain in the site map.

## HTTP/2, WebSockets, and pagination

`http_send` with `http2:true` builds an HTTP/2 request from the raw text: the
request line becomes `:method`, `:path`, and `:scheme`; `Host` becomes
`:authority`; connection-specific headers are dropped; header names are
lowercased. HTTP/2 is direct only. `http2` and `viaProxy` are rejected together
because Burp's proxy path is HTTP/1.1. Without `http2`, Burp negotiates the
protocol itself and usually reaches HTTP/2 on modern TLS targets.

`ws_history` returns URL, direction, payload, and timestamp for each message.
`proxy_history` and `ws_history` take a Java `regex` as well as `contains`.
`meta:true` returns `{items,total,offset,limit,count,hasMore,nextOffset}` instead
of a bare array.

## Saved requests and the editor

Right-click a request in Burp and choose **Send to AgentBridge saved requests**.
The library is stored in `~/.BurpSuite/agent-bridge-saved.json` and survives
extension reloads and Burp restarts. `saved_list` returns metadata, `saved_get`
returns the request text, `saved_note` annotates it, and `saved_resend` replays
it. `find` and `replace` edit the request on the way out:

```
saved_resend {"id": 4, "find": "/api/v1/", "replace": "/api/v2/"}
```

`editor_get` reads the message editor that has keyboard focus in Burp.
`editor_set` replaces or appends its text and returns the previous length. A
tester can focus a request, let the agent read or edit it, then send it. Both
tools return `no focused text editor` when the focus is elsewhere.

## Transports

stdio is the default:

```bash
python3 src/server.py
```

HTTP and SSE:

```bash
python3 src/server.py --transport http --port 9878
```

- Streamable HTTP: `POST http://127.0.0.1:9878/mcp`
- Legacy SSE: `GET http://127.0.0.1:9878/sse`, then `POST /messages?sessionId=...`
- Health: `GET http://127.0.0.1:9878/healthz`

The HTTP listener binds to loopback and refuses a non-loopback address unless
`--auth-token` (or `AGENT_BRIDGE_HTTP_TOKEN`) is set. It rejects requests with an
`Origin` header and requires `application/json` on POST, so a web page cannot
drive it with a no-preflight request.

## Security model

The extension binds to `127.0.0.1` and rejects requests that carry an `Origin`
header, which blocks browser pages from driving the port. The HTTP transport
applies the same checks.

Every call needs a credential. On first start the extension writes
`~/.BurpSuite/agent-bridge.token` with mode 600 and expects
`Authorization: Bearer <token>`. `server.py` reads the file, or
`AGENT_BRIDGE_TOKEN` when set. If the token file cannot be written, the extension
uses an in-memory token and logs that you must set `AGENT_BRIDGE_TOKEN`.
`AGENT_BRIDGE_KEY` with `X-Burp-Key` also works as a shared secret.

Outbound hosts are checked before every send, site-map add, Repeater or Intruder
hand-off, and scan. Loopback is always allowed. `AGENT_BRIDGE_ALLOW_HOSTS` adds
host globs such as `*.example.com` or IPv4 CIDR ranges. URLs already in Burp's
target scope are allowed too. Three modes exist:

- `allowlist` (default): the checks above.
- `prompt`: a Burp dialog asks for approval, with a 30-second auto-deny.
- `open`: no check.

Set the mode with `AGENT_BRIDGE_POLICY` before starting Burp. The allowlist is a
guardrail against sending to the wrong host. It is not an authorization
boundary, because `scope_set` is exposed. For a hard boundary, use
`AGENT_BRIDGE_ALLOW_HOSTS` and do not give the client the scope tools.

Every routed call goes into an in-memory audit log of 500 entries with time,
method, path, target, HTTP status, and duration. Read it with `audit_list`.
Config exports mask values for keys that look like credentials (`password`,
`secret`, `token`, `api_key`, `credential`, `authorization`, `cookie`, and
similar) unless you pass `redact:false`.

The script sandbox denies Java classes. It exposes four host globals: `args`,
`argsJson`, `bridge`, and `console`. Extension state is read-only.

## Limitations

- HTTP/2 is direct only. Proxied HTTP/2 would need to go through Burp's own proxy
  listener, which the bridge does not drive.
- The allowlist is a guardrail, not an authorization boundary, because the model
  can call `scope_set`.
- Editor tools depend on keyboard focus inside a Burp message editor. There is no
  API to address a specific tab.
- Bambda support is import only. Montoya has no method to list or remove bambdas,
  so a failed import leaves an entry to clean up in the UI.
- The bridge cannot start another extension's UI actions or context menus.
- `shutdown` requires `confirm:true`. Changing the task engine state does too.
- Scanner, Collaborator, and Burp AI need Burp Pro. AI also needs credits.
- Request text in `proxy_history` and payloads in `ws_history` are truncated at
  6000 characters. `editor_get` truncates at 200000.
- Removing an extension may take effect only after a Burp restart.
- Extensions are installed and removed by hand. Removing one reloads AgentBridge
  and clears audit IDs tracked in memory. Recorded findings are not lost.
- The audit log is in memory and resets when the extension reloads.
- The Streamable HTTP endpoint returns a JSON-RPC response per request and 202
  for notifications. It has no GET stream and no resumption. Legacy SSE is
  available on `/sse` for clients that need it.

## Changes in 2.1.0

- `http_send` and `http_batch_send` speak HTTP/2 with `http2:true`. `viaProxy` and
  `http2` cannot be combined.
- `ws_history` reads Burp's WebSocket log.
- `proxy_history`, `ws_history`, and `organizer_items` accept `regex`.
  `proxy_history`, `ws_history`, `issues_list`, and `organizer_items` return
  pagination metadata with `meta:true`.
- `task_engine` reads and sets Burp's execution engine state. Setting it needs
  `confirm:true`.
- `codec` covers URL, Base64, Base64url, and hex. `random_string` uses
  `SecureRandom`.
- `saved_*` adds a persistent request library with notes, find/replace replay,
  and a right-click menu item in Burp.
- `editor_get` and `editor_set` read and write the focused message editor.
- `server.py` gains Streamable HTTP and SSE transports. `doctor.py` checks an
  install and prints client configuration.
- Every call requires a credential. Exports mask credential-like keys by default.
  `audit_list` exposes a call log, and hosts are checked against an allowlist.
- Tool count: 49.
