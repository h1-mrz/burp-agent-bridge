#!/usr/bin/env python3
"""
Burp Suite MCP server (burp-agent-bridge) bridges any MCP client (OpenCode, Claude Code, etc.)
to Burp Suite Pro via the AgentBridge extension HTTP API (127.0.0.1:9877).

Protocol: MCP stdio (newline-delimited JSON-RPC 2.0). Zero third-party dependencies.

Setup:
  1. Burp Suite Pro running with ext/agent-bridge-v2.jar loaded
  2. Register in your harness:
       opencode.json -> "mcp": {"burp": {"command": "python3", "args": ["/path/to/burp-agent-bridge/src/server.py"]}}
       claude: claude mcp add burp -- python3 /path/to/burp-agent-bridge/src/server.py
  3. Auth: the extension writes ~/.BurpSuite/agent-bridge.token on first start and
     this server sends it automatically. Override with AGENT_BRIDGE_TOKEN, or use
     AGENT_BRIDGE_KEY when Burp was started with that variable set.
"""
import argparse
import hmac
import json
import os
import queue
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BRIDGE_URL = os.environ.get("BURP_BRIDGE_URL", "http://127.0.0.1:9877")
API_KEY = os.environ.get("AGENT_BRIDGE_KEY", "")


def _load_token():
    env = os.environ.get("AGENT_BRIDGE_TOKEN", "").strip()
    if env:
        return env
    path = os.environ.get("AGENT_BRIDGE_TOKEN_FILE", "").strip()
    candidates = [path] if path else []
    candidates.append(os.path.expanduser("~/.BurpSuite/agent-bridge.token"))
    for candidate in candidates:
        if not candidate:
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return ""


TOKEN = _load_token()
SERVER_VERSION = "2.1.0"

# Protocol revisions this server actually implements (tools + tools/call semantics).
PROTOCOL_VERSION = "2024-11-05"
KNOWN_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}

# Tool calls run in parallel (Burp's HTTP API is thread-safe); anything else stays ordered.
MAX_WORKERS = 8
MAX_LINE = 64 * 1024 * 1024


# The bridge is loopback-only, so ambient http_proxy/https_proxy environment
# variables must never be applied to these calls.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _reload_token():
    """Pick up a token the extension recreated after this process started."""
    global TOKEN
    fresh = _load_token()
    if fresh and fresh != TOKEN:
        TOKEN = fresh
        return True
    return False


def bridge_call(method, path, params=None, body=None, timeout=120):
    # Retry once on a connection failure, but only for reads. A write that timed
    # out may already have been applied; replaying it would duplicate the action
    # (a second scan, repeater tab, or issued payload).
    code, text = _bridge_call_once(method, path, params, body, timeout)
    if code == 401 and _reload_token():
        # Authorization failures are never applied, so replaying is safe.
        code, text = _bridge_call_once(method, path, params, body, timeout)
    if code != 0 or method != "GET":
        return code, text
    time.sleep(2)
    return _bridge_call_once(method, path, params, body, timeout)


def _bridge_call_once(method, path, params=None, body=None, timeout=120):
    url = BRIDGE_URL + path
    if params:
        qs = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items() if v not in (None, "",))
        if qs:
            url += ("&" if "?" in url else "?") + qs
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    if API_KEY:
        req.add_header("X-Burp-Key", API_KEY)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return 200, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("utf-8", "replace")
        except Exception:
            text = json.dumps({"error": f"HTTP {e.code}"})
        if e.code == 401:
            text = json.dumps({
                "error": "AgentBridge rejected the token",
                "hint": "server.py could not read ~/.BurpSuite/agent-bridge.token. "
                        "If Burp runs as another user (for example root), set "
                        "AGENT_BRIDGE_TOKEN to the same value in Burp and in this "
                        "server's environment, or point AGENT_BRIDGE_TOKEN_FILE at the file.",
                "detail": text[:200],
            })
        return e.code, text
    except Exception as e:
        return 0, json.dumps({
            "error": f"cannot reach AgentBridge at {BRIDGE_URL}: {e}",
            "hint": "Is Burp Suite Pro running with ext/agent-bridge-v2.jar loaded?",
        })


def call_tool(name, args):
    a = args or {}

    def reqmap_body():
        # Pass the full argument dict through; endpoints like batch-send need
        # the raw "requests" array; fixed whitelists silently drop keys.
        passthrough = {}
        for k, v in a.items():
            if v is not None:
                passthrough[k] = v
        return json.dumps(passthrough)

    if name == "health":
        return bridge_call("GET", "/health", timeout=10)
    if name == "extension_info":
        return bridge_call("GET", "/api/extension/info", timeout=10)
    if name == "bridge_meta":
        return bridge_call("GET", "/api/bridge/meta", timeout=10)
    if name == "version":
        return bridge_call("GET", "/api/version")
    if name == "sitemap_list":
        params = {"prefix": a.get("prefix", ""), "limit": a.get("limit", 300)}
        return bridge_call("GET", "/api/sitemap", params)
    if name == "sitemap_add":
        return bridge_call("POST", "/api/sitemap/add", body=reqmap_body())
    if name == "issues_list":
        params = {"prefix": a.get("prefix", ""), "severity": a.get("severity", ""),
                  "limit": a.get("limit", 0), "offset": a.get("offset", 0),
                  "meta": "1" if a.get("meta") else ""}
        return bridge_call("GET", "/api/issues", params)
    if name == "scope_check":
        return bridge_call("GET", "/api/scope/check", {"url": a.get("url", "")})
    if name == "scope_set":
        body = {"include": a.get("include", []), "exclude": a.get("exclude", [])}
        return bridge_call("POST", "/api/scope/add", body=json.dumps(body))
    if name == "proxy_history":
        params = {"limit": a.get("limit", 100), "offset": a.get("offset", 0),
                  "contains": a.get("contains", ""), "regex": a.get("regex", ""),
                  "meta": "1" if a.get("meta") else ""}
        return bridge_call("GET", "/api/proxy/history", params)
    if name == "ws_history":
        params = {"limit": a.get("limit", 100), "offset": a.get("offset", 0),
                  "contains": a.get("contains", ""), "regex": a.get("regex", ""),
                  "meta": "1" if a.get("meta") else ""}
        return bridge_call("GET", "/api/proxy/ws-history", params)
    if name == "intercept_state":
        return bridge_call("GET", "/api/proxy/intercept/state")
    if name == "intercept_enable":
        return bridge_call("GET", "/api/proxy/intercept/enable")
    if name == "intercept_disable":
        return bridge_call("GET", "/api/proxy/intercept/disable")
    if name == "repeater_send":
        return bridge_call("POST", "/api/repeater/send", body=reqmap_body())
    if name == "intruder_send":
        return bridge_call("POST", "/api/intruder/send", body=reqmap_body())
    if name == "http_send":
        return bridge_call("POST", "/api/http/send", body=reqmap_body(), timeout=180)
    if name == "http_batch_send":
        return bridge_call("POST", "/api/http/batch-send", body=reqmap_body(), timeout=600)
    if name == "scan_start":
        return bridge_call("POST", "/api/scan/start", body=reqmap_body())
    if name == "scan_status":
        return bridge_call("GET", "/api/scan/status")
    if name == "scan_issues":
        return bridge_call("GET", "/api/scan/issues", {"auditId": a.get("auditId", -1)})
    if name == "scan_delete":
        return bridge_call("GET", "/api/scan/delete", {"auditId": a.get("auditId", -1)})
    if name == "collaborator_payload":
        return bridge_call("GET", "/api/collaborator/payload")
    if name == "collaborator_interactions":
        return bridge_call("GET", "/api/collaborator/interactions")
    if name == "organizer_send":
        return bridge_call("POST", "/api/organizer/send", body=reqmap_body())
    if name == "organizer_items":
        return bridge_call("GET", "/api/organizer/items",
                           {"limit": a.get("limit", 50), "offset": a.get("offset", 0),
                            "contains": a.get("contains", ""), "regex": a.get("regex", ""),
                            "meta": "1" if a.get("meta") else ""})
    if name == "bambda_import":
        raw = a.get("script")
        body = json.dumps({"script": raw})
        return bridge_call("POST", "/api/bambda/import", body=body)
    if name == "ai_status":
        return bridge_call("GET", "/api/ai/status")
    if name == "ai_prompt":
        msgs = a.get("messages") or ([a.get("prompt")] if a.get("prompt") else [])
        return bridge_call("POST", "/api/ai/prompt", body=json.dumps({"messages": msgs}), timeout=300)
    if name == "settings_export_user":
        return bridge_call("GET", "/api/settings/export/user",
                           {"path": a.get("path", ""),
                            "redact": "false" if a.get("redact") is False else "true"})
    if name == "settings_export_project":
        return bridge_call("GET", "/api/settings/export/project",
                           {"path": a.get("path", ""),
                            "redact": "false" if a.get("redact") is False else "true"})
    if name == "settings_import_user":
        return bridge_call("POST", "/api/settings/import/user", body=a.get("config", "{}"))
    if name == "settings_import_project":
        return bridge_call("POST", "/api/settings/import/project", body=a.get("config", "{}"))
    if name == "extensions_list":
        return bridge_call("GET", "/api/extensions/list")
    if name == "task_engine":
        if a.get("state"):
            body = json.dumps({"state": a.get("state"), "confirm": bool(a.get("confirm", False))})
            return bridge_call("POST", "/api/task-engine/state", body=body)
        return bridge_call("GET", "/api/task-engine")
    if name == "codec":
        body = {"op": a.get("op", "encode"), "scheme": a.get("scheme", "url"),
                "text": a.get("text", "")}
        return bridge_call("POST", "/api/codec", body=json.dumps(body))
    if name == "random_string":
        return bridge_call("GET", "/api/random",
                           {"length": a.get("length", 16), "charset": a.get("charset", "alnum")})
    if name == "audit_list":
        return bridge_call("GET", "/api/audit/log",
                           {"limit": a.get("limit", 100), "meta": "1" if a.get("meta") else ""})
    if name == "policy_info":
        return bridge_call("GET", "/api/policy")
    if name == "saved_list":
        return bridge_call("GET", "/api/saved", {"limit": a.get("limit", 100)})
    if name == "saved_get":
        return bridge_call("GET", "/api/saved/get", {"id": a.get("id", -1)})
    if name == "saved_save":
        body = {"host": a.get("host", ""), "request": a.get("request", ""),
                "note": a.get("note", "")}
        if a.get("port") is not None:
            body["port"] = a.get("port")
        if a.get("https") is not None:
            body["https"] = bool(a.get("https"))
        return bridge_call("POST", "/api/saved/save", body=json.dumps(body))
    if name == "saved_note":
        return bridge_call("POST", "/api/saved/note",
                           body=json.dumps({"id": a.get("id", -1), "note": a.get("note", "")}))
    if name == "saved_delete":
        return bridge_call("POST", "/api/saved/delete", body=json.dumps({"id": a.get("id", -1)}))
    if name == "saved_resend":
        body = {"id": a.get("id", -1), "find": a.get("find", ""), "replace": a.get("replace", "")}
        for key in ("viaProxy", "proxyPort", "http2"):
            if a.get(key) is not None:
                body[key] = a.get(key)
        return bridge_call("POST", "/api/saved/resend", body=json.dumps(body), timeout=180)
    if name == "editor_get":
        return bridge_call("GET", "/api/editor/get", timeout=15)
    if name == "editor_set":
        body = {"text": a.get("text", ""), "append": bool(a.get("append", False))}
        if a.get("caret") is not None:
            body["caret"] = a.get("caret")
        return bridge_call("POST", "/api/editor/set", body=json.dumps(body), timeout=30)
    if name == "shutdown":
        return bridge_call("POST", "/api/burp/shutdown", body=json.dumps({"confirm": bool(a.get("confirm", False))}))
    if name == "script_run":
        return bridge_call("POST", "/api/script/run", body=json.dumps(
            {"script": a.get("script", ""), "args": a.get("args", {})}), timeout=300)

    return (404, json.dumps({"error": f"unknown tool {name}"}))


TOOLS = [
    ("health", "Check that Burp + AgentBridge are alive.",
     {}, lambda: None),
    ("extension_info", "Info about the AgentBridge extension loaded in Burp.", {}, None),
    ("bridge_meta", "AgentBridge version and endpoint inventory.", {}, None),
    ("version", "Burp Suite version and command line args.", {}, None),
    ("sitemap_list", "List Burp site map entries (URL, method, status).",
     {"type": "object", "properties": {
         "prefix": {"type": "string", "description": "URL prefix filter"},
         "limit": {"type": "integer", "default": 300}}}, None),
    ("sitemap_add", "Send an HTTP request through Burp (upstream proxies/session rules applied) and add the result to the site map.",
     {"type": "object", "properties": {
         "host": {"type": "string"}, "port": {"type": "integer"},
         "https": {"type": "boolean"}, "request": {"type": "string", "description": "Raw HTTP request"}}, "required": ["host", "request"]}, None),
    ("issues_list", "List all audit issues (optionally by URL prefix and severity). limit/offset/meta page the result.",
     {"type": "object", "properties": {"prefix": {"type": "string"},
                                      "severity": {"type": "string", "enum": ["High", "Medium", "Low", "Info"]},
                                      "limit": {"type": "integer", "default": 0},
                                      "offset": {"type": "integer", "default": 0},
                                      "meta": {"type": "boolean", "default": False}}}, None),
    ("scope_check", "Check whether a URL is in Burp's target scope.",
     {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}, None),
    ("scope_set", "Add/remove URL prefixes to/from Burp's target scope.",
     {"type": "object", "properties": {"include": {"type": "array", "items": {"type": "string"}}, "exclude": {"type": "array", "items": {"type": "string"}}}}, None),
    ("proxy_history", "Burp proxy history entries (newest first, with request text). Filter with contains or a Java regex; meta=true returns total/hasMore/nextOffset.",
     {"type": "object", "properties": {"limit": {"type": "integer", "default": 100}, "offset": {"type": "integer"},
                                      "contains": {"type": "string"}, "regex": {"type": "string", "description": "Java regular expression matched against URL and request text"},
                                      "meta": {"type": "boolean", "default": False}}}, None),
    ("ws_history", "Burp proxy WebSocket message history (newest first): url, direction, payload.",
     {"type": "object", "properties": {"limit": {"type": "integer", "default": 100}, "offset": {"type": "integer"},
                                      "contains": {"type": "string"}, "regex": {"type": "string"},
                                      "meta": {"type": "boolean", "default": False}}}, None),
    ("intercept_state", "Get proxy interception state.", {}, None),
    ("intercept_enable", "Enable proxy interception.", {}, None),
    ("intercept_disable", "Disable proxy interception.", {}, None),
    ("repeater_send", "Send a raw request to a Burp Repeater tab. http2=true opens an HTTP/2 tab.",
     {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "https": {"type": "boolean"},
                                      "request": {"type": "string"}, "tabName": {"type": "string"},
                                      "http2": {"type": "boolean", "default": False}}, "required": ["host", "request"]}, None),
    ("intruder_send", "Send a raw request to Burp Intruder.",
     {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "https": {"type": "boolean"}, "request": {"type": "string"}, "tabName": {"type": "string"}}, "required": ["host", "request"]}, None),
    ("http_send", "Send an HTTP request via Burp's network stack and return the response. Set viaProxy=true to route it through Burp's proxy listener at 127.0.0.1:8080 so proxy-based extensions (for example Param Miner auto-mining) see the traffic.",
     {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "https": {"type": "boolean"}, "request": {"type": "string"}, "viaProxy": {"type": "boolean", "default": False}, "proxyPort": {"type": "integer", "default": 8080},
         "http2": {"type": "boolean", "default": False, "description": "Send as HTTP/2 (direct only; cannot be combined with viaProxy)"}}, "required": ["host", "request"]}, None),
    ("http_batch_send", "Send MANY HTTP requests in parallel through Burp (Pro task engine semantics). Set viaProxy=true to route them through Burp's proxy listener.",
     {"type": "object", "properties": {"requests": {"type": "array", "items": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "https": {"type": "boolean"}, "request": {"type": "string"}}}}, "viaProxy": {"type": "boolean", "default": False}, "proxyPort": {"type": "integer", "default": 8080}}, "required": ["requests"]}, None),
    ("scan_start", "Start an active or passive audit scan on a URL (Burp Pro).",
     {"type": "object", "properties": {"url": {"type": "string"}, "mode": {"type": "string", "enum": ["active", "passive"], "default": "active"}}, "required": ["url"]}, None),
    ("scan_status", "Status of audits started by the agent. issues is -1 when the running Burp build cannot report per-audit issue counts.", {}, None),
    ("scan_issues", "Issues reported by an agent-started audit. Falls back to site map issues under the audit URL when the running Burp build has no per-audit issue access.",
     {"type": "object", "properties": {"auditId": {"type": "integer"}}, "required": ["auditId"]}, None),
    ("scan_delete", "Delete an audit task.", {"type": "object", "properties": {"auditId": {"type": "integer"}}, "required": ["auditId"]}, None),
    ("collaborator_payload", "Generate a Burp Collaborator payload (Pro).", {}, None),
    ("collaborator_interactions", "List Collaborator interactions for the bridge client (Pro).", {}, None),
    ("organizer_send", "Send a request to Burp Organizer.",
     {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "https": {"type": "boolean"}, "request": {"type": "string"}}, "required": ["host", "request"]}, None),
    ("organizer_items", "List Organizer items, filtered with contains or regex; meta=true returns pagination.",
     {"type": "object", "properties": {"limit": {"type": "integer", "default": 50},
                                      "offset": {"type": "integer", "default": 0},
                                      "contains": {"type": "string"}, "regex": {"type": "string"},
                                      "meta": {"type": "boolean", "default": False}}}, None),
    ("bambda_import", "Import a Bambda (Java filter script) into Burp's bambda library.",
     {"type": "object", "properties": {"script": {"type": "string"}}, "required": ["script"]}, None),
    ("ai_status", "Whether Burp AI (Pro) is enabled for this extension.", {}, None),
    ("ai_prompt", "Ask Burp AI (Pro) a question (uses Burp AI credits).",
     {"type": "object", "properties": {"messages": {"type": "array", "items": {"type": "string"}}, "prompt": {"type": "string"}}}, None),
    ("settings_export_user", "Export Burp user settings as a JSON object (optionally only the given section paths, comma-separated). Credential-looking keys are masked unless redact=false.",
     {"type": "object", "properties": {"path": {"type": "string", "description": "e.g. user_options.extender"},
                                      "redact": {"type": "boolean", "default": True}}}, None),
    ("settings_export_project", "Export Burp project settings as a JSON object. Credential-looking keys are masked unless redact=false.",
     {"type": "object", "properties": {"path": {"type": "string"},
                                      "redact": {"type": "boolean", "default": True}}}, None),
    ("settings_import_user", "Import user settings JSON (partial ok). Returns changed:false when Burp ignored the payload (unknown, read-only or unchanged keys).",
     {"type": "object", "properties": {"config": {"type": "string"}}, "required": ["config"]}, None),
    ("settings_import_project", "Import project settings JSON (partial ok). Returns changed:false when Burp ignored the payload (unknown, read-only or unchanged keys).",
     {"type": "object", "properties": {"config": {"type": "string"}}, "required": ["config"]}, None),
    ("extensions_list", "List extensions registered with Burp (read-only; install/remove/toggle are intentionally not exposed).", {}, None),
    ("task_engine", "Read or set Burp's task execution engine state. Setting PAUSED or RUNNING requires confirm=true and pauses all Burp tasks globally.",
     {"type": "object", "properties": {"state": {"type": "string", "enum": ["RUNNING", "PAUSED"]},
                                      "confirm": {"type": "boolean", "default": False}}}, None),
    ("codec", "Encode or decode text. Schemes: url, base64, base64url, hex.",
     {"type": "object", "properties": {"op": {"type": "string", "enum": ["encode", "decode"], "default": "encode"},
                                      "scheme": {"type": "string", "enum": ["url", "base64", "base64url", "hex"], "default": "url"},
                                      "text": {"type": "string"}}, "required": ["text"]}, None),
    ("random_string", "Generate a cryptographically random string (SecureRandom).",
     {"type": "object", "properties": {"length": {"type": "integer", "default": 16},
                                      "charset": {"type": "string", "enum": ["alnum", "alpha", "digits", "hex"], "default": "alnum"}}}, None),
    ("audit_list", "Recent bridge calls (time, method, path, target, HTTP code, duration). Newest last.",
     {"type": "object", "properties": {"limit": {"type": "integer", "default": 100},
                                      "meta": {"type": "boolean", "default": False}}}, None),
    ("policy_info", "Effective host policy: allowlist, prompt, or open, plus allowed hosts and token requirement.", {}, None),
    ("saved_list", "Saved requests (id, method, url, note, time) captured from the context menu or saved by the agent. Newest first.",
     {"type": "object", "properties": {"limit": {"type": "integer", "default": 100}}}, None),
    ("saved_get", "Full saved request including raw HTTP text.",
     {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}, None),
    ("saved_save", "Save a request for later replay. In Burp, right-click a request and choose 'Send to AgentBridge saved requests'.",
     {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"},
                                      "https": {"type": "boolean"}, "request": {"type": "string"},
                                      "note": {"type": "string"}}, "required": ["host", "request"]}, None),
    ("saved_note", "Attach or replace a note on a saved request.",
     {"type": "object", "properties": {"id": {"type": "integer"}, "note": {"type": "string"}},
      "required": ["id", "note"]}, None),
    ("saved_delete", "Delete a saved request.",
     {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}, None),
    ("saved_resend", "Replay a saved request, optionally replacing text (find/replace) and choosing proxy or HTTP/2.",
     {"type": "object", "properties": {"id": {"type": "integer"}, "find": {"type": "string"},
                                      "replace": {"type": "string"}, "viaProxy": {"type": "boolean"},
                                      "proxyPort": {"type": "integer"}, "http2": {"type": "boolean"}},
      "required": ["id"]}, None),
    ("editor_get", "Read the Burp message editor that currently has keyboard focus (text, caret, selection).",
     {}, None),
    ("editor_set", "Replace or append text in the focused Burp message editor. Returns the previous length.",
     {"type": "object", "properties": {"text": {"type": "string"}, "append": {"type": "boolean", "default": False},
                                      "caret": {"type": "integer"}}, "required": ["text"]}, None),
    ("shutdown", " Shut down Burp programmatically (needs confirm=true; only when the user asks).",
     {"type": "object", "properties": {"confirm": {"type": "boolean"}}}, None),
    ("script_run", "Run sandboxed JavaScript (Rhino/ES6) inside Burp. The last expression is the result; a top-level 'return' is rejected. Globals: args, argsJson, bridge (API calls as string-in/string-out methods, e.g. bridge.httpSend(host,port,https,request), bridge.sitemapList(prefix,limit)), console (console.log buffers; console.flush() returns and clears the buffer). No Java package or class access.",
     {"type": "object", "properties": {"script": {"type": "string"}, "args": {"type": "object"}}, "required": ["script"]}, None),
]


def tool_catalog():
    out = []
    for name, desc, schema, _ in TOOLS:
        out.append({"name": name, "description": desc, "inputSchema": schema or {"type": "object"}})
    return out


def handle(req):
    method = req.get("method")
    msg_id = req.get("id")

    # JSON-RPC notifications carry no id and must never be answered.
    if method is not None and method.startswith("notifications/"):
        return None

    result = handle_request(method, req, msg_id)
    return result


def handle_request(method, req, msg_id):
    if method == "initialize":
        params = req.get("params") or {}
        requested = params.get("protocolVersion") or PROTOCOL_VERSION
        negotiated = requested if requested in KNOWN_PROTOCOLS else PROTOCOL_VERSION
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "burp-agent-bridge", "version": SERVER_VERSION},
            "instructions": ("Drive Burp Suite Pro through the AgentBridge extension. "
                             "Read-only tools first (health, sitemap_list, issues_list, proxy_history); "
                             "mutating calls (scope_set, intercept, scans, sends, settings) act on real Burp "
                             "state. Extensions are installed by the user in Burp; extensions_list is read-only."),
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tool_catalog()}}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        raw_code, raw_text = call_tool(name, params.get("arguments") or {})
        data = json_dumps_safe(raw_text)
        summary = build_summary(name, data)
        failed = raw_code != 200 or (isinstance(data, dict) and "error" in data)
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "content": [{"type": "text", "text": summary}],
            "isError": failed,
        }}
    if method is None:
        return None
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def json_dumps_safe(text):
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text}


def build_summary(tool, data):
    if isinstance(data, dict) and data.get("error"):
        extra = {k: v for k, v in data.items() if k != "error"}
        head = "error: " + str(data["error"])
        if extra:
            head += "\n" + json.dumps(extra, indent=2)
        return head
    if tool == "sitemap_list":
        items = data if isinstance(data, list) else []
        return f"sitemap entries: {len(items)}\n" + json.dumps(items, indent=1)
    if tool == "issues_list":
        if isinstance(data, dict) and "items" in data:
            return (f"issues: {data.get('total', 0)} total, {data.get('count', 0)} shown\n"
                    + json.dumps(data, indent=1))
        items = data if isinstance(data, list) else []
        return f"issues: {len(items)}\n" + json.dumps(items, indent=1)
    if tool in ("proxy_history", "ws_history"):
        if isinstance(data, dict) and "items" in data:
            return (f"history entries: {data.get('total', 0)} total, {data.get('count', 0)} shown\n"
                    + json.dumps(data, indent=1))
        items = data if isinstance(data, list) else []
        return f"history entries: {len(items)} (newest first)\n" + json.dumps(items, indent=1)
    if tool == "collaborator_interactions":
        items = data if isinstance(data, list) else []
        return f"interactions: {len(items)}\n" + json.dumps(items, indent=1)
    return json.dumps(data, indent=2)


def serve_stdio():
    out_lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="burp-tool")

    def write(resp):
        if resp is None:
            return
        payload = json.dumps(resp) + "\n"
        with out_lock:
            try:
                sys.stdout.write(payload)
                sys.stdout.flush()
            except (BrokenPipeError, ValueError):
                pass

    def run(req):
        try:
            resp = handle(req)
        except Exception as e:  # never let one bad request kill the server
            resp = {"jsonrpc": "2.0", "id": req.get("id") if isinstance(req, dict) else None,
                    "error": {"code": -32603, "message": str(e)}}
        write(resp)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if len(line) > MAX_LINE:
                write({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32600, "message": "request too large"}})
                continue
            try:
                req = json.loads(line)
            except Exception:
                write({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(req, dict):
                write({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32600, "message": "invalid request"}})
                continue
            # Tool calls can be slow (batch sends, scans): run them in parallel.
            if req.get("method") == "tools/call":
                pool.submit(run, req)
            else:
                run(req)
    finally:
        pool.shutdown(wait=True)


class McpHttpHandler(BaseHTTPRequestHandler):
    """Streamable HTTP (/mcp) plus legacy SSE (/sse + /messages) over loopback."""

    protocol_version = "HTTP/1.1"
    sessions = {}
    sessions_lock = threading.Lock()
    auth_token = ""

    def log_message(self, fmt, *args):  # keep Burp's stdout clean
        pass

    def _authorized(self):
        if not self.auth_token:
            return True
        got = self.headers.get("Authorization", "")
        if got.lower().startswith("bearer "):
            got = got[7:].strip()
        return hmac.compare_digest(got, self.auth_token)

    def _browser_guard(self):
        """Reject cross-origin and non-JSON requests so a web page cannot drive
        this loopback port with a no-preflight POST (CSRF)."""
        if self.headers.get("Origin"):
            self._json(403, {"error": "cross-origin requests are not allowed"})
            return False
        if self.command == "POST":
            ctype = (self.headers.get("Content-Type") or "").lower()
            if not ctype.startswith("application/json"):
                self._json(415, {"error": "Content-Type must be application/json"})
                return False
        return True

    def _json(self, code, obj):
        payload = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _read(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length < 0 or length > MAX_LINE:
            return None
        return self.rfile.read(length)

    def do_POST(self):
        if not self._browser_guard():
            return
        path = urllib.parse.urlparse(self.path).path
        if path not in ("/mcp", "/messages"):
            self._json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        raw = self._read()
        if raw is None:
            self._json(413, {"error": "request too large"})
            return
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}})
            return
        if not isinstance(req, dict):
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "invalid request"}})
            return
        try:
            resp = handle(req)
        except Exception as e:
            resp = {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32603, "message": str(e)}}

        if path == "/messages":
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("sessionId", [""])[0]
            with self.sessions_lock:
                sink = self.sessions.get(sid)
            if sink is None:
                self._json(404, {"error": "unknown sessionId"})
                return
            if resp is not None:
                sink.put(resp)
            self._json(202, None)
            return

        if resp is None:
            self._json(202, None)
        else:
            self._json(200, resp)

    def do_GET(self):
        if not self._browser_guard():
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/sse":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            sid = uuid.uuid4().hex
            sink = queue.Queue()
            with self.sessions_lock:
                self.sessions[sid] = sink
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(f"event: endpoint\ndata: /messages?sessionId={sid}\n\n".encode())
                self.wfile.flush()
                while True:
                    try:
                        msg = sink.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                        continue
                    self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with self.sessions_lock:
                    self.sessions.pop(sid, None)
            return
        if path == "/mcp":
            # Streamable HTTP allows a GET stream; this server is request/response only.
            self._json(405, {"error": "use POST /mcp"})
            return
        if path == "/healthz":
            self._json(200, {"ok": True, "server": SERVER_VERSION,
                             "tools": len(TOOLS), "transport": "http"})
            return
        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        self._json(204, None)


def serve_http(host, port, auth_token=""):
    if host not in ("127.0.0.1", "localhost", "::1") and not auth_token:
        print("refusing to listen on a non-loopback address without --auth-token",
              file=sys.stderr)
        return 2
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: MCP HTTP endpoint exposed on {host} with bearer auth", file=sys.stderr)
    McpHttpHandler.auth_token = auth_token or ""
    httpd = ThreadingHTTPServer((host, port), McpHttpHandler)
    httpd.daemon_threads = True
    print(f"burp-agent-bridge MCP over HTTP on http://{host}:{port}/mcp "
          f"(SSE: /sse, tools: {len(TOOLS)})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(
        description="burp-agent-bridge MCP server (stdio by default).")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio",
                        help="stdio for MCP clients that launch a process; http for Streamable HTTP + SSE")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9878)
    parser.add_argument("--auth-token", default=os.environ.get("AGENT_BRIDGE_HTTP_TOKEN", ""),
                        help="optional bearer token for the HTTP transport")
    args = parser.parse_args()
    if args.transport == "http":
        raise SystemExit(serve_http(args.host, args.port, args.auth_token))
    serve_stdio()


if __name__ == "__main__":
    main()
