#!/usr/bin/env python3
"""Preflight check and client-config helper for burp-agent-bridge.

Run this before registering the MCP server. It verifies that Burp has the
extension loaded, that the token is readable, and that the bridge answers.

    python3 doctor.py
    python3 doctor.py --url http://127.0.0.1:9877
"""
import argparse
import json
import os
import shutil
import sys
import urllib.error
import urllib.request

OK = "\033[32mok\033[0m"
WARN = "\033[33mwarn\033[0m"
FAIL = "\033[31mfail\033[0m"


def token_candidates():
    out = []
    if os.environ.get("AGENT_BRIDGE_TOKEN"):
        out.append(("AGENT_BRIDGE_TOKEN", os.environ["AGENT_BRIDGE_TOKEN"].strip()))
    if os.environ.get("AGENT_BRIDGE_TOKEN_FILE"):
        out.append((os.environ["AGENT_BRIDGE_TOKEN_FILE"],
                    _read(os.environ["AGENT_BRIDGE_TOKEN_FILE"])))
    path = os.path.expanduser("~/.BurpSuite/agent-bridge.token")
    out.append((path, _read(path)))
    return [(name, value) for name, value in out if value]


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def call(url, path, token):
    req = urllib.request.Request(url + path, headers={"Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("BURP_BRIDGE_URL", "http://127.0.0.1:9877"))
    args = parser.parse_args()
    failures = 0

    print(f"burp-agent-bridge doctor  ({args.url})")
    print()

    tokens = token_candidates()
    if tokens:
        name, token = tokens[0]
        print(f"[{OK}] token found via {name} ({len(token)} chars)")
    else:
        print(f"[{FAIL}] no token. Start Burp with the extension loaded; it writes")
        print("       ~/.BurpSuite/agent-bridge.token. If Burp runs as another user,")
        print("       set AGENT_BRIDGE_TOKEN in both environments.")
        return 2

    try:
        health = call(args.url, "/health", token)
        print(f"[{OK}] bridge reachable: {health.get('extension')} {health.get('version')}")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            print(f"[{FAIL}] bridge rejected the token.")
            print("       Burp and this shell see different token files. Set AGENT_BRIDGE_TOKEN")
            print("       to one value in Burp's environment and in this shell, then retry.")
        else:
            print(f"[{FAIL}] /health returned HTTP {exc.code}")
        return 2
    except Exception as exc:
        print(f"[{FAIL}] cannot reach the bridge: {exc}")
        print("       Is Burp running with ext/agent-bridge-v2.jar loaded? Port 9877 must be free.")
        return 2

    try:
        meta = call(args.url, "/api/bridge/meta", token)
        print(f"[{OK}] {meta.get('endpoints')} endpoints, policy={meta.get('policy')}, "
              f"http2={meta.get('http2')}, websockets={meta.get('webSockets')}, "
              f"editor={meta.get('editorTools')}, contextMenu={meta.get('contextMenu')}")
    except Exception as exc:
        print(f"[{WARN}] meta unavailable: {exc}")

    try:
        policy = call(args.url, "/api/policy", token)
        print(f"[{OK}] token enforced={policy.get('tokenRequired')}, "
              f"allow hosts={policy.get('allowHosts') or '[]'}")
    except Exception as exc:
        print(f"[{WARN}] policy unavailable: {exc}")

    try:
        tools = call(args.url, "/api/extension/info", token)
        print(f"[{OK}] extension file: {tools.get('file')}")
    except Exception:
        pass

    target = shutil.which("python3") or sys.executable
    server = os.path.abspath(os.path.join(os.path.dirname(__file__), "src", "server.py"))
    print()
    print("Register this server with your MCP client:")
    print()
    print("  OpenCode  (~/.config/opencode/opencode.json)")
    print(json.dumps({"mcp": {"servers": {"burp": {"type": "local",
                                                "command": [target, server]}}}}, indent=2))
    print()
    print("  Claude Code")
    print(f"    claude mcp add burp -- {target} {server}")
    print()
    print("  HTTP clients (Streamable HTTP + SSE)")
    print(f"    {target} {server} --transport http --port 9878")
    print("    endpoint: http://127.0.0.1:9878/mcp   (legacy SSE: /sse)")
    print()
    if failures:
        return 1
    print("Ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
