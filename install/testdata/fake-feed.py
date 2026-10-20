#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
fake-feed.py - the keyed feed and the control plane, faked for the install gate. Python 3 stdlib only.

It speaks what whisper-edge-refresh's keyed path depends on and nothing else: the four keyed names under
/edge/k/ (manifest.json, manifest.json.sig, tenant.bin, tenant.bin.sig), authentication before every
other check, the status map (401 with realm="whisper-edge" and a JSON code, 403 FORBIDDEN_SCOPE, 503
with Retry-After, 404 no_lists, 412 on an If-Match that is not current, 304 on the manifest's ETag),
Whisper-Node on every answer, and op:edge's key sub-ops at /api/query in the front door's envelope. It
listens on one port on several loopback addresses, one node per address, over TLS, so the refresh's
https-only rule holds in the gate exactly as in the field.

Usage:
    fake-feed.py --root DIR --port P (--cert C --key K | --plain 1) --node ADDR=HEX8 [--node ADDR=HEX8 ...]

--plain 1 serves http, for a harness that drives a gate's rows over its http override; the refresh
itself never sends a key over http, so its gate always runs the TLS form.

Everything it serves is read from DIR on each request, so the gate changes the feed between runs by
writing files:
    DIR/content/<name>/{manifest.json, manifest.json.sig, tenant.bin, tenant.bin.sig, keyless.json}
                      (keyless.json, when present, is /edge/manifest.json, served with no key)
    DIR/config.json   {"content": "<name>", "nodes": {"<addr>": {"content": .., "auth": {..}}},
                       "keys": {"<sha256 of a key>": "ok" | "KEY_REVOKED" | "KEY_EXPIRED" | ...},
                       "owners": ["<sha256 of an owner key>"],
                       "rules": [{"addr", "path", "status", "code", "times", "realm", "html",
                                  "retry_after", "preauth", "action": "reset"}],
                       "hold": {"path", "started", "release"},
                       "control": {"<addr>" | "*": "ok" | "owner_only" | "owner_only_with_result"
                                   | "bad_args" | "not_yet" | "unknown_op" | "drop"
                                   | "revoke_other_id" | "revoke_live" | "http401" | "http403"},
                       "capture": "<file in testdata/envelopes, named <what>.<status>.json>" (every
                                   control call is answered with that envelope file's bytes, a live capture or a built-* file, and status),
                       "positional_rows": true (the outer row as an array, the other shape a reader accepts),
                       per node: "switch": {"before": "<content>", "after": N} (the first N manifest
                       requests get the "before" content, then the node's own),
                       "drop_header": "<a keyed answer's header to leave out>"}
    DIR/requests.log  one JSON line per request: address, node, path, which credential arrived and
                      whether it was a known key (never the key), the conditional headers
    DIR/state.json    the fake's own state: rules consumed, keys minted and revoked
"""
import base64
import hashlib
import http.server
import json
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time

LOCK = threading.Lock()
ARGS = {}
KEYED = ("manifest.json", "manifest.json.sig", "tenant.bin", "tenant.bin.sig")


def load(name, default):
    try:
        with open(os.path.join(ARGS["root"], name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(name, value):
    p = os.path.join(ARGS["root"], name)
    with open(p + ".tmp", "w") as f:
        json.dump(value, f)
    os.replace(p + ".tmp", p)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def key_shape(k):
    return 20 <= len(k) <= 256 and not any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in k)


def b64(n):
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fake-feed"

    def log_message(self, *a):
        pass

    # -- plumbing ----------------------------------------------------------------------------------
    def addr(self):
        return self.server.server_address[0]

    def node(self):
        return ARGS["nodes"][self.addr()]

    def credential(self):
        auth = self.headers.get_all("Authorization") or []
        xk = self.headers.get_all("X-API-Key") or []
        bearer = None
        for a in auth:
            p = a.split(None, 1)
            if len(p) == 2 and p[0].lower() == "bearer":
                bearer = p[1].strip()
        key = bearer or (xk[0].strip() if xk else None)
        return key, ("bearer" if bearer else ("x-api-key" if xk else "none"))

    def record(self, extra):
        key, how = self.credential()
        cfg = load("config.json", {})
        st = load("state.json", {})
        known = set(cfg.get("keys", {})) | set(st.get("keys", {})) | set(cfg.get("owners", []))
        line = {"t": time.time(), "addr": self.addr(), "node": self.node(), "method": self.command,
                "path": self.path, "auth": how, "known_key": bool(key and sha(key.encode()) in known),
                "if_match": self.headers.get("If-Match"), "if_none_match": self.headers.get("If-None-Match"),
                "pairing": self.headers.get("Whisper-Edge-Plane")}
        line.update(extra)
        with open(os.path.join(ARGS["root"], "requests.log"), "a") as f:
            f.write(json.dumps(line) + "\n")

    def send(self, status, body=b"", headers=None, ctype="application/json"):
        self.send_response(status)
        self.send_header("Whisper-Node", self.node())
        if self.path.startswith("/edge/k/"):
            # every keyed answer: never stored by a shared cache, never readable cross-origin
            drop = load("config.json", {}).get("drop_header")
            for k, v in (("Vary", "Authorization, X-API-Key, Accept-Encoding"),
                         ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")):
                if k != drop:
                    self.send_header(k, v)
        if status >= 300:
            self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if body or status not in (204, 304):
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def flood(self, n):
        """A 200 with no Content-Length (delimited by the close), n bytes of it: the size a client cannot know
        before it reads, which curl before 8.4.0 does not cap with --max-filesize. Logs the bytes the client took."""
        self.close_connection = True
        self.send_response(200)
        self.send_header("Whisper-Node", self.node())
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        sent, chunk = 0, b"x" * 65536
        try:
            while sent < n:
                k = min(len(chunk), n - sent)
                self.wfile.write(chunk[:k])
                sent += k
            self.wfile.flush()
        except OSError:
            pass
        self.record({"flood_sent": sent})

    def refuse(self, status, code, realm=True, error=None, retry_after=None, html=False):
        h = {}
        if realm:
            h["WWW-Authenticate"] = 'Bearer realm="whisper-edge"' + (', error="%s"' % error if error else "")
        if retry_after:
            h["Retry-After"] = str(retry_after)
        if html:
            return self.send(status, b"<html><body>blocked by the proxy</body></html>", h, "text/html")
        self.send(status, json.dumps({"code": code}).encode(), h)

    def reset(self):
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.close_connection = True
        try:
            self.connection.close()
        except OSError:
            pass

    def rule(self, name, preauth):
        """The first rule that matches this request, consumed when it has a count."""
        with LOCK:
            cfg = load("config.json", {})
            st = load("state.json", {})
            used = st.setdefault("used", {})
            for i, r in enumerate(cfg.get("rules", [])):
                if bool(r.get("preauth")) != preauth:
                    continue
                if r.get("addr", "*") not in ("*", self.addr()) or r.get("path", "*") not in ("*", name):
                    continue
                times = r.get("times")
                if times is not None and used.get(str(i), 0) >= times:
                    continue
                used[str(i)] = used.get(str(i), 0) + 1
                save("state.json", st)
                return r
        return None

    def apply(self, r):
        if r.get("action") == "reset":
            return self.reset()
        if r.get("action") == "flood":
            return self.flood(int(r.get("bytes", 8 << 20)))
        self.refuse(r["status"], r.get("code", "busy"), realm=r.get("realm", False),
                    error=r.get("error"), retry_after=r.get("retry_after"), html=r.get("html", False))

    # -- the keyed feed ----------------------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/edge/manifest.json":
            self.record({})
            cfg = load("config.json", {})
            ncfg = cfg.get("nodes", {}).get(self.addr(), {})
            cname = ncfg.get("content") or cfg.get("content", "a")
            sw = ncfg.get("switch")
            if sw:
                st = load("state.json", {})
                cname = sw["before"] if st.get("switch_seen", {}).get(self.addr(), 0) < sw["after"] else cname
            p = os.path.join(ARGS["root"], "content", cname, "keyless.json")
            if not os.path.exists(p):
                return self.send(404, b"not found\n", ctype="text/plain")
            return self.send(200, open(p, "rb").read(), {"Cache-Control": "no-cache"})
        if not path.startswith("/edge/k/"):
            self.record({})
            return self.send(404, b"not found\n", ctype="text/plain")
        name = path[len("/edge/k/"):]
        self.record({})
        r = self.rule(name, True)
        if r:
            return self.apply(r)
        cfg = load("config.json", {})
        st = load("state.json", {})
        ncfg = cfg.get("nodes", {}).get(self.addr(), {})
        key, _ = self.credential()
        if key is None:
            return self.refuse(401, "key_required")
        if not key_shape(key):
            return self.refuse(401, "malformed_key", error="invalid_token")
        ks = sha(key.encode())
        state = ncfg.get("auth", {}).get(ks) or st.get("keys", {}).get(ks) or cfg.get("keys", {}).get(ks)
        state = ncfg.get("auth_all") or state
        if state is None:
            return self.refuse(401, "invalid_token", error="invalid_token")
        if state in ("KEY_REVOKED", "KEY_EXPIRED", "invalid_token"):
            return self.refuse(401, state, error="invalid_token")
        if state == "FORBIDDEN_SCOPE":
            return self.refuse(403, state, error="insufficient_scope")
        if state in ("auth_unavailable", "auth_inconsistent"):
            return self.refuse(503, state, realm=False, retry_after=30)
        r = self.rule(name, False)
        if r:
            return self.apply(r)
        if name not in KEYED:
            return self.send(404, b"", ctype="text/plain")
        hold = cfg.get("hold")
        if hold and hold.get("path") == name and not st.get("held"):
            with LOCK:
                st = load("state.json", {})
                st["held"] = True
                save("state.json", st)
            with open(hold["started"], "w") as f:
                f.write("stalled\n")
            with open(hold["release"]) as f:
                f.read()
        cname = ncfg.get("content") or cfg.get("content", "a")
        sw = ncfg.get("switch")
        if sw and name == "manifest.json":
            # a deterministic convergence: the first N manifest requests to this node get the old content
            with LOCK:
                st = load("state.json", {})
                seen = st.setdefault("switch_seen", {})
                seen[self.addr()] = seen.get(self.addr(), 0) + 1
                save("state.json", st)
            cname = sw["before"] if seen[self.addr()] <= sw["after"] else cname
            with LOCK:
                st = load("state.json", {})
                st.setdefault("switch_content", {})[self.addr()] = cname
                save("state.json", st)
        elif sw:
            cname = load("state.json", {}).get("switch_content", {}).get(self.addr(), cname)
        content = os.path.join(ARGS["root"], "content", cname)
        try:
            manifest = open(os.path.join(content, "manifest.json"), "rb").read()
        except OSError:
            return self.refuse(503, "tenant_unavailable", realm=False, retry_after=60)
        msha = sha(manifest)
        plane = None
        try:
            plane = open(os.path.join(content, "tenant.bin"), "rb").read()
        except OSError:
            pass
        if name.startswith("tenant.bin") and plane is None:
            return self.send(404, json.dumps({"code": "no_lists"}).encode())
        # The feed responder's pairing rules, which the real feed implements: a signature's ETag is the
        # signed revision's sha, a dot and 16 hex of the signature bytes' own digest; If-Match is strict
        # on every name (only the selected representation's own tag, or *, matches); a signature is
        # paired with its revision by
        # Whisper-Edge-Plane, quoted or bare, and a mismatch is 412 with a body saying so.
        current = msha if name.startswith("manifest") else sha(plane)
        body = open(os.path.join(content, name), "rb").read()
        signature = name.endswith(".sig")
        etag = '"%s.%s"' % (current, sha(body)[:16]) if signature else '"%s"' % current
        pairing = self.headers.get("Whisper-Edge-Plane") if signature else None
        if pairing is not None and pairing.strip() not in ('"%s"' % current, current):
            return self.send(412, json.dumps({"code": "precondition_failed",
                                              "detail": "Whisper-Edge-Plane names another revision than the one"
                                                        " this signature signs; fetch the manifest again"}).encode())
        im = self.headers.get("If-Match")
        if im is not None and not any(t.strip() in ("*", etag) for t in im.split(",")):
            return self.send(412)
        inm = self.headers.get("If-None-Match")
        if name == "manifest.json" and inm is not None and inm.strip() == etag:
            return self.send(304, headers={"ETag": etag, "Cache-Control": "private, no-cache"})
        self.send(200, body, {"ETag": etag, "Cache-Control": "private, no-cache"},
                  "application/octet-stream" if not name.endswith(".json") else "application/json")

    # -- the control plane -------------------------------------------------------------------------
    def envelope(self, ok, result=None, error=None, status=200):
        # the front door's grammar, as its result writer writes it and a live call returns it: the outer
        # row is an OBJECT keyed by column, the inner result rows are positional arrays
        cols = ["op", "ok", "status", "result", "error", "retry_after", "elapsed_ms"]
        row = dict(zip(cols, ["edge", ok, status, result, error, None, 1]))
        if load("config.json", {}).get("positional_rows"):
            row = [row[c] for c in cols]
        body = {"columns": cols, "rows": [row], "statistics": {"rowCount": 1, "executionTimeMs": 1}}
        self.send(200, json.dumps(body, separators=(",", ":")).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
            query, p = req["query"], req["parameters"]["p"]
            op, args = p["op"], p["args"]
            sub = args.get("sub")
        except (ValueError, KeyError, TypeError, AttributeError):
            query, op, args, sub = None, None, {}, None
        self.record({"sub": sub, "label": args.get("label")})
        # the front door's own checks before any dispatch: the one Cypher call, then a known op
        if not isinstance(query, str) or not re.fullmatch(r"\s*CALL\s+whisper\.agents\(\$p\)\s*", query):
            return self.send(400, json.dumps({"error": "bad_request", "detail": "expected CALL whisper.agents($p)"}).encode())
        if op != "edge":
            return self.send(400, json.dumps({"error": "unknown_op", "detail": "unknown or unsupported op: %s" % op}).encode())
        cfg = load("config.json", {})
        ctl = cfg.get("control", {})
        mode = ctl.get(self.addr(), ctl.get("*", "ok"))
        key, _ = self.credential()
        cap = cfg.get("capture")
        if cap:
            here = os.path.dirname(os.path.abspath(__file__))
            body = open(os.path.join(here, "envelopes", os.path.basename(cap)), "rb").read()
            return self.send(int(cap.rsplit(".", 2)[-2]), body, {}, "application/json")
        if mode in ("http401", "http403"):
            # the front door's own key check, answered before any dispatch, with no typed body
            return self.send(int(mode[4:]), b"unauthorized\n", {}, "text/plain")
        if mode == "unknown_op":
            return self.send(400, json.dumps({"error": "unknown_op", "detail": "unknown or unsupported op: edge"}).encode())
        if not key or sha(key.encode()) not in cfg.get("owners", []):
            return self.envelope(False, error={"code": "ANONYMOUS_WRITE", "message": "no owner key", "retryable": False}, status=403)
        if mode == "owner_only_with_result":
            # a refusal relayed with the row it refused: only an envelope reader tells it from a mint
            cols = ["id", "api_key", "label", "created_at", "scopes", "use"]
            row = ["ag_" + b64(12), "whisper_live_" + b64(24), "-", "-", "-", "-"]
            return self.envelope(False, {"columns": cols, "rows": [row], "sensitive": ["api_key"]},
                                 {"code": "EDGE_OWNER_ONLY", "message": "edge keys are the account owner's",
                                  "retryable": False}, status=403)
        if mode == "owner_only":
            return self.envelope(False, error={"code": "EDGE_OWNER_ONLY", "message": "edge keys are the account owner's",
                                               "retryable": False}, status=403)
        if mode == "not_yet":
            return self.envelope(False, error={"code": "NOT_YET", "message": "minting is not enabled yet",
                                               "retryable": False}, status=501)
        if mode == "bad_args":
            return self.envelope(False, error={"code": "BAD_ARGS", "message": "label: 1 to 64 characters with no control character",
                                               "retryable": False}, status=400)
        with LOCK:
            st = load("state.json", {})
            keys = st.setdefault("keys", {})
            minted = st.setdefault("minted", {})
            if sub == "key":
                k = "whisper_live_" + b64(24)
                kid = "ag_" + b64(12)
                keys[sha(k.encode())] = "ok"
                minted[kid] = sha(k.encode())
                save("state.json", st)
                if mode == "drop" and not st.get("dropped"):
                    st["dropped"] = True
                    save("state.json", st)
                    return self.reset()
                cols = ["id", "api_key", "label", "created_at", "scopes", "use"]
                row = [kid, k, args.get("label") or "2026-10-12", "2026-10-12T00:00:00Z", "edge:read,ns:edge", "-"]
                return self.envelope(True, {"columns": cols, "rows": [row], "sensitive": ["api_key"]})
            if sub == "key.revoke":
                kid = args.get("id")
                if kid not in minted:
                    return self.envelope(False, error={"code": "NOT_FOUND", "message": "no such key", "retryable": False}, status=404)
                if mode == "revoke_live":
                    # an ok answer for the right id that did not revoke it
                    return self.envelope(True, {"columns": ["id", "state", "effect"], "rows": [[kid, "live", "-"]],
                                                "sensitive": []})
                keys[minted[kid]] = "KEY_REVOKED"
                save("state.json", st)
                if mode == "revoke_other_id":
                    # an ok answer naming another key: this one is revoked here, but the answer cannot say so
                    return self.envelope(True, {"columns": ["id", "state", "effect"],
                                                "rows": [["ag_" + b64(12), "revoked", "-"]], "sensitive": []})
                return self.envelope(True, {"columns": ["id", "state", "effect"], "rows": [[kid, "revoked", "-"]],
                                            "sensitive": []})
            if sub == "key.list":
                rows = [[k, "-", "-", "revoked" if keys.get(v) == "KEY_REVOKED" else "live"] for k, v in minted.items()]
                return self.envelope(True, {"columns": ["id", "label", "created_at", "state"], "rows": rows, "sensitive": []})
        self.envelope(False, error={"code": "BAD_ARGS", "message": "unknown sub-op", "retryable": False}, status=400)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv):
    nodes, i = {}, 0
    while i < len(argv):
        if argv[i] == "--node":
            a, n = argv[i + 1].split("=", 1)
            nodes[a] = n
        else:
            ARGS[argv[i][2:]] = argv[i + 1]
        i += 2
    ARGS["nodes"] = nodes
    ctx = None
    if not ARGS.get("plain"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ARGS["cert"], ARGS["key"])
    servers = []
    for a in nodes:
        s = Server((a, int(ARGS["port"])), Handler)
        if ctx:
            s.socket = ctx.wrap_socket(s.socket, server_side=True)
        servers.append(s)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    open(os.path.join(ARGS["root"], "ready"), "w").close()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(sys.argv[1:])
