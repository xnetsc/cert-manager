#!/usr/bin/env python3
"""FC custom-container entrypoint: an HTTP server whose POST /invoke
(timer trigger or manual) runs one sweep. GET /healthz for liveness.
A run lock keeps overlapping invocations from racing the state."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import sweep as sweep_mod

_lock = threading.Lock()
_last = {"status": "never run"}


def run_once():
    if not _lock.acquire(blocking=False):
        return {"status": "already running"}
    lines = []

    def _log(line):
        # Both: into the invoke response and onto stdout, where the
        # platform log service can see it.
        lines.append(line)
        print(line, flush=True)

    try:
        oss = sweep_mod.build_oss()
        failures = sweep_mod.sweep(oss, log=_log)
        _last["status"] = "\n".join(lines)
        return {"status": "done", "failures": failures, "log": lines}
    except Exception as e:
        _last["status"] = f"error: {e}"
        return {"status": "error", "error": str(e)}
    finally:
        _lock.release()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b"ok"
        else:
            body = _last["status"].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        payload = None
        if raw:
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
        if not sweep_mod.should_run(payload):
            result = {"status": "ignored",
                      "reason": "OSS event for a non-registry object"}
        else:
            result = run_once()
        body = json.dumps(result).encode()
        self.send_response(200 if result["status"] != "error" else 500)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9001), Handler).serve_forever()
