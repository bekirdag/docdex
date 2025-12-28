#!/usr/bin/env python3
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockOllamaHandler(BaseHTTPRequestHandler):
    model_name = "fake-model"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send_json(200, {"models": [{"name": self.model_name}]})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""
        payload = {}
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                payload = {}

        if self.path == "/api/generate":
            prompt = payload.get("prompt") or "ok"
            self._send_json(200, {"response": prompt})
            return
        if self.path == "/api/embeddings":
            self._send_json(200, {"embedding": [0.1, 0.2, 0.3, 0.4]})
            return
        self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description="Mock Ollama server for docdexd E2E tests.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--model", default="fake-model")
    args = parser.parse_args()

    handler = MockOllamaHandler
    handler.model_name = args.model
    server = ThreadingHTTPServer((args.host, args.port), handler)
    host, port = server.server_address
    with open(args.port_file, "w", encoding="utf-8") as fh:
        fh.write(str(port))
        fh.flush()
    sys.stdout.write(f"mock ollama listening on http://{host}:{port}\n")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
