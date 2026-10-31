"""A local stand-in for the directory, recording every request."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def start_server(handler):
    requests = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _serve(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode() if n else ""
            rec = {"method": self.command, "url": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body}
            requests.append(rec)
            out = handler(rec) or {}
            if out.get("delay"):
                time.sleep(out["delay"])
            status = out.get("status", 200)
            payload = out.get("body", {})
            data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            self.send_response(status)
            for k, v in out.get("headers", {"Content-Type": "application/json"}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = _serve

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def close():
        server.shutdown()
        server.server_close()

    return base, requests, close
