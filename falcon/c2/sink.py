"""Lab-owned beacon sink. Binds to loopback ONLY. 'Commands' are inert tokens."""
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOOPBACK = {"127.0.0.1", "localhost"}


class Sink:
    def __init__(self, host="127.0.0.1", port=8443):
        if host not in LOOPBACK:
            raise ValueError("sink may only bind to loopback")
        self.received = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.received.append({"ts": datetime.now(timezone.utc).isoformat(),
                                       "ua": self.headers.get("User-Agent"),
                                       "body": body.decode(errors="replace")[:200]})
                reply = json.dumps({"cmd": "noop", "seq": len(outer.received)}).encode()  # inert token
                self.send_response(200)
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer((host, port), H)
        self.host, self.port = host, self.server.server_address[1]
        self._t = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self._t.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
