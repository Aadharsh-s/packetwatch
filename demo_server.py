"""Tiny web server for showing a PacketWatch block from a phone.

    python demo_server.py            # Administrator PowerShell, port 8080

Open http://<laptop-ip>:8080 on the phone. The page pings the server every
second: green while reachable, red once the phone's IP has been blocked. Runs
standard library only. Needs Administrator to open its port in Windows Firewall
for the run (the rule is removed on exit); without it, the port stays closed.
"""
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
RULE = f"PW_DemoServer_{PORT}"

PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>PacketWatch demo</title>
<body style="font-family:sans-serif;text-align:center;margin-top:20vh">
<h1 id=s>...</h1><p id=d></p>
<script>
let ok = 0;
async function ping() {
  const c = new AbortController(); setTimeout(() => c.abort(), 2000);
  try {
    await fetch('/ping?' + Date.now(), {signal: c.signal, cache: 'no-store'});
    ok = Date.now(); document.body.style.background = '#c8f7c5';
    s.textContent = 'REACHABLE'; d.textContent = 'server answered ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.body.style.background = '#f7c5c5';
    s.textContent = 'BLOCKED'; d.textContent = ok ? 'last reached ' + new Date(ok).toLocaleTimeString() : 'never reached';
  }
}
setInterval(ping, 1000); ping();
</script>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok" if self.path.startswith("/ping") else PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain" if body == b"ok" else "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if body != b"ok":
            print(f"{time.strftime('%H:%M:%S')} page served to {self.client_address[0]}", flush=True)

    def log_message(self, *args):
        pass


def firewall(*args):
    return subprocess.run(["netsh", "advfirewall", "firewall", *args],
                          capture_output=True, text=True).returncode == 0


if __name__ == "__main__":
    opened = firewall("add", "rule", f"name={RULE}", "dir=in", "action=allow",
                      "protocol=TCP", f"localport={PORT}")
    print(f"Serving on port {PORT}. " + ("Firewall port opened." if opened else
          "Could not open the firewall port (run as Administrator)."), flush=True)
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if opened:
            firewall("delete", "rule", f"name={RULE}")
            print("Firewall port closed.")
