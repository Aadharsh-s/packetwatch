"""Optional local dashboard for a running PacketWatch (--dashboard).

Three constraints shape this module, and all three come from the rest of the
system rather than from the web page:

* **Memory stays bounded.** Everything the dashboard remembers lives in a
  fixed-length deque. A dashboard that accumulated history would quietly undo
  the one guarantee BENCHMARK.md makes about running under attack.
* **The capture path is not touched.** Nothing here runs per packet. Decisions
  arrive through two cheap callbacks on the once-a-second sweep, packets/sec is
  sampled by this module's own thread from a counter the pipeline already
  keeps, and the per-source table is built only when it is asked for.
* **It is not reachable from the network.** The server binds to loopback, the
  Host header is checked, and the two routes that change state need a header
  that a cross-origin page cannot set. A dashboard that can lift a block is a
  control surface, not a report, and is treated as one.
"""
import functools
import ipaddress
import json
import logging
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import config
from .features import FEATURE_NAMES
from .verify import nearest_rule

log = logging.getLogger("packetwatch.dashboard")

PAGE = Path(__file__).resolve().parent / "dashboard.html"

# A cross-origin page can send a form POST, but it cannot set a custom header
# without a CORS preflight, which this server never approves. Requiring one on
# every state-changing route is what stops a web page the user happens to have
# open from unblocking an attacker on their behalf.
CONTROL_HEADER = "X-PacketWatch-Control"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class DashboardState:
    """Bounded record of what the pipeline has decided, and the snapshot API."""

    def __init__(self, pipeline, blocker, iface=None, dry_run=False,
                 clock=time.time):
        self.pipeline = pipeline
        self.blocker = blocker
        self.iface = iface
        self.dry_run = dry_run
        self.clock = clock
        self.started = clock()
        self.alerts = deque(maxlen=config.DASHBOARD_ALERTS)
        self.unverified = deque(maxlen=config.DASHBOARD_UNVERIFIED)
        self.traffic = deque(maxlen=config.DASHBOARD_TRAFFIC_SAMPLES)
        self._lock = threading.Lock()
        self._last_packets = 0
        self._last_sample = self.started

    # --- observer interface, called from Pipeline.evaluate -----------------

    def on_alert(self, record):
        if record:
            with self._lock:
                self.alerts.appendleft(record)

    def on_unverified(self, src, vec, ml):
        """A source the classifiers flagged that no rule confirmed.

        This is the verification layer declining to act, so the dashboard shows
        what the source was short of rather than just that it was ignored.
        """
        with self._lock:
            self.unverified.appendleft({
                "time": self.clock(),
                "ip": src,
                "dt": ml["dt"], "nb": ml["nb"],
                "dt_proba": ml["dt_proba"], "nb_proba": ml["nb_proba"],
                "features": dict(zip(FEATURE_NAMES, vec)),
                "closest": nearest_rule(vec),
            })

    # --- sampled by our own thread, not by the packet handler --------------

    def sample(self):
        """One packets/sec reading, from a counter the pipeline already keeps."""
        now = self.clock()
        total = self.pipeline.stats["packets"]
        elapsed = max(1e-6, now - self._last_sample)
        pps = max(0, total - self._last_packets) / elapsed
        self._last_packets, self._last_sample = total, now
        with self._lock:
            self.traffic.append({"t": round(now, 2), "pps": round(pps, 1)})

    # --- assembled on request ----------------------------------------------

    def _reason_for(self, ip):
        """The most recent alert explaining why this address is blocked."""
        for record in self.alerts:
            if record.get("src_ip") == ip:
                return {"severity": record.get("severity"),
                        "trigger": record.get("trigger"),
                        "explanation": record.get("explanation", [])}
        return None

    def snapshot(self):
        now = self.clock()
        stats = dict(self.pipeline.stats)
        with self._lock:
            alerts = list(self.alerts)[:50]
            unverified = list(self.unverified)[:25]
            traffic = list(self.traffic)
            pps = traffic[-1]["pps"] if traffic else 0.0
        blocks = self.blocker.blocks()
        for row in blocks:
            row["reason"] = self._reason_for(row["ip"])
        sources = self.pipeline.snapshot_sources()
        return {
            "now": now,
            "status": {
                "iface": self.iface or "default",
                "uptime": round(now - self.started, 1),
                "dry_run": self.dry_run,
                "packets": stats["packets"],
                "pps": pps,
                "active_sources": len(sources),
                "evicted": self.pipeline.evicted,
                "blocked_count": len(blocks),
                "ttl_min": self.blocker.ttl_min,
                "protected": sorted(self.pipeline.own),
                "thresholds": {
                    "port_scan": config.PORT_SCAN_THRESHOLD,
                    "flood_pps": config.FLOOD_PPS_THRESHOLD,
                    "suspicious_port": config.SUSPICIOUS_PORT_THRESHOLD,
                    "calibrated": bool(config.CALIBRATED),
                },
            },
            # The funnel counts judgements, not unique hosts: one source judged
            # in ten consecutive sweeps is ten windows. Naming it that way keeps
            # the panel honest against the [stats] line the terminal prints.
            "funnel": {
                "judged": stats["judged"],
                "ml_flagged": stats["ml_flagged"],
                "unverified": stats["unverified"],
                "confirmed": stats["confirmed"],
                "rules_only": stats["rule_triggered"],
                "risk_escalated": stats["risk_escalated"],
            },
            "blocks": blocks,
            "alerts": alerts,
            "unverified": unverified,
            "traffic": traffic,
            "sources": sources,
        }


class _Handler(BaseHTTPRequestHandler):
    server_version = "PacketWatch"
    protocol_version = "HTTP/1.1"

    def __init__(self, state, *args, **kwargs):
        self.state = state
        super().__init__(*args, **kwargs)

    def log_message(self, fmt, *args):
        """Per-request logging would bury the alert output this shares a terminal with."""
        log.debug("%s - %s", self.address_string(), fmt % args)

    # --- helpers -----------------------------------------------------------

    def _local_host(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host in LOCAL_HOSTS

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, payload):
        self._send(code, json.dumps(payload), "application/json")

    def _drain(self):
        """Read the whole request body, whatever we intend to do with it.

        On a keep-alive connection an unread body is still sitting in the socket
        when the response is written, and the connection is then torn down mid
        reply - which Windows surfaces to the client as an aborted connection
        rather than as the 403 it was actually sent. So the body is consumed
        first and the routing decisions are made afterwards.
        """
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n > 0 else b""
        except (ValueError, OSError):
            return b""

    @staticmethod
    def _parse(raw):
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    # --- routes ------------------------------------------------------------

    def do_GET(self):
        if not self._local_host():
            return self._json(403, {"error": "loopback only"})
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            except OSError as exc:
                return self._send(500, f"dashboard.html missing: {exc}", "text/plain")
        if path == "/api/status":
            try:
                return self._json(200, self.state.snapshot())
            except Exception:
                log.exception("snapshot failed")
                return self._json(500, {"error": "snapshot failed"})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        raw = self._drain()
        if not self._local_host():
            return self._json(403, {"error": "loopback only"})
        if self.headers.get(CONTROL_HEADER) is None:
            # Not a CSRF nicety: without this, any page in the user's browser
            # could lift a block on a host PacketWatch had just stopped.
            return self._json(403, {"error": f"missing {CONTROL_HEADER} header"})
        path = self.path.split("?", 1)[0]
        if path == "/api/unblock":
            ip = str(self._parse(raw).get("ip", ""))
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                return self._json(400, {"error": "invalid IP"})
            self.state.blocker.unblock(ip)
            return self._json(200, {"unblocked": [ip]})
        if path == "/api/unblock-all":
            removed = sorted(self.state.blocker.blocked)
            for ip in removed:
                self.state.blocker.unblock(ip)
            return self._json(200, {"unblocked": removed})
        return self._json(404, {"error": "not found"})


class Dashboard:
    """Serves the page and the snapshot API for a running pipeline."""

    def __init__(self, pipeline, blocker, iface=None, dry_run=False,
                 host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT):
        self.state = DashboardState(pipeline, blocker, iface=iface, dry_run=dry_run)
        self.host, self.port = host, port
        self._server = None
        self._stop = threading.Event()

    @property
    def url(self):
        return f"http://{self.host}:{self.port}/"

    def start(self):
        """Bind and serve in the background. False if the port is unavailable.

        A dashboard that cannot start must not take the IDS down with it, so the
        failure is reported and capture continues without it.
        """
        try:
            self._server = ThreadingHTTPServer((self.host, self.port),
                                               functools.partial(_Handler, self.state))
        except OSError as exc:
            log.error("dashboard could not bind %s:%s (%s) - continuing without it",
                      self.host, self.port, exc)
            return False
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]   # resolves port 0
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        threading.Thread(target=self._sampler, daemon=True).start()
        return True

    def _sampler(self):
        while not self._stop.wait(1.0):
            try:
                self.state.sample()
            except Exception:
                log.exception("traffic sample failed")

    def stop(self):
        self._stop.set()
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def attach(pipeline, blocker, iface=None, dry_run=False,
           port=config.DASHBOARD_PORT):
    """Create, wire and start a dashboard for a pipeline. None if it could not."""
    dash = Dashboard(pipeline, blocker, iface=iface, dry_run=dry_run, port=port)
    if not dash.start():
        return None
    pipeline.observer = dash.state
    return dash
