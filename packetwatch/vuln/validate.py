"""Check whether a high-priority finding is actually exposed, without attacking it.

VPID's third step generates "targeted validation payloads" - it tries the
vulnerability to see whether it is real. This module deliberately stops short of
that. It answers the cheaper question that removes most of the false positives
anyway: is the service the scanner complained about actually listening, and does
it look like what the scanner thought it was?

What it does: a TCP connect, an optional banner read, and for HTTP an unmodified
HEAD request. Nothing it sends is malformed, oversized, or specific to any
vulnerability, and it never tries to trigger one. Confirming a vulnerability by
exploiting it needs a lab, permission, and a human deciding it is worth the
risk - so that stays out of this tool.

Targets are restricted to private and loopback addresses unless explicitly
allowed, so a mis-parsed report cannot send traffic to a stranger.
"""
import ipaddress
import socket
import ssl
from dataclasses import dataclass

TIMEOUT = 3.0
BANNER_BYTES = 200
HTTP_PORTS = {80, 8080, 8000, 8008, 591}
TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 5061}


@dataclass
class Check:
    host: str
    port: int
    reachable: bool
    detail: str
    banner: str = ""

    def line(self):
        state = "OPEN " if self.reachable else "closed"
        return f"{state} {self.host}:{self.port} {self.detail}".rstrip()


# Explicit LAN ranges rather than ipaddress.is_private, which also covers
# documentation and reserved blocks such as 203.0.113.0/24 - addresses that are
# emphatically not your network, and that this tool must not probe.
LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"))


def is_local_target(host):
    """True only for loopback, link-local and RFC1918-style LAN addresses."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False                      # hostnames are never assumed local
    return any(addr in net for net in LOCAL_NETWORKS if net.version == addr.version)


def _read_banner(sock):
    try:
        sock.settimeout(TIMEOUT)
        data = sock.recv(BANNER_BYTES)
        return data.decode("utf-8", "replace").strip().splitlines()[0][:120] if data else ""
    except (OSError, IndexError):
        return ""


def check_port(host, port, timeout=TIMEOUT):
    """Connect, and describe what answered. No payload beyond a plain HEAD."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        proto = tls.version()
                        cipher = (tls.cipher() or ("?",))[0]
                        return Check(host, port, True, f"TLS {proto}, {cipher}")
                except ssl.SSLError as exc:
                    return Check(host, port, True, f"TLS handshake failed: {exc.reason}")
            if port in HTTP_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n"
                             % host.encode("idna", "ignore"))
                banner = _read_banner(sock)
                return Check(host, port, True, f"HTTP: {banner}" if banner else "HTTP",
                             banner)
            banner = _read_banner(sock)
            return Check(host, port, True, f"banner: {banner}" if banner else "open",
                         banner)
    except socket.timeout:
        return Check(host, port, False, "no answer within %.0fs" % timeout)
    except OSError as exc:
        return Check(host, port, False, f"{exc.__class__.__name__}: {exc}")


def validate(ranked, limit=10, allow_external=False):
    """Check the top findings. Returns (Check, Priority, Finding) triples."""
    out, seen = [], set()
    for priority, finding in ranked:
        if len(out) >= limit:
            break
        port = finding.port_number
        if port is None or finding.protocol != "tcp":
            continue                      # UDP and portless findings are not probed
        key = (finding.host, port)
        if key in seen:
            continue
        seen.add(key)
        if not allow_external and not is_local_target(finding.host):
            out.append((Check(finding.host, port, False,
                              "skipped: not a private address (use --allow-external)"),
                        priority, finding))
            continue
        out.append((check_port(finding.host, port), priority, finding))
    return out
