"""REQ 4: OS-level blocking via Windows Firewall (netsh) + alerting.

netsh advfirewall is the Windows counterpart of VPID's iptables enforcement.
"""
import ipaddress
import json
import logging
import subprocess
import threading
from datetime import datetime, timezone

from . import config

log = logging.getLogger("packetwatch.response")

NETSH = "netsh"


def local_addresses():
    """This host's own IPs plus its default gateway - never block these."""
    addrs = set()
    try:
        from scapy.all import conf, get_if_addr, get_working_ifaces

        for iface in get_working_ifaces():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    addrs.add(ip)
            except Exception:
                pass
        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            addrs.add(gw)
    except Exception as exc:  # scapy/Npcap unavailable (e.g. in tests)
        log.debug("could not enumerate local addresses: %s", exc)
    return addrs


def rule_name(ip, direction):
    return f"{config.RULE_PREFIX}{ip}_{direction}"


class FirewallBlocker:
    def __init__(self, dry_run=False, whitelist=None, ttl_min=config.BLOCK_TTL_MIN,
                 runner=None):
        self.dry_run = dry_run
        self.whitelist = set(config.WHITELIST) | set(whitelist or ())
        self.ttl_min = ttl_min
        self.run = runner or subprocess.run
        self.blocked = set()
        self._lock = threading.Lock()
        self._timers = []

    def is_protected(self, ip):
        addr = ipaddress.ip_address(ip)
        return (ip in self.whitelist or addr.is_loopback or addr.is_multicast
                or addr.is_unspecified or ip == "255.255.255.255")

    def _netsh(self, args):
        cmd = [NETSH, "advfirewall", "firewall", *args]
        if self.dry_run:
            log.info("[dry-run] %s", " ".join(cmd))
            return True
        try:
            self.run(cmd, check=True, capture_output=True, text=True)
            return True
        except (subprocess.CalledProcessError, OSError) as exc:
            detail = getattr(exc, "stdout", "") or getattr(exc, "stderr", "") or exc
            log.error("netsh failed (%s): %s", " ".join(cmd), str(detail).strip())
            return False

    def block(self, ip):
        """Add inbound + outbound block rules. Returns the action taken."""
        ip = str(ipaddress.ip_address(ip))  # validates; raises ValueError otherwise
        with self._lock:
            if self.is_protected(ip):
                return "skipped (whitelisted)"
            if ip in self.blocked:
                return "already blocked"
            ok = all(
                self._netsh(["add", "rule", f"name={rule_name(ip, d)}", f"dir={d}",
                             "action=block", f"remoteip={ip}", "enable=yes"])
                for d in ("in", "out")
            )
            if not ok:
                return "block FAILED"
            self.blocked.add(ip)
        if self.ttl_min:
            t = threading.Timer(self.ttl_min * 60, self.unblock, args=(ip,))
            t.daemon = True
            t.start()
            self._timers.append(t)
        return "dry-run block" if self.dry_run else "blocked"

    def unblock(self, ip):
        with self._lock:
            for d in ("in", "out"):
                self._netsh(["delete", "rule", f"name={rule_name(ip, d)}"])
            self.blocked.discard(ip)
        log.info("unblocked %s", ip)

    def show(self, ip):
        name = rule_name(ip, "in")
        res = self.run([NETSH, "advfirewall", "firewall", "show", "rule", f"name={name}"],
                       capture_output=True, text=True)
        return res.stdout

    def unblock_all(self):
        """Delete every PacketWatch rule, including ones from previous runs."""
        res = self.run([NETSH, "advfirewall", "firewall", "show", "rule", "name=all"],
                       capture_output=True, text=True)
        names = {
            line.split(":", 1)[1].strip()
            for line in (res.stdout or "").splitlines()
            if line.lower().startswith("rule name:")
            and line.split(":", 1)[1].strip().startswith(config.RULE_PREFIX)
        }
        for name in sorted(names):
            self._netsh(["delete", "rule", f"name={name}"])
        self.blocked.clear()
        return sorted(names)


class Alerter:
    COLORS = {"HIGH": "\033[93m", "CRITICAL": "\033[91m", "INFO": "\033[96m"}
    RESET = "\033[0m"

    def __init__(self, log_path=config.ALERT_LOG, console=True):
        self.log_path = log_path
        self.console = console

    def alert(self, ip, severity, ml, hits, action, trigger="ml+rule", risk=None):
        record = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "src_ip": ip,
            "severity": severity,
            "trigger": trigger,
            "classifiers": ml,
            "rule_hits": [h.as_dict() for h in hits],
            "explanation": [h.explain() for h in hits],
            "action": action,
        }
        if risk:
            record["targets_known_vulnerability"] = {
                "cve": risk.get("cve", ""), "band": risk.get("band", ""),
                "reason": risk.get("reason", "")}
        if self.console:
            color = self.COLORS.get(severity, "")
            print(f"{color}[{severity}] {ip} -> {action} | trigger={trigger} | "
                  f"DT={ml['dt']}({ml['dt_proba']}) NB={ml['nb']}({ml['nb_proba']}) | "
                  f"{'; '.join(record['explanation'])}"
                  + (f" | targets {risk.get('cve') or 'a known-vulnerable service'}"
                     if risk else "") + self.RESET, flush=True)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        return record
