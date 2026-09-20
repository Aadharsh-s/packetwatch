"""PacketWatch CLI: python -m packetwatch --help"""
import argparse
import ipaddress
import logging
import sys
import threading

from . import capture, config


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="packetwatch",
                                description="Single-host IDS/IPS: capture -> DT+NB -> "
                                            "rule verification -> Windows Firewall block")
    p.add_argument("--iface", help="interface to sniff (default: Scapy's default)")
    p.add_argument("--timeout", type=int, help="stop capturing after N seconds")
    p.add_argument("--dry-run", action="store_true",
                   help="log firewall commands instead of executing them")
    p.add_argument("--whitelist", nargs="*", default=[], help="extra IPs never to block")
    p.add_argument("--risk-map", metavar="JSON",
                   help="vulnerability-module output (python -m packetwatch.vuln "
                        "--json ...): traffic aimed at a known-vulnerable port is "
                        "escalated and blocked on a single rule")
    p.add_argument("--record", metavar="CSV",
                   help="append live feature rows to CSV (label them, then --train --csv)")
    p.add_argument("--train", action="store_true", help="(re)train both classifiers and exit")
    p.add_argument("--csv", help="labelled CSV to add to training data")
    p.add_argument("--calibrate", type=int, metavar="SECONDS",
                   help="learn this host's rule thresholds from SECONDS of its own "
                        "quiet traffic, then exit")
    p.add_argument("--simulate", action="store_true",
                   help="replay crafted attack/benign traffic offline (no admin needed)")
    p.add_argument("--list-ifaces", action="store_true", help="list interfaces and exit")
    p.add_argument("--unblock-all", action="store_true",
                   help=f"delete every {config.RULE_PREFIX}* firewall rule and exit")
    p.add_argument("--test-block", metavar="IP",
                   help="add a real block rule for IP, show it, remove it, and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.train:
        from .model import train
        train(csv_path=args.csv)
        return
    if args.calibrate:
        from .calibrate import run
        run(iface=args.iface, seconds=args.calibrate)
        return
    if args.simulate:
        from .riskmap import RiskMap
        from .simulate import run
        run(RiskMap.from_json(args.risk_map) if args.risk_map else None)
        return
    if args.list_ifaces:
        capture.list_ifaces()
        return

    from .response import Alerter, FirewallBlocker, local_addresses

    if args.unblock_all or args.test_block:
        if not capture.is_admin():
            sys.exit("ERROR: firewall changes require an Administrator terminal.")
        blocker = FirewallBlocker(ttl_min=0)
        if args.unblock_all:
            removed = blocker.unblock_all()
            print(f"Removed {len(removed)} rule(s): {', '.join(removed) or '-'}")
            return
        ip = str(ipaddress.ip_address(args.test_block))
        print(f"Blocking {ip}: {blocker.block(ip)}")
        print(blocker.show(ip))
        blocker.unblock(ip)
        print(f"Removed test rules for {ip}.")
        return

    capture.preflight()
    from .model import Detector
    from .pipeline import Pipeline

    from .riskmap import RiskMap

    risk = RiskMap.from_json(args.risk_map) if args.risk_map else RiskMap()
    own = local_addresses()
    blocker = FirewallBlocker(dry_run=args.dry_run, whitelist=set(args.whitelist) | own)
    pipeline = Pipeline(Detector(), blocker, Alerter(), own_addresses=own,
                        record_path=args.record, risk_map=risk)
    tuned = ("calibrated" if config.CALIBRATED else "stock")
    print(f"PacketWatch running{' (DRY RUN)' if args.dry_run else ''} - "
          f"protected addresses: {', '.join(sorted(own)) or '-'}. "
          f"Thresholds ({tuned}): {config.PORT_SCAN_THRESHOLD} ports / "
          f"{config.FLOOD_PPS_THRESHOLD} pps / {config.SUSPICIOUS_PORT_THRESHOLD} "
          f"suspicious. Risk map: {risk.summary()}. Ctrl+C to stop.")
    stop = threading.Event()
    threading.Thread(target=pipeline.run_ticker, args=(stop,), daemon=True).start()
    try:
        capture.start_capture(pipeline.handle, iface=args.iface, timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        pipeline.sweep(force=True)
        pipeline.close()
    print(f"Stopped. Active blocks: {', '.join(sorted(blocker.blocked)) or 'none'} "
          f"(auto-expire after {config.BLOCK_TTL_MIN} min while running; "
          f"use --unblock-all to clear).")


if __name__ == "__main__":
    main()
