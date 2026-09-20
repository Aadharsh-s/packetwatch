"""REQ 1: live traffic capture with Scapy's sniff() (needs Npcap + Administrator)."""
import ctypes
import sys


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:  # non-Windows
        import os
        return os.geteuid() == 0


def preflight():
    """Exit with a clear message if capture cannot work."""
    if not is_admin():
        sys.exit("ERROR: PacketWatch must run from an Administrator terminal "
                 "(packet capture and firewall changes require elevation).")
    from scapy.all import conf, get_working_ifaces

    if sys.platform == "win32" and not conf.use_pcap:
        sys.exit("ERROR: Npcap not detected. Install it from https://npcap.com "
                 "(tick 'WinPcap API-compatible mode').")
    if not list(get_working_ifaces()):
        sys.exit("ERROR: no capture-capable network interfaces found.")


def list_ifaces():
    from scapy.all import get_working_ifaces

    for iface in get_working_ifaces():
        print(f"{iface.name!r:45} ip={iface.ip or '-':16} {iface.description}")


def start_capture(handler, iface=None, timeout=None):
    from scapy.all import sniff

    sniff(prn=handler, store=False, filter="ip", iface=iface, timeout=timeout)
