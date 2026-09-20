"""Central tunables for PacketWatch. Every threshold used anywhere lives here.

The three rule thresholds are stock values for a home or small-office link. If
models/thresholds.json exists (written by `--calibrate`), its values are used
instead: see packetwatch/calibrate.py for why and for the safety floors.
"""
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
ALERT_LOG = BASE_DIR.parent / "alerts.log"

# Feature window: per-source-IP rolling window length (seconds)
WINDOW_SECONDS = 10
# Evaluate a given source at most this often (seconds)
EVAL_INTERVAL = 1.0
# Stats line interval (seconds)
STATS_INTERVAL = 30

# --- memory bounds ---------------------------------------------------------
# Nothing in the running system may grow with traffic volume. These are the
# ceilings that guarantee it; all of them are per-process, in ordinary heap
# memory, and none of them hold packets.
MAX_SOURCES = 4096          # source IPs tracked at once; oldest evicted first
IDLE_EVICT_SECONDS = 60     # drop a source this long after its last packet
PORT_TRACK_CAP = 256        # distinct ports remembered per source (>= any threshold)
DST_TRACK_CAP = 64          # distinct destinations remembered per source
MAX_CORRELATED_IPS = 4096   # IPs held by the alert correlator
MAX_CALIBRATION_SAMPLES = 50_000   # reservoir size while calibrating

# --- alert log retention ---------------------------------------------------
ALERT_LOG_MAX_BYTES = 5 * 1024 * 1024
ALERT_LOG_BACKUPS = 3       # alerts.log.1 .. .3, then the oldest is discarded

# --- Verification rules (REQ 3) ---
PORT_SCAN_THRESHOLD = 10          # unique destination ports within the window
FLOOD_PPS_THRESHOLD = 100         # packets per second
SUSPICIOUS_PORT_THRESHOLD = 3     # hits on SUSPICIOUS_PORTS within the window

CALIBRATED = {}
_threshold_file = MODEL_DIR / "thresholds.json"
if _threshold_file.exists():
    try:
        CALIBRATED = json.loads(_threshold_file.read_text(encoding="utf-8"))
        PORT_SCAN_THRESHOLD = int(CALIBRATED["port_scan"])
        FLOOD_PPS_THRESHOLD = int(CALIBRATED["flood_pps"])
        SUSPICIOUS_PORT_THRESHOLD = int(CALIBRATED["suspicious_port"])
    except (ValueError, KeyError, OSError):
        CALIBRATED = {}                # malformed file: keep the stock values
# 22 was added after CIC-IDS2017 showed SSH-Patator brute force passing the rule
# layer untouched while FTP-Patator on 21 was caught in full. It costs ~0.4pp of
# false positives on a corporate capture with real admin SSH; on a single Windows
# host, inbound SSH is itself anomalous. 3306/5432 cost nothing measurable.
SUSPICIOUS_PORTS = frozenset({21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 4444,
                              5432, 5900, 6667})

# Alert correlation: escalate to CRITICAL when one IP trips >= N distinct rules
CORRELATION_WINDOW = 60
CORRELATION_MIN_RULES = 2

# Independent rule trigger: block on rules alone when this many distinct rules
# fire at once, even if neither classifier flagged the source. Measured on
# CIC-IDS2017 (see EVALUATION.md): without it, attack types absent from training
# are never blocked (recall 44% on unseen Friday attacks vs 99% with it).
# 0 disables, restoring "the ML must flag first" behaviour.
INDEPENDENT_RULE_TRIGGER = 2

# --- Response (REQ 4) ---
RULE_PREFIX = "PacketWatch_Block_"
BLOCK_TTL_MIN = 30                # auto-unblock after this many minutes (0 = never)
# Addresses that must never be blocked (own IPs, loopback, gateway are added at runtime)
WHITELIST = frozenset({"127.0.0.1", "::1", "0.0.0.0"})
