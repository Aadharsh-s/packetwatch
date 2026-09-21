"""Draw PacketWatch's logical data model as an ER diagram.

    python docs/er_diagram.py      ->  docs/er_diagram.png (+ .svg)

Entities mirror what the code actually creates: a source host is summarised
in rolling traffic windows, each window is scored by the two classifiers,
a confirmed window raises an alert explained by rule hits, and an alert may
result in a firewall block.
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon, Rectangle

OUT = Path(__file__).resolve().parent
plt.rcParams["font.family"] = "Calibri"

INK = "#1F2937"
LINE = "#374151"
HEAD = {
    "SOURCE_HOST": "#0369A1",
    "TRAFFIC_WINDOW": "#4338CA",
    "DETECTION": "#B45309",
    "ALERT": "#BE185D",
    "RULE_HIT": "#7C3AED",
    "BLOCK": "#15803D",
}

fig, ax = plt.subplots(figsize=(16, 11), dpi=200)
ax.set_xlim(0, 170)
ax.set_ylim(0, 120)
ax.axis("off")

W, HEADER, ROW = 40, 7.0, 4.3


def entity(name, x, top, attrs):
    """Table-style entity. attrs: list of (tag, name) with tag in {'PK','FK',''}."""
    h = HEADER + ROW * len(attrs) + 2.2
    color = HEAD[name]
    ax.add_patch(FancyBboxPatch((x, top - h), W, h, boxstyle="round,pad=0,rounding_size=1.2",
                                fc="white", ec=color, lw=2.2))
    ax.add_patch(Rectangle((x, top - HEADER), W, HEADER, fc=color, ec=color, lw=2.2))
    ax.text(x + W / 2, top - HEADER / 2, name, ha="center", va="center", fontsize=14.5,
            fontweight="bold", color="white")
    for i, (tag, attr) in enumerate(attrs):
        y = top - HEADER - 3.0 - i * ROW
        if tag:
            ax.text(x + 2.2, y, tag, ha="left", va="center", fontsize=10,
                    fontweight="bold", color=color)
        ax.text(x + 9, y, attr, ha="left", va="center", fontsize=12,
                color=INK, fontweight="bold" if tag == "PK" else "normal",
                style="italic" if tag == "FK" else "normal")
    return {"x": x, "top": top, "bottom": top - h, "w": W}


def diamond(cx, cy, label, w=19, h=8.5):
    ax.add_patch(Polygon([(cx - w / 2, cy), (cx, cy + h / 2), (cx + w / 2, cy),
                          (cx, cy - h / 2)], closed=True, fc="#FFFBEB", ec=LINE, lw=1.8,
                         zorder=3))
    ax.text(cx, cy, label, ha="center", va="center", fontsize=11, color=INK, zorder=4,
            style="italic")


def card(x, y, text, ha="center"):
    ax.text(x, y, text, ha=ha, va="center", fontsize=12.5, fontweight="bold", color=LINE)


def hline(x1, x2, y):
    ax.plot([x1, x2], [y, y], color=LINE, lw=1.8, zorder=1)


def vline(x, y1, y2):
    ax.plot([x, x], [y1, y2], color=LINE, lw=1.8, zorder=1)


ax.text(85, 116, "PacketWatch: Entity-Relationship Diagram", ha="center", va="center",
        fontsize=22, fontweight="bold", color=INK)

C1, C2, C3 = 4, 65, 126
R1, R2 = 108, 44

detection = entity("DETECTION", C1, R1, [
    ("PK", "detection_id"), ("FK", "window_id"), ("", "dt_flag"), ("", "nb_flag"),
    ("", "dt_probability"), ("", "nb_probability"), ("", "flagged")])
window = entity("TRAFFIC_WINDOW", C2, R1, [
    ("PK", "window_id"), ("FK", "source_ip"), ("", "window_start"), ("", "pkt_count"),
    ("", "pkts_per_sec"), ("", "unique_dst_ports"), ("", "suspicious_port_hits"),
    ("", "+ 5 more features")])
host = entity("SOURCE_HOST", C3, R1, [
    ("PK", "source_ip"), ("", "first_seen"), ("", "last_seen"), ("", "is_protected")])

rule_hit = entity("RULE_HIT", C1, R2, [
    ("PK", "hit_id"), ("FK", "alert_id"), ("", "rule_name"), ("", "observed_value"),
    ("", "threshold")])
alert = entity("ALERT", C2, R2, [
    ("PK", "alert_id"), ("FK", "window_id"), ("", "timestamp"), ("", "severity"),
    ("", "trigger"), ("", "action")])
block = entity("BLOCK", C3, R2, [
    ("PK", "block_id"), ("FK", "alert_id"), ("FK", "source_ip"), ("", "firewall_rule"),
    ("", "blocked_at"), ("", "expires_at")])

# --- row 1: host -< window -- detection -------------------------------------------
y1 = R1 - HEADER - 7
hline(C2 + W, C3, y1)
diamond((C2 + W + C3) / 2, y1, "summarised in")
card(C3 - 2, y1 + 2.6, "1", ha="right")
card(C2 + W + 2, y1 + 2.6, "N", ha="left")

hline(C1 + W, C2, y1)
diamond((C1 + W + C2) / 2, y1, "scored as")
card(C2 - 2, y1 + 2.6, "1", ha="right")
card(C1 + W + 2, y1 + 2.6, "1", ha="left")

# --- window -- alert (vertical) ---------------------------------------------------
vx = C2 + W / 2
vline(vx, window["bottom"], alert["top"])
diamond(vx, (window["bottom"] + alert["top"]) / 2, "raises", w=15, h=7.5)
card(vx + 2.2, window["bottom"] - 2.2, "1", ha="left")
card(vx + 2.2, alert["top"] + 2.2, "0..1", ha="left")

# --- host -- block (vertical) -----------------------------------------------------
hx = C3 + W / 2
vline(hx, host["bottom"], block["top"])
diamond(hx, (host["bottom"] + block["top"]) / 2, "blocked as", w=17, h=7.5)
card(hx + 2.2, host["bottom"] - 2.2, "1", ha="left")
card(hx + 2.2, block["top"] + 2.2, "0..N", ha="left")

# --- row 2: rule_hit >- alert -- block ---------------------------------------------
y2 = R2 - HEADER - 7
hline(C1 + W, C2, y2)
diamond((C1 + W + C2) / 2, y2, "explained by")
card(C2 - 2, y2 + 2.6, "1", ha="right")
card(C1 + W + 2, y2 + 2.6, "N", ha="left")

hline(C2 + W, C3, y2)
diamond((C2 + W + C3) / 2, y2, "results in")
card(C2 + W + 2, y2 + 2.6, "1", ha="left")
card(C3 - 2, y2 + 2.6, "0..1", ha="right")

# --- legend -------------------------------------------------------------------------
ax.text(4, 2.5, "PK  primary key      FK  foreign key      1 / N / 0..1  cardinality",
        ha="left", va="center", fontsize=11.5, color=LINE)
ax.text(166, 2.5, "Logical data model: alerts are persisted to alerts.log today",
        ha="right", va="center", fontsize=11.5, color=LINE, style="italic")

fig.savefig(OUT / "er_diagram.png", bbox_inches="tight", facecolor="white")
fig.savefig(OUT / "er_diagram.svg", bbox_inches="tight", facecolor="white")
print("wrote", OUT / "er_diagram.png")
