"""Draw the PacketWatch architecture diagram for the presentation.

    python docs/architecture.py      ->  docs/architecture.png (+ .svg)
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parent
plt.rcParams["font.family"] = "Calibri"

INK = "#1F2937"
MUTED = "#4B5563"
STAGES = {                     # fill, edge / title colour
    "capture": ("#E0F2FE", "#0369A1"),
    "features": ("#E0E7FF", "#4338CA"),
    "detect": ("#FEF3C7", "#B45309"),
    "verify": ("#FCE7F3", "#BE185D"),
    "respond": ("#DCFCE7", "#15803D"),
    "side": ("#F3F4F6", "#374151"),
}

fig, ax = plt.subplots(figsize=(16, 7.4), dpi=200)
ax.set_xlim(0, 160)
ax.set_ylim(0, 74)
ax.axis("off")


def box(x, y, w, h, kind, title, lines=(), title_size=15, body_size=11.5, dashed=False):
    fill, edge = STAGES[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=2.2",
                                fc=fill, ec=edge, lw=2, ls="--" if dashed else "-"))
    ax.text(x + w / 2, y + h - 3.4, title, ha="center", va="top", fontsize=title_size,
            fontweight="bold", color=edge)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 9.6 - i * 4.3, line, ha="center", va="top",
                fontsize=body_size, color=INK)


def arrow(x1, y1, x2, y2, color=INK, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=18, lw=2, color=color))


ax.text(80, 71, "PacketWatch: System Architecture", ha="center", va="center",
        fontsize=22, fontweight="bold", color=INK)

# ---- main pipeline -----------------------------------------------------------
Y, H, W = 33, 26, 25
xs = [2, 33.5, 65, 96.5, 128]
box(xs[0], Y, W, H, "capture", "1. Capture",
    ["Live network traffic", "Scapy sniff() via Npcap", "packets handled,", "never stored"])
box(xs[1], Y, W, H, "features", "2. Features",
    ["Per-source-IP", "rolling 10 s window", "10 features, fixed", "memory per source"])
box(xs[2], Y, W, H, "detect", "3. Detection",
    ["Decision Tree", "Multinomial Naive Bayes", "OR fusion: flag if", "either model agrees"])
box(xs[3], Y, W, H, "verify", "4. Verification",
    ["Port-scan rule", "Packet-flood rule", "Suspicious-port rule", "(replaces Snort)"])
box(xs[4], Y, W + 5, H, "respond", "5. Response",
    ["Windows Firewall block", "(netsh, replaces iptables)", "Explainable alert", "auto-expires in 30 min"])

for a, b in zip(xs[:-1], xs[1:]):
    arrow(a + W + 0.8, Y + H / 2, b - 0.8, Y + H / 2)

# ---- independent trigger, above verification ---------------------------------
vcx = xs[3] + W / 2
ax.text(vcx, 64.5, "Two rules firing together block on their own, even if the models miss",
        ha="center", fontsize=11.5, color=STAGES["verify"][1], style="italic")
arrow(vcx, 63, vcx, Y + H + 0.8, color=STAGES["verify"][1])

# ---- supporting boxes: each sits under the stage it feeds ---------------------
BY, BH = 2, 18
# memory bounds -> features
box(xs[1] - 2, BY, W + 4, BH, "side", "Memory bounds",
    ["Max 4,096 sources,", "idle ones released"], title_size=13, body_size=11, dashed=True)
arrow(xs[1] + W / 2, BY + BH + 0.8, xs[1] + W / 2, Y - 0.8, color=MUTED)

# unconfirmed flags <- detection path, logged only
box(xs[2] - 2, BY, W + 4, BH, "side", "Not confirmed",
    ["Logged for review,", "never blocked"], title_size=13, body_size=11, dashed=True)
arrow(xs[3] + 3, Y - 0.8, xs[2] + W - 1, BY + BH + 0.8, color=MUTED)

# thresholds -> verification
box(xs[3] - 2, BY, W + 4, BH, "side", "Thresholds",
    ["Stock values, or learned", "from normal traffic"], title_size=13, body_size=11,
    dashed=True)
arrow(vcx + 5, BY + BH + 0.8, vcx + 5, Y - 0.8, color=MUTED)

# protected addresses -> response
box(xs[4] - 1, BY, W + 6, BH, "side", "Protected addresses",
    ["Own IPs, router, loopback:", "never blocked"], title_size=13, body_size=11,
    dashed=True)
arrow(xs[4] + (W + 5) / 2, BY + BH + 0.8, xs[4] + (W + 5) / 2, Y - 0.8, color=MUTED)

fig.savefig(OUT / "architecture.png", bbox_inches="tight", facecolor="white")
fig.savefig(OUT / "architecture.svg", bbox_inches="tight", facecolor="white")
print("wrote", OUT / "architecture.png")
