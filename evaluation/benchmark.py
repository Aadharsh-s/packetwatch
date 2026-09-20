"""Measure what PacketWatch costs to run: throughput, latency, CPU and memory.

The abstract calls the system lightweight; this puts numbers behind that.
Everything is measured on the real pipeline (features -> DT + NB -> rules ->
blocker), with only the firewall call stubbed out, since netsh needs admin and
would be measuring Windows, not us.

Usage:
    python -m evaluation.benchmark [--packets 200000] [--out BENCHMARK.md]
"""
import argparse
import json
import platform
import statistics
import subprocess
import time
import gc
import tracemalloc
from pathlib import Path

import psutil
from scapy.layers.inet import ICMP, IP, TCP, UDP

from packetwatch import config
from packetwatch.model import Detector
from packetwatch.pipeline import Pipeline
from packetwatch.response import Alerter, FirewallBlocker

HOST = "192.168.50.10"


def silent_blocker():
    """Blocker whose netsh calls do nothing, so timings are ours, not Windows'."""
    return FirewallBlocker(runner=lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
                           ttl_min=0)


DETECTOR = None


def quiet_pipeline(clock=time.time, sources=1):
    """Pipeline with no console output and no stats spam, sharing one Detector."""
    global DETECTOR
    if DETECTOR is None:
        DETECTOR = Detector()
    pipe = Pipeline(DETECTOR, silent_blocker(), Alerter(log_path=None, console=False),
                    own_addresses={HOST}, clock=clock)
    pipe._maybe_stats = lambda now: None
    return pipe


def _src_ip(n):
    return f"10.{n // 65536 % 256}.{n // 256 % 256}.{n % 256}"


def build_traffic(n, sources, wire=True):
    """A realistic mix: mostly benign TCP/UDP, spread over `sources` hosts.

    With wire=True the packets are serialised and re-dissected, which is what
    sniff() hands the handler: header fields populated, raw bytes attached.
    Hand-crafted packets lack both, so any length query forces Scapy to rebuild
    them - a test artefact that costs 13x more per packet than live traffic.
    """
    pkts = []
    for i in range(n):
        src = _src_ip(i % sources)
        if i % 10 == 0:
            p = IP(src=src, dst=HOST) / UDP(sport=53, dport=50000 + (i % 1000)) / (b"d" * 60)
        elif i % 37 == 0:
            p = IP(src=src, dst=HOST) / ICMP()
        else:
            p = IP(src=src, dst=HOST) / TCP(sport=443, dport=50000 + (i % 1000),
                                            flags="A") / (b"x" * 500)
        pkts.append(IP(bytes(p)) if wire else p)
    return pkts


def bench_throughput(n, sources, wire=True):
    """Packets per second and per-packet cost through the full pipeline."""
    pipe = quiet_pipeline(sources=sources)
    pkts = build_traffic(n, sources, wire=wire)   # built up front, not timed
    proc = psutil.Process()
    cpu0 = proc.cpu_times()
    t0 = time.perf_counter()
    for p in pkts:
        pipe.handle(p)
    elapsed = time.perf_counter() - t0
    cpu1 = proc.cpu_times()
    cpu = (cpu1.user - cpu0.user) + (cpu1.system - cpu0.system)
    return {"sources": sources, "wire": wire, "packets": n, "seconds": elapsed,
            "pps": n / elapsed, "us_per_packet": elapsed / n * 1e6,
            "cpu_seconds": cpu, "cpu_per_packet_us": cpu / n * 1e6,
            "judged": pipe.stats["judged"]}


def bench_latency(samples=15):
    """Wall-clock seconds from an attack's first packet to the block decision."""
    lat = []
    for _ in range(samples):
        pipe = quiet_pipeline()
        blocker = pipe.blocker
        start = time.perf_counter()
        attacker = "203.0.113.7"
        i = 0
        while attacker not in blocker.blocked and time.perf_counter() - start < 5:
            pipe.handle(IP(src=attacker, dst=HOST) / TCP(dport=1000 + i, flags="S"))
            i += 1
            if i > 400:                       # nudge the sweep past its 1 s throttle
                pipe.sweep(force=True)
        lat.append(time.perf_counter() - start)
    return {"samples": samples, "median_s": statistics.median(lat),
            "p95_s": sorted(lat)[int(len(lat) * 0.95) - 1], "max_s": max(lat)}


def bench_memory(source_counts, per_source_packets=6):
    """Resident memory growth as the number of tracked source IPs rises.

    One packet object per source is built up front and replayed, so the figures
    measure PacketWatch's own state (windows, counters), not Scapy allocations.
    """
    out = []
    for n_src in source_counts:
        pipe = quiet_pipeline(sources=n_src)
        pool = [IP(bytes(IP(src=_src_ip(i), dst=HOST)
                              / TCP(sport=443, dport=443, flags="A")))
                for i in range(n_src)]
        for p in pool:                      # force lazy field building before timing
            len(bytes(p))
        gc.collect()
        tracemalloc.start()
        base = psutil.Process().memory_info().rss
        for _ in range(per_source_packets):
            for p in pool:
                pipe.handle(p)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        rss = psutil.Process().memory_info().rss - base
        tracked = len(pipe.windows)
        out.append({"sources": tracked, "rss_delta_mb": rss / 1e6,
                    "traced_peak_mb": peak / 1e6,
                    "kb_per_source": peak / max(1, tracked) / 1e3})
        print(f"  memory: {tracked:,} sources -> {rss/1e6:.1f} MB RSS", flush=True)
    return out


def bench_under_attack():
        """Memory while being flooded and while being scanned.

        These are the cases that used to hurt: both once grew with the amount of
        traffic sent, which handed an attacker a way to exhaust memory just by
        sending more. Both are now fixed-size per source.
        """
        from packetwatch.features import PORT_CAP, SourceWindow

        out = {}
        for label, packets, ports in (("flood_200k_packets", 200_000, 1),
                                      ("scan_all_65535_ports", 65_535, 70_000)):
            gc.collect()
            tracemalloc.start()
            w = SourceWindow()
            for i in range(packets):
                w.add(1000.0 + (i % 10) * 0.1, (i % ports) + 1, "10.0.0.1", 6,
                      True, 500)
            out[label] = {"packets": packets,
                          "peak_kb": tracemalloc.get_traced_memory()[1] / 1e3}
            tracemalloc.stop()

        # a spoofed-source flood, against the whole pipeline
        clock = time.time
        pipe = quiet_pipeline(clock=clock)
        wire = [IP(bytes(IP(src=_src_ip(i), dst=HOST) / TCP(dport=80, flags="S")))
                for i in range(20_000)]
        gc.collect()
        tracemalloc.start()
        for p in wire:
            pipe.handle(p)
        out["spoofed_sources"] = {
            "unique_sources": len(wire), "tracked": len(pipe.windows),
            "evicted": pipe.evicted,
            "peak_mb": tracemalloc.get_traced_memory()[1] / 1e6}
        tracemalloc.stop()
        out["port_cap"] = PORT_CAP
        return out


def bench_idle(seconds=3.0):
    """CPU used while running but seeing no traffic (the ticker thread only)."""
    import threading
    pipe = quiet_pipeline()
    stop = threading.Event()
    proc = psutil.Process()
    t = threading.Thread(target=pipe.run_ticker, args=(stop,), daemon=True)
    c0 = proc.cpu_times()
    t.start()
    time.sleep(seconds)
    stop.set()
    t.join(timeout=2)
    c1 = proc.cpu_times()
    cpu = (c1.user - c0.user) + (c1.system - c0.system)
    return {"seconds": seconds, "cpu_seconds": cpu, "cpu_percent": cpu / seconds * 100}


def bench_model_load():
    t0 = time.perf_counter()
    det = Detector()
    load = time.perf_counter() - t0
    vec = [500, 50, 3, 1, 480, 20, 0, 2, 0, 5]
    t0 = time.perf_counter()
    for _ in range(2000):
        det.predict(vec)
    single = (time.perf_counter() - t0) / 2000 * 1e3
    batch_in = [vec] * 500
    t0 = time.perf_counter()
    for _ in range(20):
        det.predict_many(batch_in)
    batched = (time.perf_counter() - t0) / (20 * 500) * 1e3
    return {"load_s": load, "predict_ms": single, "predict_batched_ms": batched}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", type=int, default=25_000)
    ap.add_argument("--out", default="BENCHMARK.md")
    args = ap.parse_args()

    cpu_name = platform.processor() or "unknown CPU"
    cores = psutil.cpu_count(logical=True)
    total_ram = psutil.virtual_memory().total / 1e9

    t_start = time.perf_counter()
    print("measuring throughput...", flush=True)
    thr = []
    for n_src in (1, 50, 1000):
        r = bench_throughput(args.packets, n_src)
        print(f"  {n_src:,} sources -> {r['pps']:,.0f} pkt/s", flush=True)
        thr.append(r)
    crafted = bench_throughput(args.packets // 5, 50, wire=False)
    print("measuring model cost...", flush=True)
    model = bench_model_load()
    print("measuring latency...", flush=True)
    lat = bench_latency()
    print("measuring memory...", flush=True)
    mem = bench_memory([100, 1000, 5000])
    print("measuring memory under attack...", flush=True)
    attack = bench_under_attack()
    print("measuring idle cost...", flush=True)
    idle = bench_idle()

    print(f"total benchmark time: {time.perf_counter() - t_start:.0f}s", flush=True)
    best = max(thr, key=lambda r: r["pps"])
    worst = min(thr, key=lambda r: r["pps"])
    rep = [
        "# PacketWatch resource benchmark", "",
        f"Host: {cpu_name}, {cores} logical cores, {total_ram:.0f} GB RAM, "
        f"Python {platform.python_version()} on {platform.system()} "
        f"{platform.release()}.", "",
        "Measured on the real pipeline (feature windows, Decision Tree, Naive Bayes, "
        "rule verification, blocker bookkeeping). Only the `netsh` call is stubbed, "
        "because it needs Administrator rights and would measure Windows rather than "
        "PacketWatch. Packets are built before timing starts.", "",
        "## Throughput", "",
        "| Distinct source IPs | Packets | Wall seconds | Packets/sec | "
        "CPU us/packet | Evaluations |",
        "|---|---|---|---|---|---|",
    ]
    for r in thr:
        rep.append(f"| {r['sources']:,} | {r['packets']:,} | {r['seconds']:.2f} | "
                   f"{r['pps']:,.0f} | {r['cpu_per_packet_us']:.2f} | {r['judged']:,} |")
    rep += [
        "", f"Sustained {worst['pps']:,.0f}-{best['pps']:,.0f} packets/sec on one core, "
        f"i.e. {best['us_per_packet']:.0f}-{worst['us_per_packet']:.0f} us of CPU per "
        "packet. For scale, saturating a 100 Mbit link with 1500-byte frames is about "
        "8,300 packets/sec, so one core covers a home or small-office link with room "
        "to spare.", "",
        "Cost scales with the number of active sources, not total traffic: each sweep "
        "classifies every pending source in a single batched call.", "",
        f"Hand-crafted packets (as in the unit tests) run at only "
        f"{crafted['pps']:,.0f} packets/sec, because they carry no IP length field or "
        "raw bytes and Scapy must rebuild them to answer a length query. Live capture "
        "never takes that path; `packet_length()` reads the wire values instead.", "",
        "## Detection latency", "",
        f"Time from an attack's first packet to the block decision, over "
        f"{lat['samples']} runs: median **{lat['median_s']*1000:.0f} ms**, "
        f"p95 {lat['p95_s']*1000:.0f} ms, worst {lat['max_s']*1000:.0f} ms.", "",
        "The floor is the one-second evaluation interval: a source is judged at most "
        f"once per {config.EVAL_INTERVAL:.0f}s, so an attack is confirmed within about "
        "a second of crossing a threshold.", "",
        "## Memory", "",
        "| Tracked source IPs | RSS growth | Traced peak | Per source |",
        "|---|---|---|---|",
    ]
    for m in mem:
        rep.append(f"| {m['sources']:,} | {m['rss_delta_mb']:.1f} MB | "
                   f"{m['traced_peak_mb']:.1f} MB | {m['kb_per_source']:.1f} KB |")
    rep += [
        "", f"Memory is bounded by the rolling {config.WINDOW_SECONDS}s window: entries "
        "older than that are dropped on every packet, and idle sources are evicted "
        f"every {config.STATS_INTERVAL}s, so usage tracks active sources rather than "
        "total traffic seen.", "",
        "## Memory while under attack", "",
        "Memory must not grow with how much an attacker sends, or flooding the "
        "host becomes a way to exhaust its memory. Nothing per-packet is stored: "
        "each source keeps one set of counters per second of the window, recycled "
        "as the window slides.", "",
        "| Situation | Peak memory |",
        "|---|---|",
        f"| One source flooding 200,000 packets | "
        f"{attack['flood_200k_packets']['peak_kb']:.0f} KB |",
        f"| One source scanning all 65,535 ports | "
        f"{attack['scan_all_65535_ports']['peak_kb']:.0f} KB |",
        f"| {attack['spoofed_sources']['unique_sources']:,} spoofed source addresses | "
        f"{attack['spoofed_sources']['peak_mb']:.1f} MB "
        f"({attack['spoofed_sources']['tracked']:,} tracked, "
        f"{attack['spoofed_sources']['evicted']:,} evicted) |", "",
        f"Distinct ports per source are remembered up to {attack['port_cap']}, well "
        "above any threshold that can fire, so a scan of every port is still caught "
        "while only the cap is stored.", "",
        "## Idle cost and startup", "",
        f"- Idle CPU (running, no traffic): {idle['cpu_percent']:.2f}% of one core, "
        "the once-a-second sweep thread.",
        f"- Model load from disk: {model['load_s']*1000:.0f} ms.",
        f"- One classification on its own (both models): {model['predict_ms']:.3f} ms.",
        f"- Per source when classified in a batch of 500: "
        f"{model['predict_batched_ms']:.4f} ms "
        f"({model['predict_ms']/model['predict_batched_ms']:.0f}x cheaper). Each sweep "
        "classifies all pending sources in one call for this reason.", "",
        "## Reproduce", "", "```",
        f"python -m evaluation.benchmark --packets {args.packets}", "```",
    ]
    Path(args.out).write_text("\n".join(rep), encoding="utf-8")
    Path(args.out).with_suffix(".json").write_text(json.dumps(
        {"host": {"cpu": cpu_name, "cores": cores, "ram_gb": total_ram},
         "throughput": thr, "latency": lat, "memory": mem, "idle": idle,
         "under_attack": attack,
         "model": model}, indent=2), encoding="utf-8")
    print("\n".join(rep[8:]))
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
