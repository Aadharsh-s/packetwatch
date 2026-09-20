# PacketWatch resource benchmark

Host: Intel64 Family 6 Model 140 Stepping 2, GenuineIntel, 4 logical cores, 8 GB RAM, Python 3.13.1 on Windows 11.

Measured on the real pipeline (feature windows, Decision Tree, Naive Bayes, rule verification, blocker bookkeeping). Only the `netsh` call is stubbed, because it needs Administrator rights and would measure Windows rather than PacketWatch. Packets are built before timing starts.

## Throughput

| Distinct source IPs | Packets | Wall seconds | Packets/sec | CPU us/packet | Evaluations |
|---|---|---|---|---|---|
| 1 | 40,000 | 0.88 | 45,422 | 21.88 | 1 |
| 50 | 40,000 | 0.94 | 42,753 | 22.66 | 1 |
| 1,000 | 40,000 | 1.17 | 34,165 | 29.30 | 1,001 |

Sustained 34,165-45,422 packets/sec on one core, i.e. 22-29 us of CPU per packet. For scale, saturating a 100 Mbit link with 1500-byte frames is about 8,300 packets/sec, so one core covers a home or small-office link with room to spare.

Cost scales with the number of active sources, not total traffic: each sweep classifies every pending source in a single batched call.

Hand-crafted packets (as in the unit tests) run at only 3,115 packets/sec, because they carry no IP length field or raw bytes and Scapy must rebuild them to answer a length query. Live capture never takes that path; `packet_length()` reads the wire values instead.

## Detection latency

Time from an attack's first packet to the block decision, over 15 runs: median **140 ms**, p95 217 ms, worst 272 ms.

The floor is the one-second evaluation interval: a source is judged at most once per 1s, so an attack is confirmed within about a second of crossing a threshold.

## Memory

| Tracked source IPs | RSS growth | Traced peak | Per source |
|---|---|---|---|
| 100 | 0.3 MB | 0.6 MB | 6.1 KB |
| 1,000 | 2.6 MB | 6.1 MB | 6.1 KB |
| 4,096 | 13.1 MB | 27.3 MB | 6.7 KB |

Memory is bounded by the rolling 10s window: entries older than that are dropped on every packet, and idle sources are evicted every 30s, so usage tracks active sources rather than total traffic seen.

## Memory while under attack

Memory must not grow with how much an attacker sends, or flooding the host becomes a way to exhaust its memory. Nothing per-packet is stored: each source keeps one set of counters per second of the window, recycled as the window slides.

| Situation | Peak memory |
|---|---|
| One source flooding 200,000 packets | 7 KB |
| One source scanning all 65,535 ports | 16 KB |
| 20,000 spoofed source addresses | 27.3 MB (4,096 tracked, 15,904 evicted) |

Distinct ports per source are remembered up to 256, well above any threshold that can fire, so a scan of every port is still caught while only the cap is stored.

## Idle cost and startup

- Idle CPU (running, no traffic): 0.00% of one core, the once-a-second sweep thread.
- Model load from disk: 1 ms.
- One classification on its own (both models): 0.225 ms.
- Per source when classified in a batch of 500: 0.0030 ms (75x cheaper). Each sweep classifies all pending sources in one call for this reason.

## Reproduce

```
python -m evaluation.benchmark --packets 40000
```