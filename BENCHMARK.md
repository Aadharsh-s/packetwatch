# PacketWatch resource benchmark

Host: Intel64 Family 6 Model 140 Stepping 2, GenuineIntel, 4 logical cores, 8 GB RAM, Python 3.13.1 on Windows 11.

Measured on the real pipeline (feature windows, Decision Tree, Naive Bayes, rule verification, blocker bookkeeping). Only the `netsh` call is stubbed, because it needs Administrator rights and would measure Windows rather than PacketWatch. Packets are built before timing starts.

## Throughput

| Distinct source IPs | Packets | Wall seconds | Packets/sec | CPU us/packet | Evaluations |
|---|---|---|---|---|---|
| 1 | 60,000 | 2.49 | 24,101 | 41.15 | 2 |
| 50 | 60,000 | 2.93 | 20,476 | 46.09 | 51 |
| 1,000 | 60,000 | 2.89 | 20,738 | 45.05 | 2,001 |

Sustained 20,476-24,101 packets/sec on one core, i.e. 41-49 us of CPU per packet. For scale, saturating a 100 Mbit link with 1500-byte frames is about 8,300 packets/sec, so one core covers a home or small-office link with room to spare.

Cost scales with the number of active sources, not total traffic: each sweep classifies every pending source in a single batched call.

Hand-crafted packets (as in the unit tests) run at only 1,455 packets/sec, because they carry no IP length field or raw bytes and Scapy must rebuild them to answer a length query. Live capture never takes that path; `packet_length()` reads the wire values instead.

## Detection latency

Time from an attack's first packet to the block decision, over 15 runs: median **317 ms**, p95 322 ms, worst 323 ms.

The floor is the one-second evaluation interval: a source is judged at most once per 1s, so an attack is confirmed within about a second of crossing a threshold.

## Memory

| Tracked source IPs | RSS growth | Traced peak | Per source |
|---|---|---|---|
| 100 | 0.2 MB | 0.2 MB | 1.7 KB |
| 1,000 | 2.9 MB | 2.0 MB | 2.0 KB |
| 5,000 | 3.6 MB | 9.2 MB | 1.8 KB |

Memory is bounded by the rolling 10s window: entries older than that are dropped on every packet, and idle sources are evicted every 30s, so usage tracks active sources rather than total traffic seen.

## Idle cost and startup

- Idle CPU (running, no traffic): 0.00% of one core, the once-a-second sweep thread.
- Model load from disk: 4 ms.
- One classification on its own (both models): 0.499 ms.
- Per source when classified in a batch of 500: 0.0075 ms (67x cheaper). Each sweep classifies all pending sources in one call for this reason.

## Reproduce

```
python -m evaluation.benchmark --packets 60000
```