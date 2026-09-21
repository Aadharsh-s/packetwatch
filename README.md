# PacketWatch

A lightweight, CPU-only intrusion detection and prevention system for a single Windows machine. It watches live network traffic, classifies each remote host's behaviour with a Decision Tree and a Multinomial Naive Bayes model, confirms every flag with explainable threshold rules, and blocks confirmed attackers through Windows Firewall.

## Base paper

S. Ismail, S. Dandan and A. Qushou, "Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets," *IEEE Access*, vol. 13, pp. 73468-73485, 2025, doi: [10.1109/ACCESS.2025.3554083](https://doi.org/10.1109/ACCESS.2025.3554083). Open access.

The paper compares lightweight ML models for intrusion detection (Decision Tree, Random Forest, Bagging, Stacking, LightGBM), selects features with Mutual Information, measures model size and training time alongside accuracy, tests whether models transfer between datasets, and deploys the models live to **monitor and log** predictions.

PacketWatch takes that to a working **prevention** system on an ordinary PC:

| | Base paper | PacketWatch |
|---|---|---|
| Models | DT, RF, Bagging, Stacking, LightGBM | Same five compared; **DT + Multinomial NB** deployed, chosen on the comparison |
| Feature selection | Mutual Information | Mutual Information ranking of PacketWatch's 10 features |
| Metrics | Precision, recall, micro-F1, model size, training time | The same, plus prediction cost per sample |
| Datasets | TON_IoT, WUSTL-IIoT-2021, Edge-IIoTset | TON_IoT, CIC-IDS2017, UNSW-NB15 |
| Cross-dataset transfer | TON_IoT to WUSTL-IIoT-2021 | TON_IoT to and from UNSW-NB15 |
| Live deployment | Predictions logged, CPU and memory monitored | Live capture, CPU and memory measured, **and**: |
| Verification | - | Threshold rules must confirm every flag before action |
| Response | - | Automatic Windows Firewall blocking, expiring after 30 min |
| Explainability | - | Every alert states the rule, the observed value and the threshold |
| Robustness | - | Memory bounded under attack; thresholds calibratable per host |

## How it works

```
Scapy sniff()  ->  per-source 10 s window  ->  Decision Tree + Multinomial NB  ->  rule verification  ->  Windows Firewall block
  (capture)          (10 features)              (flag if either model agrees)     (must confirm)          + explainable alert
```

1. **Capture.** Scapy reads live traffic from the network adapter through Npcap. Each packet is processed once and dropped; nothing is stored.
2. **Features.** Every remote host gets a rolling 10-second summary of 10 numbers: packet count, peak packets per second, distinct ports and destinations contacted, TCP/UDP/ICMP counts, SYN-only packets, suspicious-port hits and average packet size.
3. **Detection.** A Decision Tree and a Multinomial Naive Bayes model score each summary. Either one can flag the host.
4. **Verification.** A flag only counts if a rule confirms it: 10 or more ports contacted (port scan), 100 or more packets per second (flood), or 3 or more hits on ports such as SSH, SMB and RDP. Two rules firing together are strong enough to block on their own.
5. **Response.** The host is blocked through Windows Firewall, and the alert records why.

## Quick start

**Requirements:** Windows, Python 3.10 or newer (tested on 3.13), and [Npcap](https://npcap.com) (tick "WinPcap API-compatible mode" when installing).

```
cd C:\Aadharsh\project
pip install -r requirements.txt
python -m packetwatch --train
```

**See it work without Administrator rights** - fake traffic through the complete system, with firewall commands only printed:

```
python -m packetwatch --simulate
```

**Run it for real** from an Administrator PowerShell (right-click, Run as administrator):

```
python -m packetwatch --list-ifaces              # find your adapter's name, e.g. Wi-Fi
python -m packetwatch --dry-run --iface "Wi-Fi"  # watch live traffic, only print what it would block
python -m packetwatch --iface "Wi-Fi"            # watch and block for real; Ctrl+C to stop
python -m packetwatch --unblock-all              # remove every rule PacketWatch created
```

For a step-by-step demo, including triggering a real block from a second device, see [DEMO.md](DEMO.md).

## Command reference

| Command | What it does | Admin? |
|---|---|---|
| `python -m packetwatch --simulate` | Offline demo of the whole pipeline | No |
| `python -m packetwatch --train` | Retrain both models; prints accuracy reports | No |
| `python -m packetwatch --list-ifaces` | List network adapters | No |
| `python -m packetwatch --iface "Wi-Fi"` | Live detection and blocking | Yes |
| `python -m packetwatch --dry-run --iface "Wi-Fi"` | Live detection, blocking only printed | Yes |
| `python -m packetwatch --test-block 203.0.113.50` | Add a real firewall rule for a test address, show it, remove it | Yes |
| `python -m packetwatch --unblock-all` | Remove every `PacketWatch_Block_*` rule | Yes |
| `python -m packetwatch --calibrate 300 --iface "Wi-Fi"` | Learn thresholds from 300 s of your normal traffic | Yes |
| `python -m packetwatch --record rows.csv --iface "Wi-Fi"` | Save live feature rows, to label and retrain on | Yes |
| `python -m packetwatch --train --csv rows.csv` | Retrain including your labelled rows | No |
| `python -m unittest discover tests` | Run the 57 tests | No |

Other options: `--whitelist IP ...` never blocks the listed addresses; `--timeout N` stops after N seconds; `-v` gives verbose logging. Alerts are printed and also appended as JSON lines to `alerts.log`.

## Results

### Lightweight model comparison (the base paper's protocol)

All six models were trained identically on the same features. Full tables, including multi-class results and Mutual Information rankings, are in [MODEL_COMPARISON.md](MODEL_COMPARISON.md) and [TON_IOT_EVALUATION.md](TON_IOT_EVALUATION.md).

**UNSW-NB15** (802,356 windows of PacketWatch's own features, attack vs. normal):

| Model | F1 | False alarms | Model size | Time per prediction |
|---|---|---|---|---|
| **Decision Tree** | **0.733** | 0.95% | **9 KB** | **0.09 us** |
| LightGBM | 0.810 | 0.74% | 1.4 MB | 12.4 us |
| Bagging | 0.827 | 0.73% | 34 MB | 5.1 us |
| Stacking | 0.827 | 0.68% | 39 MB | 2.4 us |
| Random Forest | 0.829 | 0.71% | 79 MB | 4.2 us |

**TON_IoT** (211,043 records, the base paper's primary dataset, per-record as in the paper):

| Model | F1 | False alarms | Model size |
|---|---|---|---|
| **Decision Tree** | **0.994** | 2.67% | **9 KB** |
| LightGBM | 0.998 | 0.44% | 1.4 MB |
| Random Forest | 0.998 | 0.46% | 6.9 MB |

The ensembles gain up to 0.10 F1, at up to 8,700 times the model size and up to 140 times the prediction cost. On one PC, the 9 KB Decision Tree gets 88-99% of the best score, which is why it is the model PacketWatch deploys.

**Mutual Information** ranks packets per second, TCP count, packet count and distinct ports as the most informative of PacketWatch's features; SYN-only and ICMP counts carry almost none.

**Cross-dataset transfer.** Trained on TON_IoT and tested on UNSW-NB15, or the reverse, every model collapses to F1 0.05-0.22. Models do not carry over between capture environments.

### The full pipeline on CIC-IDS2017

2.83 million flows across eight captures, measured per flow on a random 70/30 split. Full write-up in [EVALUATION.md](EVALUATION.md).

| Metric | PacketWatch |
|---|---|
| Precision | 88.3% |
| Recall | 96.7% |
| F1 | 92.3% |
| False positive rate | 3.08% |

On the scans and floods PacketWatch is built for, F1 is **0.98** with a **1.0%** false positive rate. Trained on some days and tested on attacks from other days, recall is 98.8%.

Rule verification is what keeps false alarms low: the two models alone flag 6.5% of normal traffic, and requiring a rule to confirm cuts that to 3.1%.

### Where it is blind

The rules see volume and port spread, not content. Slow DoS, web brute force, XSS, SQL injection and botnet traffic arrive on ports 80 or 8080 at ordinary rates, and no header-based threshold separates them from real browsing. Catching those needs payload inspection (for example Snort), which is future work.

On UNSW-NB15, whose attacks are low-volume exploits that are *quieter* than its generated background traffic, the rule layer blocks about 10% of attack windows. [UNSW_EVALUATION.md](UNSW_EVALUATION.md) documents this in full.

## Calibrating the thresholds

The three thresholds are stock values for a home or small-office link. `--calibrate` replaces them with values learned from a quiet baseline of your own traffic:

```
python -m packetwatch --calibrate 300 --iface "Wi-Fi"
```

It watches for 300 seconds, takes the 99.9th percentile of what each source did, and writes `packetwatch/models/thresholds.json`, loaded on the next start. Delete that file to return to the stock values. Measured effect on the rules' false positives: 21.8% to 2.8% on UNSW-NB15, and 1.64% to 0.37% on CIC-IDS2017. **Don't scan or flood the machine while calibrating** - whatever happens is learned as normal.

## Resource cost

Measured by `python -m evaluation.benchmark`; full numbers in [BENCHMARK.md](BENCHMARK.md).

| | |
|---|---|
| Throughput | 34,000-45,000 packets/sec on one CPU core |
| Time to block | 140 ms median from the first attack packet |
| Memory per tracked source | about 6 KB, fixed |
| Memory under a 200,000-packet flood | 7 KB for that source |
| Worst case (4,096 sources, the cap) | 27 MB |
| Idle CPU | under 1% of one core |

Saturating a 100 Mbit link with full-size frames is about 8,300 packets/sec, so one core covers a home or office link with headroom.

**Memory is bounded by design.** Nothing is stored per packet: each source keeps one small set of counters per second of the window, recycled as the window slides. That costs about 6 KB per source whether it sends one packet a second or a million, where the earlier per-packet design cost 25.7 MB for one flooding source. Everything else that could grow is capped too (limits in `config.py`): at most 4,096 tracked sources, idle sources released after 60 s, 256 distinct ports per source, expired alerts forgotten, and `alerts.log` rotated at 5 MB with 3 old files kept.

## Reproducing the evaluations

Install the extra packages first with `pip install -r requirements-eval.txt`. The datasets are large and not stored in the repository; these are the public mirrors used:

| Dataset | Source | Command |
|---|---|---|
| CIC-IDS2017 | [bvsam/cic-ids-2017](https://huggingface.co/datasets/bvsam/cic-ids-2017), `traffic_labels/*.parquet` | `python -m evaluation.cicids2017 --data <dir>` |
| UNSW-NB15 | [rdpahalavan/UNSW-NB15](https://huggingface.co/datasets/rdpahalavan/UNSW-NB15), `Network-Flows/UNSW_Flow.parquet` | `python -m evaluation.unsw_nb15 --data <dir>` |
| TON_IoT | [codymlewis/TON_IoT_network](https://huggingface.co/datasets/codymlewis/TON_IoT_network), `train_test_network.csv` | `python -m evaluation.ton_iot --data <dir> --unsw <dir>` |
| Model comparison | CIC-IDS2017 + UNSW-NB15 | `python -m evaluation.model_comparison --cic <dir> --unsw <dir>` |
| Benchmark | none needed | `python -m evaluation.benchmark` |

Each script rewrites its report (`*.md`) and a matching `*.json` with the raw numbers.

## Design decisions

- **Why Decision Tree + Naive Bayes.** The comparison above: the tree gets 88-99% of the ensembles' F1 at 9 KB and well under a microsecond per prediction, needs no tuning (LightGBM's training diverged at its default learning rate on this data), and its decisions can be read as rules. Naive Bayes is cheaper still and catches cases the tree misses.
- **No class weighting.** On real, imbalanced traffic a class-balanced Decision Tree scored F1 0.44 with 16.8% false alarms; unweighted it scored 0.73 with 0.95%. The shared setting lives in `packetwatch.model.make_tree()`.
- **OR fusion, then verification.** Flag if either model agrees, which favours catching attacks; the rules then remove false alarms before anything is blocked.
- **Two rules can block without the models.** Added after models trained on some attack types missed unseen ones that the rules caught clearly. Every alert records whether it fired as `ml+rule` or `rules-only`.
- **Suspicious ports:** 21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 4444, 5432, 5900, 6667. SSH (22) was added after SSH brute force passed the rules untouched while FTP (21) was caught.
- **Severity:** HIGH by default, CRITICAL when one host trips two or more rules within 60 s.
- **Safety:** your own addresses, your router, loopback and `--whitelist` entries are never blocked; IPs are validated before use; `netsh` is called without a shell.
- **Only inbound traffic is judged.**

## Optional extension: vulnerability prioritisation

Beyond the base paper, PacketWatch includes a module inspired by the VPID framework (X. Chen, X. Wang and X. Li, arXiv:2609.00819, 2026). It reads an OpenVAS scan report, ranks findings by how likely they are to be exploited (CISA's known-exploited list, then EPSS scores, then a decision tree, then CVSS severity), and can check whether a service is actually exposed without attacking it:

```
python -m packetwatch.vuln --update-feeds
python -m packetwatch.vuln --report scan.xml --validate
python -m packetwatch.vuln --report scan.xml --json risk.json
python -m packetwatch --risk-map risk.json --iface "Wi-Fi"
```

With `--risk-map`, traffic aimed at a known-vulnerable port blocks on a single rule, escalates to CRITICAL and names the CVE. Evaluation in [VULN_EVALUATION.md](VULN_EVALUATION.md).

## Project layout

```
packetwatch/
  capture.py      Scapy sniff() with Npcap and Administrator checks
  features.py     per-source rolling window and the 10 features, fixed memory
  model.py        Decision Tree + Multinomial NB, OR fusion, batched prediction
  verify.py       the threshold rules, defined once and shared with the evaluations
  pipeline.py     packet -> features -> models -> rules -> block + alert
  response.py     Windows Firewall blocking and JSON alerting, with log rotation
  calibrate.py    learns thresholds from your own normal traffic
  simulate.py     offline demo, no Administrator rights or Npcap needed
  riskmap.py      applies vulnerability findings to live decisions (optional)
  vuln/           OpenVAS parsing, vulnerability ranking, exposure checks (optional)
evaluation/
  model_comparison.py  base-paper protocol on CIC-IDS2017 and UNSW-NB15
  ton_iot.py           base-paper protocol on TON_IoT, with cross-dataset transfer
  cicids2017.py        full pipeline on CIC-IDS2017
  unsw_nb15.py         full pipeline on UNSW-NB15 at real 10 s windows
  benchmark.py         throughput, latency, CPU and memory
  vuln_priority.py     vulnerability ranking against CISA KEV
docs/             architecture and ER diagrams (regenerate with python docs/<name>.py)
tests/            57 tests; no Administrator rights or network needed
```

## Limitations

- **The deployed models are trained on synthetic traffic patterns**, not real captures. This was tested three ways: models trained on real public captures flagged up to 99% of ordinary browsing as attacks, because those captures' normal traffic is machine-generated and unnaturally dense. The evidence is in [UNSW_EVALUATION.md](UNSW_EVALUATION.md). To train on your own traffic, record it with `--record`, label the rows 0 or 1, and retrain with `--train --csv`.
- **No payload inspection**, so application-layer attacks are invisible (see *Where it is blind*).
- **WUSTL-IIoT-2021 and Edge-IIoTset**, two of the base paper's three datasets, were not evaluated: WUSTL-IIoT-2021 has no public mirror, and TON_IoT was prioritised as the paper's primary dataset.
- **Blocks from a run that was killed** stay in place until `--unblock-all` is run.

## References

1. S. Ismail, S. Dandan and A. Qushou, "Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets," *IEEE Access*, vol. 13, pp. 73468-73485, 2025. **(Base paper)**
2. X. Chen, X. Wang and X. Li, "VPID: An Integrated Framework for Vulnerability Prioritization and Intrusion Detection in Enterprise Networks," arXiv:2609.00819, 2026.
3. I. Sharafaldin, A. H. Lashkari and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP, 2018. (CIC-IDS2017)
4. N. Moustafa and J. Slay, "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems," MilCIS, 2015.
