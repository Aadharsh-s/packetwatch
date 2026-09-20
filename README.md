# PacketWatch

A single-host IDS/IPS for Windows, adapting the VPID framework to one machine. It covers both of VPID's modules - intrusion defence, running live on this host, and vulnerability prioritisation, run offline over a scanner's report - and links them, so what the scanner found changes how the detector reacts.

### Module 2: intrusion defence

```
Scapy sniff()  ->  per-IP features  ->  Decision Tree + Multinomial NB  ->  rule verification  ->  netsh block + alert
  (capture)                                (detection, OR fusion)           (Snort's role)         (iptables' role)
```

| Stage | VPID | PacketWatch |
|---|---|---|
| Capture | Scapy | `scapy.sniff()` (`packetwatch/capture.py`) |
| Detection | Decision Tree + Naive Bayes | `DecisionTreeClassifier` + `MultinomialNB` (`packetwatch/model.py`) |
| Verification | Snort | Deterministic threshold rules (`packetwatch/verify.py`) |
| Response | iptables | `netsh advfirewall firewall add rule` (`packetwatch/response.py`) |

### Module 1: vulnerability prioritisation

| Stage | VPID | PacketWatch |
|---|---|---|
| Asset and vulnerability discovery | OpenVAS | reads the OpenVAS/GVM XML report (`packetwatch/vuln/openvas.py`) - the scanner is Linux-only, so PacketWatch consumes its output rather than running it |
| Prioritisation | Decision tree | KEV -> EPSS -> decision tree -> CVSS cascade (`packetwatch/vuln/model.py`) |
| Validation | Rule engine generating exploit payloads | connect-and-identify exposure checks only (`packetwatch/vuln/validate.py`) |

```
python -m packetwatch.vuln --update-feeds                    # fetch CISA KEV + EPSS
python -m packetwatch.vuln --report scan.xml --validate      # rank, then check exposure
```

Every ranked item says which signal decided it:

```
CRITICAL   100.0  192.168.0.50    445/tcp   CVE-2017-0144
                  -> listed in CISA KEV on 2022-02-10: known to be exploited in the wild
HIGH        81.8  192.168.0.50    22/tcp    CVE-2023-38408
                  -> EPSS puts the chance of exploitation in the next 30 days at 79.7%
```

**Why a cascade and not just the decision tree.** Trained to predict CISA KEV membership from CVE fields, the decision tree ranks *worse* than the CVSS score it is built from (AUC 0.71 vs 0.77), while EPSS reaches 0.97. Whether attackers adopt a vulnerability depends on what is widely deployed and whether exploit code circulates, and a CVE record says neither. Shipping the tree alone would have been worse than sorting by severity, so it is kept only for CVEs that have no EPSS score yet. Full working in [VULN_EVALUATION.md](VULN_EVALUATION.md).

**Two things this module will not do.** It does not run the scanner, and it does not confirm a vulnerability by exploiting it. The validation step opens a TCP connection, reads a banner, and for HTTP sends an ordinary HEAD - nothing malformed and nothing vulnerability-specific. It also refuses non-private addresses unless `--allow-external` is passed, so a mis-parsed report cannot send traffic to a stranger.

### The two modules together

VPID's point is that the modules feed each other: prioritising vulnerabilities is only useful if the detector then knows which services are worth defending hardest. Hand the vulnerability module's output to the detector as a risk map:

```
python -m packetwatch.vuln --report scan.xml --json risk.json
python -m packetwatch --risk-map risk.json --iface "Wi-Fi"
```

Traffic aimed at a port the scanner flagged CRITICAL or HIGH is then judged less forgivingly:

- **one rule is enough to block** it, instead of the usual two, because the target is known-vulnerable rather than merely noisy;
- **severity rises a level**, so an alert against a known-exploited service reads CRITICAL;
- **the alert names the CVE**, so whoever reads it knows why.

The same slow SMB probe, with and without the map:

```
[CRITICAL] 10.9.9.9 -> blocked | suspicious_port: observed 3 >= threshold 3 | targets CVE-2017-0144
[HIGH]     10.9.9.9 -> blocked | suspicious_port: observed 3 >= threshold 3
```

Nothing is relaxed for ports outside the map, and running without one leaves the detector exactly as it was.

## Setup

1. Install [Npcap](https://npcap.com) and tick "WinPcap API-compatible mode".
2. Install the Python dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run PacketWatch from an **Administrator** terminal. Packet capture and firewall changes both need elevation.

## Usage

```
python -m packetwatch --list-ifaces              # find your interface name
python -m packetwatch --train                    # train both models, print reports
python -m packetwatch --simulate                 # offline demo of the whole pipeline (no admin)
python -m packetwatch --simulate --risk-map risk.json   # the same demo, with scan findings applied
python -m packetwatch --dry-run                  # capture + detect, only LOG firewall commands
python -m packetwatch --iface "Wi-Fi"            # live: real blocking
python -m packetwatch --test-block 203.0.113.50  # prove netsh enforcement works (adds, shows, removes)
python -m packetwatch --unblock-all              # remove every PacketWatch_Block_* rule
python -m unittest discover tests                # tests (no admin needed)
python -m evaluation.cicids2017 --data <dir>     # accuracy on CIC-IDS2017 flows
python -m evaluation.benchmark                   # throughput, latency, CPU, memory
```

Alerts are printed to the console and appended as JSON lines to `alerts.log`.

## Design decisions (not taken from the VPID paper)

- **Features:** each source IP has a rolling 10 s window. The features are:
  - packet count and peak packets per second;
  - unique destination ports and unique destination IPs;
  - TCP, UDP and ICMP counts;
  - SYN-only count;
  - suspicious-port hits;
  - average packet length (bucketed).

  All features are non-negative integers, as MultinomialNB requires.
- **Fusion (OR):** a source is flagged when *either* classifier predicts "attack". This favours recall. The verification step removes false positives before anything is blocked.
- **When a block happens:** normally the classifiers must flag a source *and* a rule must confirm it. As an exception, **two or more distinct rules firing at once block on their own** (`INDEPENDENT_RULE_TRIGGER` in `config.py`; set it to 0 to require the ML first). This was added after the CIC-IDS2017 evaluation showed that attack types missing from training were never blocked, even when the rules caught them clearly: cross-day recall rose from 44% to 99.4%. Every alert records which path fired, as `trigger: ml+rule` or `trigger: rules-only`.
- **Verification rules**, all set in `config.py`:
  - port scan: at least 10 unique destination ports in the window;
  - flood: at least 100 packets per second;
  - suspicious ports: at least 3 hits on 21/22/23/135/139/445/1433/3306/3389/4444/5432/5900/6667.

  A source is blocked only if at least one rule fires. If the ML flags a source but no rule fires, it is logged and not blocked.
- **Severity:** HIGH by default. It rises to CRITICAL when one IP trips two or more distinct rules within 60 s.
- **Blocking:** each blocked IP gets inbound and outbound rules named `PacketWatch_Block_<ip>_in/_out`.
  - Blocks expire after 30 min while PacketWatch is running.
  - Your own IPs, the default gateway, loopback and `--whitelist` entries are never blocked.
  - IPs are validated with `ipaddress` before use, and netsh is called without a shell.
- **Evaluation cadence:** active sources are judged once per second by a sweep. The sweep is triggered by incoming packets and by a background ticker, so a short burst is still judged after the attacker goes quiet.
- **Only inbound traffic is judged.** Packets whose source is this host are ignored.

## Measured results

Evaluated on all of CIC-IDS2017: 2.83M flows across eight captures, covering scans, DoS, DDoS, FTP/SSH brute force, web attacks, infiltration, Heartbleed and botnet traffic. Full write-up in [EVALUATION.md](EVALUATION.md); rerun with `python -m evaluation.cicids2017 --data <dir>`.

Per-flow, random 70/30 split:

| Metric | VPID (paper) | PacketWatch |
|---|---|---|
| Precision | 94.5% | 84.5% |
| Recall | 88.3% | 96.7% |
| F1 | 91.3% | 90.2% |
| False positive rate | under 1.5% | 4.28% |

Not like-for-like: VPID used its own 550,000 flows and a separate 55,000-flow test set. Our figure covers every attack type in CIC-IDS2017, including ones this feature set cannot see. On the scans and floods PacketWatch is built for, the same pipeline scores F1 0.97.

**A second dataset, UNSW-NB15.** CIC-IDS2017's attack captures timestamp flows to the minute, so windows there had to be widened to 60s. UNSW-NB15 records flow start and end in seconds, so windows can be built at the live system's real 10s with a true peak-1-second rate. Results are in [UNSW_EVALUATION.md](UNSW_EVALUATION.md), and they are unflattering: its attacks are low-volume exploits and fuzzing, *quieter* than its machine-generated benign traffic, so the rule layer is inverted and the pipeline blocks about 10% of attack windows. Models trained on it reach 98.5% recall but flag a quarter of benign windows, so they are **not** shipped. The synthetic models remain the default, and that report is the honest account of where they fail.

**Where it is blind.** The classifiers catch nearly every attack type, so the rule layer decides what gets blocked, and it only sees volume and port spread. Slow DoS, web brute force, XSS, SQL injection and botnet C2 all arrive on port 80 or 8080 at ordinary rates, and no header-based threshold separates them from real browsing. Catching those needs payload inspection, which is what Snort provides in VPID. SSH brute force was in that blind spot until port 22 was added to the suspicious list.

## Calibrating the thresholds to your host

The three rule thresholds are stock values for a home or small-office link, and that assumption is the rule layer's weakest part. `--calibrate` replaces them with values derived from a quiet baseline of your own traffic:

```
python -m packetwatch --calibrate 300 --iface "Wi-Fi"
```

It watches for 300 seconds, takes the 99.9th percentile of what each source did per window, and writes `packetwatch/models/thresholds.json`, which is loaded on the next start. Delete that file to return to the stock values.

Measured effect on the rule layer's false positives: 21.8% to 2.8% on UNSW-NB15, and 1.64% to 0.37% on CIC-IDS2017 while slightly raising recall. Safety floors and ceilings stop a quiet baseline from making the rules trigger-happy or a busy one from making them blind.

**The baseline must be quiet.** Anything happening during calibration is learned as normal, so do not scan or flood the machine while it runs.

## Resource cost

Measured by `python -m evaluation.benchmark`; full numbers in [BENCHMARK.md](BENCHMARK.md).

| | |
|---|---|
| Throughput | 20,000-24,000 packets/sec on one core (~50 us/packet) |
| Detection latency | ~300 ms from first attack packet to block |
| Memory | ~1 KB per tracked source; 3.6 MB at 5,000 active sources |
| Idle CPU | ~0.5% of one core |

For scale, saturating a 100 Mbit link with full-size frames is about 8,300 packets/sec, so one core covers a home or small-office link with headroom.

Benchmarking found two real inefficiencies, both now fixed: classifying sources one at a time cost 72x more than classifying a sweep's worth in one call, and `len(pkt)` made Scapy rebuild every packet (checksums included) just to read a length, which was 88% of per-packet cost. `packet_length()` reads the wire values instead.

## Project layout

```
packetwatch/
  capture.py      Scapy sniff() with Npcap and Administrator preflight checks
  features.py     per-source-IP rolling window and the 10 features
  model.py        Decision Tree + Multinomial NB, OR fusion, batched prediction
  verify.py       the threshold rules, defined once and shared with the evaluations
  calibrate.py    learns thresholds from a quiet baseline of your own traffic
  riskmap.py      links Module 1's findings into Module 2's decisions
  response.py     Windows Firewall blocking and JSON alerting
  pipeline.py     packet -> features -> classifiers -> rules -> block + alert
  simulate.py     offline demo, no admin or Npcap needed
  vuln/           Module 1: OpenVAS report parsing, prioritisation, exposure checks
evaluation/
  cicids2017.py   accuracy on CIC-IDS2017 (2.83M flows, 8 captures)
  unsw_nb15.py    accuracy on UNSW-NB15 at real 10s windows
  vuln_priority.py  the prioritiser against CISA KEV, with CVSS and EPSS baselines
  benchmark.py    throughput, latency, CPU and memory
tests/            46 tests; no Administrator rights or network needed
```

Reports produced by those scripts: [EVALUATION.md](EVALUATION.md), [UNSW_EVALUATION.md](UNSW_EVALUATION.md), [VULN_EVALUATION.md](VULN_EVALUATION.md), [BENCHMARK.md](BENCHMARK.md).

## Limitations

- **The shipped models are trained on synthetic behaviour profiles.** This was tested rather than assumed: models trained on UNSW-NB15's real 10s windows reach 98.5% recall but flag a quarter of benign windows, and when shown ordinary traffic they flag 99% of it. Restricting their training to UNSW's volumetric attacks (the kind PacketWatch targets) did not help. Its benign traffic is machine-generated and dense, so a model trained there treats normal browsing as an attack. CIC-IDS2017 cannot supply a replacement either, because its attack days timestamp only to the minute. The synthetic models therefore remain the default, with [UNSW_EVALUATION.md](UNSW_EVALUATION.md) as the record of why.
  - Benign profiles: browsing, DNS, streaming, LAN chatter.
  - Attack profiles: fast and slow scans; UDP, ICMP and SYN floods; brute force against suspicious ports.

  The near-perfect Decision Tree score on that synthetic hold-out only shows it fits the synthetic data; the CIC-IDS2017 numbers above are the real measure. To train on your own traffic:
  1. Record it with `--record rows.csv`.
  2. Fill in the `label` column (0 or 1).
  3. Retrain with `--train --csv rows.csv`.
- MultinomialNB is weaker on this data (about 0.91 accuracy on the synthetic hold-out). It contributes through the OR fusion.
- Blocks made by a run that is later killed stay in place until you run `--unblock-all`.
