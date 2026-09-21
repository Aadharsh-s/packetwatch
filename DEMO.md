# Running PacketWatch for the review

Everything runs from the project folder:

```
cd C:\Aadharsh\project
```

---

## A. The night before (15 minutes, once)

Open **PowerShell as Administrator** (right-click, Run as administrator):

```
pip install -r requirements.txt
python -m packetwatch --train
python -m unittest discover tests
python -m packetwatch --list-ifaces
```

You should see two accuracy tables from training, `OK` after 57 tests, and your
adapter in the list (usually `'Wi-Fi'`). Every live command needs that name.

Then rehearse the firewall step, so nothing is new on the day:

```
python -m packetwatch --test-block 203.0.113.50
```

It adds a real Windows Firewall rule for a reserved test address, prints it and
removes it again. If this works, blocking will work in the demo.

**Prepare the second device.** For the live block you need another device you
own, on the **same router Wi-Fi** as the laptop: a phone with a network scanner
app, or a laptop with nmap. Do a full rehearsal of step B3 at home.

**Your undo button for the whole review:** `python -m packetwatch --unblock-all`
removes every rule PacketWatch created.

---

## B. The demo, in order (about 6 minutes)

### 1. The whole system, offline (no Administrator needed)

```
python -m packetwatch --simulate
```

Seven kinds of traffic go through capture, both models, the rules and the
firewall step. Point out:

- normal browsing and DNS are **allowed**: no false alarms;
- the port scan, the floods and the brute force are **blocked**;
- every block states the number behind it, e.g. *"51 ports, threshold 10"*;
- the last attack is **CRITICAL** because three rules fired at once.

Say: *"Firewall commands are only printed here, so this runs anywhere."*

### 2. Live traffic, watching only (Administrator window)

```
python -m packetwatch --dry-run --iface "Wi-Fi"
```

Browse a website while it runs. It watches genuine traffic and stays quiet on
normal use. Stop with **Ctrl+C**.

Say: *"Dry run makes every decision but only prints what it would block."*

### 3. A real block from a second device (the moment that lands)

Start it for real in the Administrator window, and note your laptop's IP from
the "protected addresses" line it prints:

```
python -m packetwatch --iface "Wi-Fi"
```

From the **second device**, scan the laptop. With nmap:

```
nmap -Pn -p 22,23,135,139,445,3389,1433,5900 <laptop-ip>
```

`-Pn` matters: without it, nmap first checks whether the laptop is alive,
Windows Firewall silently drops that check, and nmap gives up before scanning.
Aiming at these eight service ports trips the suspicious-port rule even at a
slow scan speed. For a CRITICAL alert, where two rules fire, scan faster and wider:

```
nmap -Pn -T4 -p 1-300 <laptop-ip>
```

With a phone app such as Fing, open the laptop's entry and run its port scan.

PacketWatch names the device, states the rule and the observed value, and blocks
it. Prove the block is real, in another Administrator window:

```
netsh advfirewall firewall show rule name=all | findstr PacketWatch
```

Then clean up:

```
python -m packetwatch --unblock-all
```

Worth saying: *"No ports need to be open on the laptop - we see the attempts,
even the ones Windows Firewall drops."*

### 4. The evidence (open in tabs; don't run live)

| File | What to say |
|---|---|
| `MODEL_COMPARISON.md` | The base paper's model comparison, repeated on our features |
| `TON_IOT_EVALUATION.md` | The base paper's own dataset and its cross-dataset test |
| `EVALUATION.md` | The full pipeline on 2.83 million CIC-IDS2017 flows |
| `UNSW_EVALUATION.md` | A second dataset, where we report where the system fails |
| `BENCHMARK.md` | Speed and memory, measured rather than claimed |
| `docs/architecture.png` | The five-stage pipeline |

Close with:

```
python -m unittest discover tests
```

57 tests in about fifteen seconds.

### 5. Optional: the vulnerability extension

Only if there is time; it goes beyond the base paper.

```
python -m packetwatch.vuln --report tests/fixtures/openvas_report.xml --json risk.json
python -m packetwatch --simulate --risk-map risk.json
```

A scan report is ranked by exploitation risk, and the same attacks as step 1 now
escalate to CRITICAL and name the vulnerability they target.

---

## C. If something goes wrong

| Problem | Fix |
|---|---|
| `No module named packetwatch` | Wrong folder: `cd C:\Aadharsh\project` |
| `must run from an Administrator terminal` | Right-click PowerShell, Run as administrator |
| `Npcap not detected` | Install from npcap.com with "WinPcap API-compatible mode" ticked |
| No packets / wrong adapter | `python -m packetwatch --list-ifaces`, then `--iface "<name>"` |
| Log shows the device but `unique_dst_ports: 2` and no block | nmap stopped at its alive check: add `-Pn` |
| "ML-flagged, not verified" and no block | The scan is too slow for the rules. Aim at the service ports above, or scan faster |
| Scanning from the laptop itself does nothing | By design: your own machine is never blocked. Use a second device |
| Works on router Wi-Fi, not on a phone hotspot | The hotspot phone *is* the router, and the router is never blocked. Use router Wi-Fi, or a third device on the hotspot |
| College Wi-Fi: devices can't reach each other | Many networks isolate clients. Use home Wi-Fi or a hotspot plus a third device |
| Firewall rules left behind | `python -m packetwatch --unblock-all` |
| Anything fails live | Fall back to `--simulate` and `--test-block 203.0.113.50`: together they prove the decisions and the real firewall action |

---

## D. Questions you will be asked

**"What is your base paper, and what did you add?"**
Ismail, Dandan and Qushou, *IEEE Access*, 2025. They compare lightweight ML
models for intrusion detection and run them live, but only to monitor and log.
We repeated their comparison on our features and datasets, deployed the best
lightweight option, and added what turns detection into prevention: rule
verification, automatic Windows Firewall blocking, explainable alerts and
memory that stays bounded under attack.

**"Why a Decision Tree and not Random Forest, which scored higher?"**
On UNSW-NB15 Random Forest scores F1 0.829 against the tree's 0.733, but it is
79 MB against 9 KB and about 45 times slower per prediction. On TON_IoT the
tree scores 0.994 against 0.998. For a tool running constantly on one PC, the
tree gives 88-99% of the accuracy at a tiny fraction of the cost, needs no
tuning, and its decisions can be read as rules.

**"How accurate is it?"**
On CIC-IDS2017's 2.83 million flows, the full pipeline scores F1 0.92 across all
attack types, and 0.98 on the scans and floods it is designed for, with a 1%
false positive rate. Quote both, the lower one first.

**"What can it not detect?"**
Attacks that look like ordinary web browsing - slow DoS, web attacks, botnet
traffic. They arrive on normal ports at normal speeds, so no rule based on
packet headers can separate them. Catching them needs reading traffic contents,
which is future work.

**"Why no Snort?"**
The base paper does not use it. Our verification rules are simpler and every
decision is explainable. Snort's payload inspection is the natural next step for
the blind spot above.

**"Why not all three of the base paper's datasets?"**
WUSTL-IIoT-2021 has no public mirror. We prioritised TON_IoT, the paper's primary
dataset, and added CIC-IDS2017 and UNSW-NB15, which let us test the live
pipeline itself.

**"Where does the training data come from?"**
Traffic patterns we generated. We tested training on real public captures three
ways: those models flagged up to 99% of ordinary browsing as attacks, because
the captures' normal traffic is machine-generated and unnaturally dense.
`UNSW_EVALUATION.md` has the evidence.

**"Could someone flood it to use up memory?"**
No. Nothing is stored per packet; each source keeps a fixed set of counters per
second. A 200,000-packet flood costs 7 KB, and the worst case is capped at 27 MB.
`BENCHMARK.md` has the numbers.
