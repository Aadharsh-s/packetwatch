# Running PacketWatch for the review

Everything below runs from the project folder:

```
cd C:\Aadharsh\project
```

---

## A. The night before (15 minutes, do this once)

Open **PowerShell as Administrator** (right-click → Run as administrator) and run:

```
pip install -r requirements.txt
python -m packetwatch --train
python -m packetwatch.vuln --update-feeds
python -m unittest discover tests
python -m packetwatch --list-ifaces
```

What you should see: training prints two accuracy tables, the feeds download
about 4 MB, the tests end in `OK` (56 tests), and the interface list contains
`'Wi-Fi'`. Write your interface name down - every live command needs it.

Then rehearse the blocking test once, so nothing is a surprise:

```
python -m packetwatch --test-block 203.0.113.50
```

It adds a real firewall rule for a reserved test address, prints it, and removes
it again. If that works, the live demo will work.

**Keep this in your pocket:** if anything misbehaves during the review, run
`python -m packetwatch --unblock-all` to remove every rule PacketWatch made.

---

## B. The demo, in order (about 6 minutes)

### 1. The offline demo - always works, no Administrator needed

```
python -m packetwatch --simulate
```

Seven kinds of traffic go through the complete system. Point out:

- normal browsing and DNS are **allowed** - no false alarms;
- the port scan, the floods and the brute force are **blocked**;
- every block states the number that triggered it: *"51 ports, threshold 10"*;
- the last one is **CRITICAL** because three rules fired at once.

Say: *"Firewall commands are only printed here, so this is safe to run anywhere."*

### 2. The two modules working together

```
python -m packetwatch.vuln --report tests/fixtures/openvas_report.xml --json risk.json
```

A scanner's report is ranked by how likely each weakness is to be used against
you. Point at the reasons: one is listed by the government as actively
exploited, another has a 79% chance of attack in the next 30 days.

```
python -m packetwatch --simulate --risk-map risk.json
```

The same attacks as step 1, but now the system knows which services are
vulnerable: alerts escalate to CRITICAL and name the CVE. This is the paper's
"integrated framework" in one line.

### 3. Live capture on real traffic (Administrator window)

```
python -m packetwatch --dry-run --iface "Wi-Fi"
```

Leave it running while you browse a website. It watches genuine traffic and
raises no alerts on normal use. Stop with **Ctrl+C**.

Say: *"Dry run means it decides everything but only prints what it would block."*

### 4. Real blocking (the moment that lands)

In the Administrator window:

```
python -m packetwatch --iface "Wi-Fi"
```

From a **second device on the same Wi-Fi** (a laptop with nmap, or a phone
running an app like Fing that scans the network):

```
nmap -sS <your-ip>
```

PacketWatch names the address, states the rule it broke, and blocks it. Prove it
is real - open a third window and run:

```
netsh advfirewall firewall show rule name=all | findstr PacketWatch
```

Clean up afterwards:

```
python -m packetwatch --unblock-all
```

### 5. The evidence (have these open in tabs, do not run them live)

| File | What to say |
|---|---|
| `EVALUATION.md` | Tested on 2.83 million real network records from CIC-IDS2017 |
| `UNSW_EVALUATION.md` | A second dataset, where we report where the system fails |
| `VULN_EVALUATION.md` | The ranking tested against real exploited-vulnerability data |
| `BENCHMARK.md` | Speed and memory, measured rather than claimed |

```
python -m unittest discover tests
```

56 tests in ten seconds is a strong closing slide.

---

## C. If something goes wrong

| Problem | Fix |
|---|---|
| `No module named packetwatch` | You are in the wrong folder. `cd C:\Aadharsh\project` |
| `must run from an Administrator terminal` | Right-click PowerShell → Run as administrator |
| `Npcap not detected` | Install from npcap.com, tick "WinPcap API-compatible mode" |
| Wrong interface / no packets | `python -m packetwatch --list-ifaces`, then pass `--iface "<name>"` |
| Nothing gets blocked live | The attacking device must be **another** machine; your own PC and router are never blocked |
| Firewall rules left behind | `python -m packetwatch --unblock-all` |
| Anything at all fails live | Fall back to `python -m packetwatch --simulate`, which needs nothing |

---

## D. Questions you will be asked

**"Is this just the paper re-implemented?"**
No. Both of its modules are rebuilt, but Snort and iptables are replaced with our
own rule engine and Windows Firewall, and we linked the two modules, which the
paper describes but does not detail. The comparison table is at the top of the
README.

**"How accurate is it?"**
On the attacks it targets - scans and floods - F1 is 0.97, against the paper's
0.91. Across every attack type in the dataset, including ones it cannot see, it
is 0.90. Both numbers are in `EVALUATION.md`; quote the second one first.

**"What can it not detect?"**
Attacks that look like ordinary web browsing - slow attacks, website attacks,
malware phoning home. They arrive on normal ports at normal speeds. Catching
them needs reading traffic contents, which is what Snort does and our rules
cannot. That is the honest limit, and it is written down.

**"Where does your training data come from?"**
Traffic patterns we generated. We tested the alternative three times: models
trained on real public captures flagged 99% of ordinary browsing as an attack,
because that capture's normal traffic is machine-generated and unnaturally
dense. The evidence is in `UNSW_EVALUATION.md`.

**"What if someone floods it to use up memory?"**
They cannot. Nothing is stored per packet - each source keeps one small set of
counters per second. A 200,000-packet flood costs 7 KB. `BENCHMARK.md` has the
before-and-after numbers.
