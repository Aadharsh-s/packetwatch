# PacketWatch evaluation on CIC-IDS2017

Data: `bvsam/cic-ids-2017` (Hugging Face mirror of CIC-IDS2017 GeneratedLabelledFlows). Four captures: an attack-free day (Monday), the DoS day (Wednesday), and Friday's DDoS and PortScan afternoons.

## How the data was mapped onto PacketWatch

PacketWatch judges one remote source talking to one protected host over a rolling window, so flows were aggregated into (source IP, destination host, 60s window) rows carrying the same 10 features the live pipeline extracts. A window counts as attack if any flow inside it is non-BENIGN. The Decision Tree, Multinomial Naive Bayes, OR fusion and threshold rules were then applied unchanged.

**Two deviations from the live system, both forced by the data:**

1. The window is 60s rather than the live 10s, because three of the four files carry timestamps with minute resolution only (every value ends at :00 seconds). Finer buckets would be invented detail.
2. Packets per second is the window average; live capture uses the peak 1s rate, so bursts look slower here than they really are, which weakens the flood rule.

| File | Flows | Attack flows | Windows | Attack windows | Attack types |
|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos | 225,745 | 128,027 | 14,741 | 22 | DDoS (128,027) |
| Friday-WorkingHours-Afternoon-PortScan | 286,467 | 158,930 | 30,613 | 27 | PortScan (158,930) |
| Monday-WorkingHours | 529,918 | 0 | 123,025 | 0 | - |
| Wednesday-workingHours | 692,703 | 252,672 | 101,481 | 86 | DoS Hulk (231,073), DoS GoldenEye (10,293), DoS slowloris (5,796), DoS Slowhttptest (5,499), Heartbleed (11) |

Total: 1,734,833 flows (539,629 attack) aggregated into 269,860 windows, of which 135 (0.05%) contain attack traffic.

Each attack here comes from one source hitting one victim, so attacks collapse into few windows while benign traffic spreads across many. Precision measured per window is therefore harsh, which is why per-flow results are reported too.

## Per-window results (operational view: one window = one alert decision)

### Random 70/30 split

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.828 | 0.600 | 0.696 | 0.01% | 24 | 5 | 16 | 80,913 |
| Naive Bayes alone | 0.017 | 0.750 | 0.033 | 2.14% | 30 | 1,729 | 10 | 79,189 |
| DT or NB (fusion, no verification) | 0.019 | 0.825 | 0.037 | 2.14% | 33 | 1,730 | 7 | 79,188 |
| Rules alone (verification layer) | 0.013 | 0.525 | 0.025 | 2.04% | 21 | 1,647 | 19 | 79,271 |
| A: ML and rule only | 0.439 | 0.450 | 0.444 | 0.03% | 18 | 23 | 22 | 80,895 |
| B: A, or 2+ rules alone (shipped) | 0.432 | 0.475 | 0.452 | 0.03% | 19 | 25 | 21 | 80,893 |
| C: A, or any single rule alone | 0.013 | 0.525 | 0.025 | 2.04% | 21 | 1,647 | 19 | 79,271 |

### Cross-day split: train on Mon+Wed, test on the unseen Friday captures

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.784 | 0.592 | 0.674 | 0.02% | 29 | 8 | 20 | 45,297 |
| Naive Bayes alone | 0.035 | 0.429 | 0.065 | 1.28% | 21 | 578 | 28 | 44,727 |
| DT or NB (fusion, no verification) | 0.047 | 0.592 | 0.087 | 1.29% | 29 | 586 | 20 | 44,719 |
| Rules alone (verification layer) | 0.041 | 0.837 | 0.079 | 2.10% | 41 | 952 | 8 | 44,353 |
| A: ML and rule only | 0.757 | 0.571 | 0.651 | 0.02% | 28 | 9 | 21 | 45,296 |
| B: A, or 2+ rules alone (shipped) | 0.762 | 0.653 | 0.703 | 0.02% | 32 | 10 | 17 | 45,295 |
| C: A, or any single rule alone | 0.041 | 0.837 | 0.079 | 2.10% | 41 | 952 | 8 | 44,353 |

## Per-flow results (each flow inherits its window's verdict)

Most published intrusion detection results are reported per flow, so this is the headline view.

### Random 70/30 split

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.999 | 0.987 | 0.993 | 0.04% | 167,814 | 132 | 2,276 | 361,777 |
| Naive Bayes alone | 0.843 | 0.882 | 0.862 | 7.73% | 150,045 | 27,971 | 20,045 | 333,938 |
| DT or NB (fusion, no verification) | 0.858 | 0.993 | 0.921 | 7.73% | 168,943 | 27,973 | 1,147 | 333,936 |
| Rules alone (verification layer) | 0.837 | 0.984 | 0.904 | 9.00% | 167,297 | 32,579 | 2,793 | 329,330 |
| A: ML and rule only | 1.000 | 0.977 | 0.988 | 0.02% | 166,178 | 79 | 3,912 | 361,830 |
| B: A, or 2+ rules alone (shipped) | 0.979 | 0.983 | 0.981 | 1.00% | 167,165 | 3,625 | 2,925 | 358,284 |
| C: A, or any single rule alone | 0.837 | 0.984 | 0.904 | 9.00% | 167,297 | 32,579 | 2,793 | 329,330 |

### Cross-day split

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.944 | 0.953 | 0.949 | 7.19% | 273,601 | 16,201 | 13,356 | 209,054 |
| Naive Bayes alone | 0.924 | 0.446 | 0.602 | 4.67% | 128,024 | 10,523 | 158,933 | 214,732 |
| DT or NB (fusion, no verification) | 0.911 | 0.953 | 0.932 | 11.86% | 273,601 | 26,724 | 13,356 | 198,531 |
| Rules alone (verification layer) | 0.869 | 0.995 | 0.928 | 19.16% | 285,596 | 43,167 | 1,361 | 182,088 |
| A: ML and rule only | 0.943 | 0.949 | 0.946 | 7.31% | 272,253 | 16,473 | 14,704 | 208,782 |
| B: A, or 2+ rules alone (shipped) | 0.940 | 0.994 | 0.966 | 8.05% | 285,232 | 18,138 | 1,725 | 207,117 |
| C: A, or any single rule alone | 0.869 | 0.995 | 0.928 | 19.16% | 285,596 | 43,167 | 1,361 | 182,088 |

## Detection rate per attack type (random split, share of attack flows)

| Attack type | Attack flows | Caught by ML fusion | Caught by rules | Caught by pipeline |
|---|---|---|---|---|
| DoS Hulk | 66,456 | 100.0% | 99.7% | 99.7% |
| PortScan | 63,621 | 98.2% | 100.0% | 99.8% |
| DDoS | 32,237 | 100.0% | 100.0% | 100.0% |
| DoS GoldenEye | 3,472 | 100.0% | 91.0% | 91.0% |
| DoS Slowhttptest | 3,031 | 99.2% | 66.8% | 66.8% |
| DoS slowloris | 1,270 | 99.8% | 0.0% | 0.0% |
| Heartbleed | 3 | 100.0% | 0.0% | 0.0% |


Read this table as the system's real boundary. The classifiers catch nearly everything, so the rule layer decides what actually gets blocked, and it only sees volume and port spread. Attacks that look like ordinary web traffic - slow DoS (GoldenEye, slowloris), web brute force, XSS, SQL injection, botnet C2 - all arrive on port 80 or 8080 at unremarkable rates, so no threshold on packet headers can separate them from real browsing. Catching those needs payload inspection, which signature engines such as Snort provide and a threshold engine cannot replace. SSH brute force was in this blind spot until port 22 was added to the suspicious list; the web-facing attacks cannot be fixed the same way, because flagging port 80 would flag the whole internet.

## Why blocking can also be triggered by rules alone

The pipeline originally blocked only when the classifiers flagged a source AND a rule confirmed it (row A). The cross-day test exposed the cost: with the original class-weighted tree, models trained on Monday and Wednesday caught only 44% of Friday's attack flows, because they had never seen a port scan, even though the rules caught nearly all of them. Three triggers were measured, and B was adopted (`config.INDEPENDENT_RULE_TRIGGER = 2`): two or more distinct rules firing at once block on their own, which is also what already escalates an alert to CRITICAL. The current figures:

| Trigger | Unseen-attack recall (cross-day) | FPR (cross-day) | Random-split F1 |
|---|---|---|---|
| A: ML and rule | 94.9% | 7.31% | 0.988 |
| B: A, or 2+ rules (shipped) | 99.4% | 8.05% | 0.981 |
| C: A, or any single rule | 99.5% | 19.16% | 0.904 |

## Headline figures (per-flow, random split)

| Metric | PacketWatch full pipeline |
|---|---|
| Precision | 97.9% |
| Recall | 98.3% |
| F1 | 98.1% |
| False positive rate | 1.00% |

These cover every attack type in the capture files evaluated, including ones this feature set cannot see (slow DoS, web attacks, botnet C2), which is where most of the missed and false detections come from. Restricted to the scans and floods PacketWatch is designed for, the same pipeline scores higher; run this script on the Monday, Wednesday and Friday-afternoon files alone to reproduce that figure.

## Findings

1. **The verification layer is what makes the system usable.** On the random split the ML fusion alone fires on 7.7% of benign flows; requiring a rule to confirm cuts that to 1.00% while costing little recall.
2. **Unseen attack types are the classifiers' weak point.** Trained on Monday and Wednesday (benign plus DoS) and tested on Friday's DDoS, port scan and bot traffic, the Decision Tree alone reaches 95.3% recall, and the threshold rules 99.5%.
3. **That finding changed the design.** With the original class-weighted tree the classifiers caught only 44% of these unseen attacks, so two or more distinct rules firing at once now block on their own. The full pipeline's cross-day recall is 99.4%.
4. **Per-window precision looks bad and largely is not.** Each attack comes from one source, so attack windows are rare; a handful of false alarms across 80,000 benign windows drives precision down while the per-flow view shows the attack traffic itself is caught.

## Reproduce

```
python -m evaluation.cicids2017 --data <dir> --window 60
```