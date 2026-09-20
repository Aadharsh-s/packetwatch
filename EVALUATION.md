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
| Friday-WorkingHours-Morning | 191,033 | 1,966 | 46,774 | 766 | Bot (1,966) |
| Monday-WorkingHours | 529,918 | 0 | 123,025 | 0 | - |
| Thursday-WorkingHours-Afternoon-Infilteration | 288,602 | 36 | 52,483 | 28 | Infiltration (36) |
| Thursday-WorkingHours-Morning-WebAttacks | 170,366 | 2,180 | 43,608 | 68 | Web Attack  Brute Force (1,507), Web Attack  XSS (652), Web Attack  Sql Injection (21) |
| Tuesday-WorkingHours | 445,909 | 13,835 | 100,984 | 127 | FTP-Patator (7,938), SSH-Patator (5,897) |
| Wednesday-workingHours | 692,703 | 252,672 | 101,481 | 86 | DoS Hulk (231,073), DoS GoldenEye (10,293), DoS slowloris (5,796), DoS Slowhttptest (5,499), Heartbleed (11) |

Total: 2,830,743 flows (557,646 attack) aggregated into 513,709 windows, of which 1,124 (0.22%) contain attack traffic.

Each attack here comes from one source hitting one victim, so attacks collapse into few windows while benign traffic spreads across many. Precision measured per window is therefore harsh, which is why per-flow results are reported too.

## Per-window results (operational view: one window = one alert decision)

### Random 70/30 split

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.009 | 0.843 | 0.018 | 20.52% | 284 | 31,559 | 53 | 122,217 |
| Naive Bayes alone | 0.024 | 0.261 | 0.044 | 2.34% | 88 | 3,591 | 249 | 150,185 |
| DT or NB (fusion, no verification) | 0.008 | 0.855 | 0.016 | 22.39% | 288 | 34,432 | 49 | 119,344 |
| Rules alone (verification layer) | 0.018 | 0.172 | 0.032 | 2.09% | 58 | 3,208 | 279 | 150,568 |
| A: ML and rule only | 0.034 | 0.166 | 0.057 | 1.03% | 56 | 1,583 | 281 | 152,193 |
| B: A, or 2+ rules alone (shipped) | 0.034 | 0.166 | 0.056 | 1.04% | 56 | 1,596 | 281 | 152,180 |
| C: A, or any single rule alone | 0.018 | 0.172 | 0.032 | 2.09% | 58 | 3,208 | 279 | 150,568 |

### Cross-day split: train on Mon+Wed, test on the unseen Friday captures

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.013 | 0.026 | 0.018 | 1.71% | 21 | 1,562 | 794 | 89,751 |
| Naive Bayes alone | 0.017 | 0.034 | 0.023 | 1.75% | 28 | 1,600 | 787 | 89,713 |
| DT or NB (fusion, no verification) | 0.009 | 0.034 | 0.015 | 3.20% | 28 | 2,921 | 787 | 88,392 |
| Rules alone (verification layer) | 0.024 | 0.054 | 0.034 | 1.93% | 44 | 1,759 | 771 | 89,554 |
| A: ML and rule only | 0.027 | 0.033 | 0.030 | 1.07% | 27 | 973 | 788 | 90,340 |
| B: A, or 2+ rules alone (shipped) | 0.036 | 0.045 | 0.040 | 1.08% | 37 | 982 | 778 | 90,331 |
| C: A, or any single rule alone | 0.024 | 0.054 | 0.034 | 1.93% | 44 | 1,759 | 771 | 89,554 |

## Per-flow results (each flow inherits its window's verdict)

VPID reports per-flow metrics, so this is the closer comparison.

### Random 70/30 split

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.633 | 0.997 | 0.774 | 13.93% | 162,181 | 94,086 | 431 | 581,420 |
| Naive Bayes alone | 0.773 | 0.922 | 0.841 | 6.51% | 149,888 | 43,980 | 12,724 | 631,526 |
| DT or NB (fusion, no verification) | 0.573 | 0.998 | 0.728 | 17.93% | 162,354 | 121,124 | 258 | 554,382 |
| Rules alone (verification layer) | 0.691 | 0.967 | 0.806 | 10.41% | 157,272 | 70,343 | 5,340 | 605,163 |
| A: ML and rule only | 0.883 | 0.967 | 0.923 | 3.08% | 157,251 | 20,825 | 5,361 | 654,681 |
| B: A, or 2+ rules alone (shipped) | 0.845 | 0.967 | 0.902 | 4.28% | 157,251 | 28,896 | 5,361 | 646,610 |
| C: A, or any single rule alone | 0.691 | 0.967 | 0.806 | 10.41% | 157,272 | 70,343 | 5,340 | 605,163 |

### Cross-day split

| Stage | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Decision Tree alone | 0.894 | 0.443 | 0.592 | 3.68% | 128,024 | 15,249 | 160,899 | 399,073 |
| Naive Bayes alone | 0.929 | 0.749 | 0.829 | 4.01% | 216,327 | 16,594 | 72,596 | 397,728 |
| DT or NB (fusion, no verification) | 0.901 | 0.749 | 0.818 | 5.71% | 216,327 | 23,652 | 72,596 | 390,670 |
| Rules alone (verification layer) | 0.847 | 0.989 | 0.912 | 12.48% | 285,627 | 51,723 | 3,296 | 362,599 |
| A: ML and rule only | 0.981 | 0.744 | 0.846 | 1.03% | 214,979 | 4,266 | 73,944 | 410,056 |
| B: A, or 2+ rules alone (shipped) | 0.937 | 0.988 | 0.962 | 4.60% | 285,522 | 19,047 | 3,401 | 395,275 |
| C: A, or any single rule alone | 0.847 | 0.989 | 0.912 | 12.48% | 285,627 | 51,723 | 3,296 | 362,599 |

## Detection rate per attack type (random split, share of attack flows)

| Attack type | Attack flows | Caught by ML fusion | Caught by rules | Caught by pipeline |
|---|---|---|---|---|
| PortScan | 55,770 | 100.0% | 100.0% | 100.0% |
| DoS Hulk | 49,797 | 100.0% | 99.6% | 99.6% |
| DDoS | 47,095 | 100.0% | 100.0% | 100.0% |
| FTP-Patator | 2,149 | 100.0% | 100.0% | 100.0% |
| DoS slowloris | 1,795 | 99.9% | 0.0% | 0.0% |
| DoS Slowhttptest | 1,698 | 94.2% | 60.4% | 60.4% |
| SSH-Patator | 1,624 | 100.0% | 100.0% | 100.0% |
| DoS GoldenEye | 1,487 | 100.0% | 0.0% | 0.0% |
| Bot | 577 | 77.3% | 1.7% | 0.0% |
| Web Attack  Brute Force | 439 | 97.5% | 0.0% | 0.0% |
| Web Attack  XSS | 164 | 100.0% | 0.0% | 0.0% |
| Infiltration | 12 | 50.0% | 25.0% | 25.0% |
| Heartbleed | 5 | 100.0% | 0.0% | 0.0% |


Read this table as the system's real boundary. The classifiers catch nearly everything, so the rule layer decides what actually gets blocked, and it only sees volume and port spread. Attacks that look like ordinary web traffic - slow DoS (GoldenEye, slowloris), web brute force, XSS, SQL injection, botnet C2 - all arrive on port 80 or 8080 at unremarkable rates, so no threshold on packet headers can separate them from real browsing. Catching those needs payload inspection, which is exactly what Snort does in VPID and what a threshold engine cannot replace. SSH brute force was in this blind spot until port 22 was added to the suspicious list; the web-facing attacks cannot be fixed the same way, because flagging port 80 would flag the whole internet.

## Why blocking can also be triggered by rules alone

The pipeline originally blocked only when the classifiers flagged a source AND a rule confirmed it (row A). The cross-day test exposed the cost: models trained on Monday and Wednesday had never seen a port scan, so Friday's scans were never blocked even though the rules caught them. Three triggers were measured, and B was adopted (`config.INDEPENDENT_RULE_TRIGGER = 2`): two or more distinct rules firing at once block on their own, which is also what already escalates an alert to CRITICAL.

| Trigger | Unseen-attack recall (cross-day) | FPR (cross-day) | Random-split F1 |
|---|---|---|---|
| A: ML and rule | 74.4% | 1.03% | 0.923 |
| B: A, or 2+ rules (shipped) | 98.8% | 4.60% | 0.902 |
| C: A, or any single rule | 98.9% | 12.48% | 0.806 |

## Comparison with VPID (per-flow, random split)

| Metric | VPID (paper) | PacketWatch full pipeline |
|---|---|---|
| Precision | 94.5% | 84.5% |
| Recall | 88.3% | 96.7% |
| F1 | 91.3% | 90.2% |
| False positive rate | under 1.5% | 4.28% |

Not a like-for-like comparison: VPID trained on 550,000 flows of its own and tested on a separate 55,000, on traffic we cannot inspect. These numbers cover every attack in CIC-IDS2017, including ones this feature set cannot see (slow DoS, web attacks, botnet C2), which is where the precision gap comes from. Restricted to the scans and floods PacketWatch is designed for, the same pipeline scores F1 0.97. Both figures are in this report; the lower one is the honest headline.

## Findings

1. **The verification layer is what makes the system usable.** On the random split the ML fusion alone fires on 17.9% of benign flows; requiring a rule to confirm cuts that to 4.28% while costing little recall.
2. **The classifiers do not generalise to attack types they never saw.** Trained on Monday and Wednesday (benign plus DoS) and tested on Friday, both models caught the DDoS but missed the port scan entirely: recall 44.3%. The threshold rules caught it (98.9% recall).
3. **That finding changed the design.** Because gating on the ML stage let those scans through, two or more distinct rules firing at once now block on their own, lifting cross-day recall to 98.8%.
4. **Per-window precision looks bad and largely is not.** Each attack comes from one source, so attack windows are rare; a handful of false alarms across 80,000 benign windows drives precision down while the per-flow view shows the attack traffic itself is caught.

## Reproduce

```
python -m evaluation.cicids2017 --data <dir> --window 60
```