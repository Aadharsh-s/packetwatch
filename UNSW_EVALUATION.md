# PacketWatch on UNSW-NB15 (real 10 s windows)

Data: `rdpahalavan/UNSW-NB15` (Hugging Face mirror of the UNSW-NB15 flow records), 2,059,415 flows from 2015, 4.8% attack.

## Why this dataset as well as CIC-IDS2017

CIC-IDS2017's attack captures timestamp flows to the minute, so windows there had to be widened to 60 s and the packet rate became a window average. UNSW-NB15 records each flow's start and end in epoch seconds, so its packets can be spread over the seconds they span. Windows here are exactly the live 10s, and `pkts_per_sec` is the real peak-1-second rate the live code measures, not an average. These are the closest numbers to live behaviour in this project.

2,059,415 flows became 802,356 windows of (source, protected host, 10s), 51,148 of them containing attack traffic (6.37%).

## Do the shipped synthetic models hold up on real traffic?

Both model pairs below see the same test set. One pair is trained on the invented behaviour profiles the project ships with, the other on UNSW-NB15 windows.

### Temporal split (train on earlier traffic, test on later)

| Model | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| synthetic-trained: DT or NB only | 0.051 | 0.099 | 0.067 | 22.58% | 2,592 | 48,439 | 23,597 | 166,061 |
| synthetic-trained: full pipeline | 0.052 | 0.098 | 0.068 | 21.67% | 2,562 | 46,472 | 23,627 | 168,028 |
| UNSW-trained: DT or NB only | 0.328 | 0.985 | 0.492 | 24.61% | 25,800 | 52,786 | 389 | 161,714 |
| UNSW-trained: full pipeline | 0.199 | 0.097 | 0.131 | 4.77% | 2,546 | 10,235 | 23,643 | 204,265 |
| rules alone (no ML) | 0.053 | 0.099 | 0.069 | 21.69% | 2,602 | 46,517 | 23,587 | 167,983 |

### Random 70/30 split

| Model | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| synthetic-trained: DT or NB only | 0.029 | 0.099 | 0.045 | 22.67% | 1,526 | 51,092 | 13,818 | 174,271 |
| synthetic-trained: full pipeline | 0.030 | 0.098 | 0.046 | 21.77% | 1,503 | 49,058 | 13,841 | 176,305 |
| UNSW-trained: DT or NB only | 0.213 | 0.985 | 0.351 | 24.74% | 15,115 | 55,756 | 229 | 169,607 |
| UNSW-trained: full pipeline | 0.125 | 0.097 | 0.109 | 4.60% | 1,487 | 10,362 | 13,857 | 215,001 |
| rules alone (no ML) | 0.030 | 0.099 | 0.046 | 21.79% | 1,520 | 49,097 | 13,824 | 176,266 |

## Detection rate per attack type (temporal split, share of attack windows blocked by the full pipeline)

| Attack type | Attack windows | Synthetic-trained | UNSW-trained |
|---|---|---|---|
| exploits | 11,416 | 12.0% | 11.9% |
| reconnaissance | 6,448 | 2.8% | 2.5% |
| generic | 3,119 | 3.7% | 4.3% |
| fuzzers | 2,427 | 28.4% | 28.0% |
| dos | 1,682 | 10.9% | 10.9% |
| shellcode | 783 | 1.1% | 0.9% |
| backdoor | 150 | 7.3% | 7.3% |
| worms | 94 | 5.3% | 5.3% |
| analysis | 70 | 0.0% | 0.0% |


## What this dataset says about the fixed thresholds

UNSW-NB15's benign traffic is machine-generated and dense: the median benign window carries 62 packets at 44 packets/sec from one source, while the median attack window carries 12 packets at 8/sec. Its attacks are *quieter* than its normal traffic, so thresholds meant for a home link fire on benign traffic and miss the attacks - the rule layer is inverted here.

`--calibrate` derives the three thresholds from a quiet baseline of the host's own traffic instead of assuming them:

| Thresholds | ports | pps | suspicious | Recall | FPR |
|---|---|---|---|---|---|
| stock | 10 | 100 | 3 | 10.0% | 21.84% |
| calibrated on this host's benign traffic | 10 | 613 | 100 | 0.8% | 2.77% |


Read that honestly. Calibration fixes the false alarms - an eightfold cut, because it learns that this host's normal traffic is fast - but it cannot rescue detection here, and recall falls as thresholds rise. No volume threshold can find attacks that are quieter than ordinary traffic. On CIC-IDS2017, whose attacks are the loud kind, the same calibration cuts rule-layer false positives from 1.64% to 0.37% while slightly *raising* recall (12.0% to 12.7% of attack windows). The lesson is that fixed thresholds are a deployment assumption rather than a constant, and that on traffic like UNSW-NB15's the rule layer is the wrong instrument altogether.

## Conclusions

1. **The shipped synthetic models do not transfer to this traffic.** They were invented from scan and flood behaviour; UNSW-NB15 is mostly low-volume exploit and fuzzing traffic, and they detect almost none of it.
2. **Training on this dataset is not a fix either.** UNSW-trained classifiers reach 98.5% recall but flag a quarter of all benign windows, because at this feature resolution its attacks and its normal traffic genuinely overlap. Shown ordinary traffic afterwards, they flag 99% of it - they have learned that anything slower than this dataset's dense generated background is suspicious. Restricting training to UNSW's volumetric attacks (reconnaissance, DoS, worms), the kind PacketWatch is built for, did not change that. Models trained here are therefore *not* shipped; the synthetic ones remain the default, and this is the record of why.
3. **Window-level recall is low on both datasets** (10-13%) because most attack windows are small and quiet, while most attack *traffic* sits in a few loud windows - which is why per-flow recall on CIC-IDS2017 is 96.7%. Both framings are reported rather than the flattering one alone.
4. **Packet headers are the ceiling.** Exploits, fuzzing and web attacks are distinguished by payload content, which this feature set never sees. That is the part of Snort a threshold engine cannot replace.

## Reproduce

```
python -m evaluation.unsw_nb15 --data <dir with UNSW_Flow.parquet>
```