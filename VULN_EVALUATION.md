# Vulnerability prioritisation evaluation

VPID ranks vulnerabilities with a decision tree trained on 15,000 labelled records that are not published. The public stand-in here is CISA's Known Exploited Vulnerabilities catalogue: a CVE deserves attention first if attackers are known to use it. The tree predicts KEV membership from the CVE's own CVSS fields.

Data: NVD year feeds (fkie-cad mirror), CISA KEV (1,716 entries), EPSS (377,166 scores). 260,922 CVEs with a CVSS v3 vector, split by publication date at 2024-01-01: 116,359 for training, 144,563 held out. Splitting by date rather than at random matters, because ranking a vulnerability is a prediction about the future, and a random split would let the model learn from CVEs published after the ones it scores.

Only 0.35% of the held-out CVEs are in KEV (509 of 144,563), so precision is hard to come by and accuracy is a meaningless measure here.

## Flagging: who would you patch?

| Strategy | Precision | Recall | F1 | CVEs flagged | KEV caught |
|---|---|---|---|---|---|
| Decision tree (this project) | 0.9% | 58.5% | 1.7% | 33,786 | 298 / 509 |
| CVSS >= 9.0 (patch the criticals) | 1.2% | 45.6% | 2.4% | 18,863 | 232 / 509 |
| CVSS >= 7.0 (patch high and above) | 0.6% | 89.4% | 1.2% | 75,405 | 455 / 509 |
| EPSS >= 0.1 (reference model) | 17.9% | 66.0% | 28.2% | 1,873 | 336 / 509 |
| Decision tree + EPSS as a feature | 10.7% | 64.0% | 18.3% | 3,048 | 326 / 509 |

## Ranking: what lands at the top of the list

Prioritisation is really a ranking task - an admin works down the list until time runs out - so this is the more useful view. Cells show how many of the 509 known-exploited CVEs appear in the first k rows.

| Ranked by | top 50 | top 200 | top 1,000 |
|---|---|---|---|
| Decision tree (CVE fields only) | 3 (1%) | 10 (2%) | 54 (11%) |
| Decision tree + EPSS as a feature | 46 (9%) | 138 (27%) | 239 (47%) |
| CVSS base score | 1 (0%) | 7 (1%) | 39 (8%) |
| EPSS (reference model) | 45 (9%) | 146 (29%) | 271 (53%) |

Ranking quality (ROC AUC): decision tree on CVE fields **0.712**, the same tree with EPSS as an input 0.731, CVSS base score alone 0.765, EPSS 0.974.

## The result that shaped the design

**A decision tree over CVE-record fields ranks worse than the CVSS score it is built from** (0.712 against 0.765). Deeper trees were tried and did worse; dropping CVE age changed little. The signal is simply not in the record: whether attackers adopt a vulnerability depends on what software is widely deployed, whether exploit code circulates, and who is targeting whom, none of which a CVE entry states. EPSS reaches 0.974 because it is trained on observed exploitation.

Reporting the tree as VPID's algorithm and stopping there would have meant shipping something worse than sorting by severity. So the shipped tool ranks in a cascade instead - KEV, then EPSS, then the tree, then CVSS - and each item states which signal decided it. The tree is retained for CVEs that have no EPSS score yet, which is where it is better than nothing.

## What the tree learned

```
|--- n_references <= 2.50
|   |--- class: 0
|--- n_references >  2.50
|   |--- impact <= 58.50
|   |   |--- n_references <= 3.50
|   |   |   |--- has_patch_ref <= 0.50
|   |   |   |   |--- truncated branch of depth 3
|   |   |   |--- has_patch_ref >  0.50
|   |   |   |   |--- truncated branch of depth 3
|   |   |--- n_references >  3.50
|   |   |   |--- n_references <= 4.50
|   |   |   |   |--- truncated branch of depth 3
|   |   |   |--- n_references >  4.50
|   |   |   |   |--- truncated branch of depth 3
|   |--- impact >  58.50
|   |   |--- n_products <= 2.50
|   |   |   |--- n_references <= 4.50
|   |   |   |   |--- truncated branch of depth 3
|   |   |   |--- n_references >  4.50
|   |   |   |   |--- truncated branch of depth 3
|   |   |--- n_products >  2.50
|   |   |   |--- n_references <= 3.50
|   |   |   |   |--- truncated branch of depth 3
|   |   |   |--- n_references >  3.50
|   |   |   |   |--- truncated branch of depth 3
```

## Comparison with VPID

| | VPID (paper) | Decision tree here | Shipped cascade's best signal |
|---|---|---|---|
| Precision | 91.8% | 0.9% | 17.9% |
| Recall | 89.5% | 58.5% | 66.0% |
| F1 | 90.6% | 1.7% | 28.2% |

These are not the same task. VPID's labels come from its own 15,000 records with an unpublished definition of priority, and its class balance is unknown. Predicting real-world exploitation from CVSS fields alone is a much harder problem: EPSS exists precisely because it needs telemetry that a CVE record does not contain. The numbers above should be read against the CVSS baselines in the same table, not against the paper.

## Honest reading

1. The decision tree on CVE fields alone is not good enough to ship by itself, and this report says so rather than quoting its accuracy, which looks impressive only because 99.65% of CVEs are not in KEV.
2. EPSS is far ahead, as it should be: it is trained on observed exploitation rather than on the CVE text. The shipped tool uses it whenever a score exists, and falls back to the tree when none does.
3. KEV is a biased label. It lists what CISA has confirmed and is weighted towards widely deployed software, so absence from KEV does not mean safe.
4. This module ranks and explains. It does not exploit anything: see `packetwatch/vuln/validate.py` for where that line is drawn.

## Reproduce

```
python -m evaluation.vuln_priority --data <dir>
```