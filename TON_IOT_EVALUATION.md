# Base-paper protocol on TON_IoT

Replicates the protocol of the base paper - S. Ismail, S. Dandan and A. Qushou, "Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets," *IEEE Access*, vol. 13, pp. 73468-73485, 2025 - on TON_IoT, its primary dataset.

## Data

TON_IoT network train/test set (Hugging Face mirror `codymlewis/TON_IoT_network`): 211,043 records. Classes: normal (50,000), backdoor (20,000), ddos (20,000), dos (20,000), injection (20,000), password (20,000), ransomware (20,000), scanning (20,000), xss (20,000), mitm (1,043).

**Why records, not PacketWatch windows.** This file has no timestamp column, so the per-source time windows PacketWatch uses cannot be built without inventing time. The base paper classifies TON_IoT record by record on the dataset's own features, which is what is done here, so these numbers compare with the paper rather than with the live system. Source and destination IPs, source ports and free-text fields (URIs, user agents, certificate subjects) are dropped so models learn behaviour rather than memorising hosts; categorical fields are encoded.

## Mutual Information feature selection

| Rank | Feature | Mutual Information |
|---|---|---|
| 1 | `dst_port` | 0.4202 |
| 2 | `src_ip_bytes` | 0.4184 |
| 3 | `dst_ip_bytes` | 0.2483 |
| 4 | `conn_state` | 0.2032 |
| 5 | `src_bytes` | 0.1826 |
| 6 | `src_pkts` | 0.1810 |
| 7 | `proto` | 0.1620 |
| 8 | `service` | 0.1554 |
| 9 | `dns_rejected` | 0.1507 |
| 10 | `duration` | 0.1454 |
| 11 | `dns_qtype` | 0.1287 |
| 12 | `dst_bytes` | 0.1239 |
| 13 | `dns_RA` | 0.1224 |
| 14 | `dns_RD` | 0.1178 |
| 15 | `dst_pkts` | 0.1168 |

The paper selects features by MI. Here the subset is the smallest top-k whose Decision Tree F1 is within 0.005 of using every feature:

| Top-k features | Decision Tree F1 |
|---|---|
| 3 | 0.9859 |
| 5 | 0.9860 |
| 8 (chosen) | 0.9944 |
| 10 | 0.9960 |
| 15 | 0.9959 |
| 34 | 0.9955 |

Selected: `dst_port`, `src_ip_bytes`, `dst_ip_bytes`, `conn_state`, `src_bytes`, `src_pkts`, `proto`, `service`.

## Model comparison (binary: attack vs. normal)

All models trained without class weighting, on the MI-selected features, with a stratified 70/30 split.

| Model | Precision | Recall | F1 | FPR | Train time | Model size | Predict / sample |
|---|---|---|---|---|---|---|---|
| Decision Tree | 0.992 | 0.996 | 0.994 | 2.67% | 0.1 s | 9 KB | 0.06 us |
| Multinomial NB | 1.000 | 0.000 | 0.001 | 0.00% | 0.0 s | 1 KB | 0.06 us |
| Random Forest | 0.999 | 0.998 | 0.998 | 0.46% | 3.3 s | 6,879 KB | 2.77 us |
| Bagging | 0.998 | 0.998 | 0.998 | 0.50% | 10.7 s | 2,575 KB | 4.70 us |
| Stacking | 0.998 | 0.998 | 0.998 | 0.53% | 5.8 s | 3,468 KB | 2.06 us |
| LightGBM | 0.999 | 0.997 | 0.998 | 0.44% | 2.4 s | 1,359 KB | 9.98 us |

## Model comparison (multi-class: attack type)

Macro-F1 weights every class equally, so it exposes the rare MITM class that micro-F1 hides.

| Model | Micro-F1 | Macro-F1 | Weighted-F1 | Train time | Model size |
|---|---|---|---|---|---|
| Decision Tree | 0.8557 | 0.809 | 0.8633 | 0.4 s | 17 KB |
| Multinomial NB | 0.2697 | 0.197 | 0.2088 | 0.5 s | 2 KB |
| Random Forest | 0.9858 | 0.961 | 0.9860 | 3.3 s | 31,488 KB |
| Bagging | 0.9858 | 0.961 | 0.9859 | 3.8 s | 11,680 KB |
| Stacking | 0.9856 | 0.962 | 0.9857 | 6.7 s | 15,789 KB |
| LightGBM | 0.9855 | 0.957 | 0.9857 | 23.7 s | 13,634 KB |

## Class imbalance

TON_IoT's train/test set is attack-majority (76% attack records), the reverse of the other datasets.

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Decision Tree, unweighted | 0.992 | 0.996 | 0.994 | 2.67% |
| Decision Tree, class-balanced | 0.996 | 0.995 | 0.996 | 1.33% |

## Cross-dataset transfer

The paper trains on TON_IoT and tests on WUSTL-IIoT-2021 to show models generalise. WUSTL-IIoT-2021 is not available from a public mirror, so the same test is run between TON_IoT and UNSW-NB15, on the seven fields both record (duration, src_bytes, dst_bytes, src_pkts, dst_pkts, dst_port, proto). UNSW-NB15 is sampled to 300,000 records.

| Train on | Test on | Model | F1 within the training dataset | Precision on the other | Recall on the other | F1 on the other |
|---|---|---|---|---|---|---|
| TON_IoT | UNSW-NB15 | Decision Tree | 0.995 | 0.077 | 0.782 | **0.139** |
| TON_IoT | UNSW-NB15 | Random Forest | 0.998 | 0.072 | 0.711 | **0.130** |
| TON_IoT | UNSW-NB15 | LightGBM | 0.998 | 0.078 | 0.636 | **0.139** |
| UNSW-NB15 | TON_IoT | Decision Tree | 0.805 | 0.227 | 0.030 | **0.053** |
| UNSW-NB15 | TON_IoT | Random Forest | 0.904 | 0.260 | 0.028 | **0.051** |
| UNSW-NB15 | TON_IoT | LightGBM | 0.906 | 0.787 | 0.125 | **0.216** |

## Reproduce

```
python -m evaluation.ton_iot --data <dir> --unsw <dir>
```