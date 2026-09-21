# Lightweight model comparison

Protocol follows the base paper: S. Ismail, S. Dandan and A. Qushou, "Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets," *IEEE Access*, vol. 13, pp. 73468-73485, 2025. Its five models (Decision Tree, Random Forest, Bagging, Stacking, LightGBM) are compared on precision, recall, micro-F1, model size and training time, with Mutual Information feature ranking and a class-imbalance check. Two rows are added: Multinomial Naive Bayes, which PacketWatch ships, and the full PacketWatch pipeline, where either model's flag must be confirmed by a rule. Prediction time per sample is also reported, because a live system pays it on every sweep.

Every model sees the same 10 features PacketWatch extracts from live traffic, computed per (source, destination host, window), with a stratified 70/30 split. All models are trained without class weighting, so they differ by algorithm alone. The Decision Tree row is exactly the configuration PacketWatch ships (`packetwatch.model.make_tree`), and weighting is examined in its own section. Because windows are per destination host, `unique_dst_ips` is always 1 here and carries no information by construction.

## UNSW-NB15

802,356 windows, 6.37% containing attack traffic. Classes: Benign (751,208), exploits (22,612), reconnaissance (12,655), generic (5,808), fuzzers (4,607), dos (3,324), shellcode (1,559), backdoor (281).

### Binary: attack vs. normal

| Model | Precision | Recall | F1 | FPR | Train time | Model size | Predict / sample |
|---|---|---|---|---|---|---|---|
| Decision Tree | 0.825 | 0.659 | 0.733 | 0.95% | 1.2 s | 9 KB | 0.09 us |
| Multinomial NB | 0.185 | 0.350 | 0.243 | 10.48% | 0.1 s | 1 KB | 0.09 us |
| Random Forest | 0.882 | 0.782 | 0.829 | 0.71% | 33.1 s | 78,720 KB | 4.20 us |
| Bagging | 0.879 | 0.781 | 0.827 | 0.73% | 49.0 s | 33,945 KB | 5.06 us |
| Stacking | 0.886 | 0.775 | 0.827 | 0.68% | 50.4 s | 39,278 KB | 2.41 us |
| LightGBM | 0.874 | 0.755 | 0.810 | 0.74% | 9.4 s | 1,370 KB | 12.43 us |
| PacketWatch (DT or NB + rule verification) | 0.095 | 0.065 | 0.077 | 4.22% | 1.3 s | 10 KB | 0.18 us |

### Multi-class: which attack

Micro-F1 is dominated by the majority class on imbalanced data, which is why macro-F1 (every class weighted equally) is shown beside it.

| Model | Micro-F1 | Macro-F1 | Weighted-F1 | Train time | Model size |
|---|---|---|---|---|---|
| Decision Tree | 0.9512 | 0.249 | 0.9420 | 3.9 s | 17 KB |
| Multinomial NB | 0.6106 | 0.114 | 0.7230 | 4.9 s | 3 KB |
| Random Forest | 0.9627 | 0.365 | 0.9596 | 37.4 s | 186,839 KB |
| Bagging | 0.9621 | 0.360 | 0.9590 | 48.8 s | 82,805 KB |
| Stacking | 0.9627 | 0.362 | 0.9591 | 63.5 s | 93,359 KB |
| LightGBM | 0.9622 | 0.366 | 0.9582 | 83.9 s | 13,705 KB |

### Mutual Information feature ranking

| Rank | Feature | Mutual Information | Relative |
|---|---|---|---|
| 1 | `pkts_per_sec` | 0.1049 | #################### |
| 2 | `tcp_count` | 0.0843 | ################ |
| 3 | `pkt_count` | 0.0806 | ############### |
| 4 | `unique_dst_ports` | 0.0305 | ###### |
| 5 | `avg_len_bucket` | 0.0152 | ### |
| 6 | `udp_count` | 0.0144 | ### |
| 7 | `suspicious_port_hits` | 0.0121 | ## |
| 8 | `icmp_count` | 0.0001 | # |
| 9 | `syn_only_count` | 0.0000 | # |
| 10 | `unique_dst_ips` | 0.0000 | # |

Decision Tree using only the top-k features by MI:

| Top-k features by MI | Precision | Recall | F1 |
|---|---|---|---|
| 2 (pkts_per_sec, tcp_count) | 0.841 | 0.437 | 0.575 |
| 3 (pkts_per_sec, tcp_count, pkt_count) | 0.818 | 0.462 | 0.590 |
| 5 (pkts_per_sec, tcp_count, pkt_count, ...) | 0.813 | 0.674 | 0.737 |
| 7 (pkts_per_sec, tcp_count, pkt_count, ...) | 0.825 | 0.659 | 0.733 |
| 10 (pkts_per_sec, tcp_count, pkt_count, ...) | 0.825 | 0.659 | 0.733 |

### Class imbalance

The same Decision Tree trained with and without class weighting. Attack windows are the minority, so an unweighted tree can score well by favouring the normal class.

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Decision Tree, unweighted | 0.825 | 0.659 | 0.733 | 0.95% |
| Decision Tree, class-balanced | 0.283 | 0.970 | 0.438 | 16.76% |

## CIC-IDS2017

513,709 windows, 0.22% containing attack traffic. Classes: Benign (512,585), Bot (766), Other (187), FTP-Patator (64), SSH-Patator (63), Web Attack  Brute Force (44).

### Binary: attack vs. normal

| Model | Precision | Recall | F1 | FPR | Train time | Model size | Predict / sample |
|---|---|---|---|---|---|---|---|
| Decision Tree | 0.968 | 0.181 | 0.305 | 0.00% | 0.4 s | 4 KB | 0.06 us |
| Multinomial NB | 0.024 | 0.261 | 0.044 | 2.34% | 0.1 s | 1 KB | 0.06 us |
| Random Forest | 0.918 | 0.199 | 0.327 | 0.00% | 15.5 s | 4,381 KB | 2.97 us |
| Bagging | 0.886 | 0.208 | 0.337 | 0.01% | 17.2 s | 1,982 KB | 4.77 us |
| Stacking | 0.985 | 0.199 | 0.331 | 0.00% | 23.5 s | 2,149 KB | 1.84 us |
| LightGBM | 0.919 | 0.202 | 0.331 | 0.00% | 5.5 s | 1,377 KB | 13.77 us |
| PacketWatch (DT or NB + rule verification) | 0.034 | 0.166 | 0.057 | 1.02% | 0.4 s | 5 KB | 0.12 us |

### Multi-class: which attack

Micro-F1 is dominated by the majority class on imbalanced data, which is why macro-F1 (every class weighted equally) is shown beside it.

| Model | Micro-F1 | Macro-F1 | Weighted-F1 | Train time | Model size |
|---|---|---|---|---|---|
| Decision Tree | 0.9982 | 0.667 | 0.9974 | 1.5 s | 7 KB |
| Multinomial NB | 0.9228 | 0.381 | 0.9580 | 1.8 s | 2 KB |
| Random Forest | 0.9982 | 0.668 | 0.9974 | 17.7 s | 6,181 KB |
| Bagging | 0.9982 | 0.681 | 0.9974 | 18.0 s | 2,784 KB |
| Stacking | 0.9982 | 0.571 | 0.9974 | 27.0 s | 3,047 KB |
| LightGBM | 0.9981 | 0.627 | 0.9973 | 31.5 s | 8,378 KB |

### Mutual Information feature ranking

| Rank | Feature | Mutual Information | Relative |
|---|---|---|---|
| 1 | `tcp_count` | 0.0053 | #################### |
| 2 | `pkt_count` | 0.0051 | ################### |
| 3 | `pkts_per_sec` | 0.0022 | ######## |
| 4 | `suspicious_port_hits` | 0.0021 | ######## |
| 5 | `avg_len_bucket` | 0.0004 | # |
| 6 | `unique_dst_ports` | 0.0003 | # |
| 7 | `udp_count` | 0.0002 | # |
| 8 | `syn_only_count` | 0.0000 | # |
| 9 | `icmp_count` | 0.0000 | # |
| 10 | `unique_dst_ips` | 0.0000 | # |

Decision Tree using only the top-k features by MI:

| Top-k features by MI | Precision | Recall | F1 |
|---|---|---|---|
| 2 (tcp_count, pkt_count) | 0.714 | 0.045 | 0.084 |
| 3 (tcp_count, pkt_count, pkts_per_sec) | 0.714 | 0.045 | 0.084 |
| 5 (tcp_count, pkt_count, pkts_per_sec, ...) | 0.953 | 0.181 | 0.304 |
| 7 (tcp_count, pkt_count, pkts_per_sec, ...) | 0.968 | 0.181 | 0.305 |
| 10 (tcp_count, pkt_count, pkts_per_sec, ...) | 0.968 | 0.181 | 0.305 |

### Class imbalance

The same Decision Tree trained with and without class weighting. Attack windows are the minority, so an unweighted tree can score well by favouring the normal class.

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Decision Tree, unweighted | 0.968 | 0.181 | 0.305 | 0.00% |
| Decision Tree, class-balanced | 0.009 | 0.843 | 0.018 | 20.52% |

## Reproduce

```
python -m evaluation.model_comparison --cic <dir> --unsw <dir>
```