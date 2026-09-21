# Lightweight model comparison

Protocol follows the base paper: S. Ismail, S. Dandan and A. Qushou, "Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets," *IEEE Access*, vol. 13, pp. 73468-73485, 2025. Its five models (Decision Tree, Random Forest, Bagging, Stacking, LightGBM) are compared on precision, recall, micro-F1, model size and training time, with Mutual Information feature ranking and a class-imbalance check. Two rows are added: Multinomial Naive Bayes, which PacketWatch ships, and the full PacketWatch pipeline, where either model's flag must be confirmed by a rule. Prediction time per sample is also reported, because a live system pays it on every sweep.

Every model sees the same 10 features PacketWatch extracts from live traffic, computed per (source, destination host, window), with a stratified 70/30 split. All models in the main tables are trained without class weighting, so they differ by algorithm alone; the class-balanced Decision Tree PacketWatch ships is listed separately, and weighting is examined in its own section. Because windows are per destination host, `unique_dst_ips` is always 1 here and carries no information by construction.

## UNSW-NB15

802,356 windows, 6.37% containing attack traffic. Classes: Benign (751,208), exploits (22,612), reconnaissance (12,655), generic (5,808), fuzzers (4,607), dos (3,324), shellcode (1,559), backdoor (281).

### Binary: attack vs. normal

| Model | Precision | Recall | F1 | FPR | Train time | Model size | Predict / sample |
|---|---|---|---|---|---|---|---|
| Decision Tree | 0.825 | 0.659 | 0.733 | 0.95% | 0.8 s | 9 KB | 0.06 us |
| Multinomial NB | 0.185 | 0.350 | 0.243 | 10.48% | 0.1 s | 1 KB | 0.06 us |
| Random Forest | 0.882 | 0.782 | 0.829 | 0.71% | 32.2 s | 78,720 KB | 3.72 us |
| Bagging | 0.879 | 0.781 | 0.827 | 0.73% | 48.8 s | 33,945 KB | 5.48 us |
| Stacking | 0.886 | 0.775 | 0.827 | 0.68% | 50.0 s | 39,278 KB | 2.11 us |
| LightGBM | 0.845 | 0.758 | 0.799 | 0.94% | 4.6 s | 678 KB | 5.73 us |
| Decision Tree, class-balanced (as shipped) | 0.283 | 0.970 | 0.438 | 16.76% | 0.9 s | 9 KB | 0.06 us |
| PacketWatch (DT or NB + rule verification) | 0.125 | 0.097 | 0.109 | 4.60% | 1.0 s | 10 KB | 0.13 us |

### Multi-class: which attack

Micro-F1 is dominated by the majority class on imbalanced data, which is why macro-F1 (every class weighted equally) is shown beside it.

| Model | Micro-F1 | Macro-F1 | Weighted-F1 | Train time | Model size |
|---|---|---|---|---|---|
| Decision Tree | 0.9512 | 0.249 | 0.9420 | 2.8 s | 17 KB |
| Multinomial NB | 0.6106 | 0.114 | 0.7230 | 3.3 s | 3 KB |
| Random Forest | 0.9627 | 0.365 | 0.9596 | 36.3 s | 186,839 KB |
| Bagging | 0.9621 | 0.360 | 0.9590 | 44.5 s | 82,805 KB |
| Stacking | 0.9627 | 0.362 | 0.9591 | 66.0 s | 93,359 KB |
| LightGBM | 0.9122 | 0.172 | 0.9178 | 43.7 s | 6,198 KB |

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
| 2 (pkts_per_sec, tcp_count) | 0.240 | 0.928 | 0.381 |
| 3 (pkts_per_sec, tcp_count, pkt_count) | 0.260 | 0.921 | 0.406 |
| 5 (pkts_per_sec, tcp_count, pkt_count, ...) | 0.330 | 0.942 | 0.489 |
| 7 (pkts_per_sec, tcp_count, pkt_count, ...) | 0.283 | 0.970 | 0.438 |
| 10 (pkts_per_sec, tcp_count, pkt_count, ...) | 0.283 | 0.970 | 0.438 |

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
| Decision Tree | 0.968 | 0.181 | 0.305 | 0.00% | 0.3 s | 4 KB | 0.06 us |
| Multinomial NB | 0.024 | 0.261 | 0.044 | 2.34% | 0.1 s | 1 KB | 0.06 us |
| Random Forest | 0.918 | 0.199 | 0.327 | 0.00% | 14.4 s | 4,381 KB | 2.84 us |
| Bagging | 0.886 | 0.208 | 0.337 | 0.01% | 16.3 s | 1,982 KB | 4.59 us |
| Stacking | 0.985 | 0.199 | 0.331 | 0.00% | 21.8 s | 2,149 KB | 1.64 us |
| LightGBM | 0.845 | 0.211 | 0.337 | 0.01% | 2.5 s | 690 KB | 6.60 us |
| Decision Tree, class-balanced (as shipped) | 0.009 | 0.843 | 0.018 | 20.52% | 0.4 s | 9 KB | 0.07 us |
| PacketWatch (DT or NB + rule verification) | 0.034 | 0.166 | 0.056 | 1.04% | 0.4 s | 9 KB | 0.13 us |

### Multi-class: which attack

Micro-F1 is dominated by the majority class on imbalanced data, which is why macro-F1 (every class weighted equally) is shown beside it.

| Model | Micro-F1 | Macro-F1 | Weighted-F1 | Train time | Model size |
|---|---|---|---|---|---|
| Decision Tree | 0.9982 | 0.667 | 0.9974 | 1.3 s | 7 KB |
| Multinomial NB | 0.9228 | 0.381 | 0.9580 | 1.7 s | 2 KB |
| Random Forest | 0.9982 | 0.668 | 0.9974 | 15.9 s | 6,181 KB |
| Bagging | 0.9982 | 0.681 | 0.9974 | 19.4 s | 2,784 KB |
| Stacking | 0.9982 | 0.571 | 0.9974 | 25.1 s | 3,047 KB |
| LightGBM | 0.7714 | 0.145 | 0.8694 | 11.2 s | 1,564 KB |

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
| 2 (tcp_count, pkt_count) | 0.010 | 0.745 | 0.019 |
| 3 (tcp_count, pkt_count, pkts_per_sec) | 0.010 | 0.745 | 0.019 |
| 5 (tcp_count, pkt_count, pkts_per_sec, ...) | 0.011 | 0.763 | 0.022 |
| 7 (tcp_count, pkt_count, pkts_per_sec, ...) | 0.009 | 0.843 | 0.018 |
| 10 (tcp_count, pkt_count, pkts_per_sec, ...) | 0.009 | 0.843 | 0.018 |

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