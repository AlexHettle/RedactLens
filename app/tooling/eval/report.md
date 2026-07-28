# RedactLens evaluation report

> Headline metrics below come only from the selection-isolated holdout corpus. The
> separate calibration corpus chooses confidence weights and the Tier A threshold.
> Findings and plants use duplicate-safe one-to-one matching; gates require support.

## Reproducibility metadata

- Generated (UTC): `2026-07-28T01:30:52+00:00`
- Corpus version: `3.0.0`
- Detector configuration SHA-256: `0697e7f34bcd1668d6fd1c3d16a910c2828bca1d209f658623d7080d7223788f`
- Evaluation source SHA-256: `740997ba8304d1fae005ed1cef38aca83146d55778fec3258e6712f92574e5f1`
- Selected confidence-weight profile: `base+0.00-contextx1.25-v1` (base offset +0.00, context scale 1.25)
- Confidence-weight policy: Minimize calibration Brier score plus expected calibration error; then maximize eligible-threshold recall and precision; preserve the deployed profile only on an identical best plateau.
- Selected Tier A threshold: `0.8500`
- Threshold policy: Across every distinct calibration confidence boundary, maximize recall subject to minimum precision; then maximize precision; preserve the deployed threshold when it lies on the best plateau.
- Calibration: seed `13371`, 26 documents, digest `0821a8010f6e0cb1971aa412394edd81a042b04ae48b8cb7dcb5c093bf1d8ab3`
- Holdout: seed `91973`, 27 documents, digest `46a783b62875c601ba63fccb7b7c371c705944d3501250e3b06c28e0aa5d3e4d`

## Holdout headline results

| quality gate | value | target | eligible support | result |
|---|---:|---:|---:|---|
| Tier A precision | 1.000 | >= 0.90 | 19 | PASS |
| Tier A recall | 0.655 | >= 0.50 | 29 | PASS |
| Any-tier recall | 1.000 | >= 0.95 | 29 | PASS |
| Selected threshold is deployed | 0.8500 | == 0.8500 | 1 | PASS |
| Selected confidence weights are deployed | `base+0.00-contextx1.25-v1` | == `base+0.00-contextx1.25-v1` | 1 | PASS |

Holdout emitted 40 canonical findings from 58 raw detector opinions across 27 documents. Consolidation absorbed 18 opinions; 18 of those were explicit suppressions.

| user-impact metric | value |
|---|---:|
| Overall precision | 0.725 |
| Overall recall | 1.000 |
| Overall F1 | 0.841 |
| Tier A recall | 0.655 |
| Tier B rescue recall | 0.345 |
| False positives / 1,000 files | 407.41 |
| Canonical findings / planted value | 1.379 |
| Files / second (single local run) | 207.2 |
| MB / second (single local run) | 0.14 |

## Calibration-only confidence-weight selection

Every profile below is evaluated only against calibration labels. Selection minimizes Brier score plus expected calibration error; threshold quality and deployment stability are deterministic tie-breaks.

| profile | base offset | context scale | Brier | ECE | threshold | precision | recall | eligible |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `base-0.05-contextx0.75-v1` | -0.05 | 0.75 | 0.1490 | 0.1200 | 0.7500 | 1.000 | 0.704 | yes |
| `base-0.05-contextx1.00-v1` | -0.05 | 1.00 | 0.1353 | 0.1268 | 0.8500 | 1.000 | 0.630 | yes |
| `base-0.05-contextx1.25-v1` | -0.05 | 1.25 | 0.1298 | 0.1470 | 0.8500 | 1.000 | 0.630 | yes |
| `base+0.00-contextx0.75-v1` | +0.00 | 0.75 | 0.1562 | 0.1859 | 0.8000 | 1.000 | 0.704 | yes |
| `base+0.00-contextx1.00-v1` | +0.00 | 1.00 | 0.1423 | 0.1370 | 0.8500 | 1.000 | 0.630 | yes |
| `base+0.00-contextx1.25-v1` **selected** | +0.00 | 1.25 | 0.1370 | 0.1172 | 0.8500 | 1.000 | 0.630 | yes |
| `base+0.05-contextx0.75-v1` | +0.05 | 0.75 | 0.1684 | 0.1795 | 0.8500 | 1.000 | 0.704 | yes |
| `base+0.05-contextx1.00-v1` | +0.05 | 1.00 | 0.1543 | 0.1580 | 0.9500 | 1.000 | 0.630 | yes |
| `base+0.05-contextx1.25-v1` | +0.05 | 1.25 | 0.1485 | 0.1426 | 0.9625 | 1.000 | 0.630 | yes |

## Calibration-only threshold selection

Minimum acceptable calibration precision: `0.90`. The selected threshold is marked; no holdout labels participate in this choice.

| threshold | precision | recall | F1 | findings |
|---:|---:|---:|---:|---:|
| 0.0000 | 0.614 | 1.000 | 0.761 | 44 |
| 0.0375 | 0.643 | 1.000 | 0.783 | 42 |
| 0.0875 | 0.659 | 1.000 | 0.794 | 41 |
| 0.1500 | 0.675 | 1.000 | 0.806 | 40 |
| 0.3500 | 0.711 | 1.000 | 0.831 | 38 |
| 0.4125 | 0.730 | 1.000 | 0.844 | 37 |
| 0.6500 | 0.750 | 1.000 | 0.857 | 36 |
| 0.6750 | 0.833 | 0.926 | 0.877 | 30 |
| 0.6875 | 0.846 | 0.815 | 0.830 | 26 |
| 0.8000 | 0.864 | 0.704 | 0.776 | 22 |
| 0.8375 | 0.850 | 0.630 | 0.723 | 20 |
| 0.8500 **selected** | 1.000 | 0.630 | 0.773 | 17 |
| 0.9125 | 1.000 | 0.630 | 0.773 | 17 |
| 0.9625 | 1.000 | 0.556 | 0.714 | 15 |
| 0.9700 | 1.000 | 0.370 | 0.541 | 10 |
| 0.9750 | 1.000 | 0.333 | 0.500 | 9 |
| 0.9875 | 1.000 | 0.185 | 0.312 | 5 |
| 1.0000 | 1.000 | 0.148 | 0.258 | 4 |

```text
0.0000  P ###############......... 0.61
      R ######################## 1.00
0.0375  P ###############......... 0.64
      R ######################## 1.00
0.0875  P ################........ 0.66
      R ######################## 1.00
0.1500  P ################........ 0.68
      R ######################## 1.00
0.3500  P #################....... 0.71
      R ######################## 1.00
0.4125  P ##################...... 0.73
      R ######################## 1.00
0.6500  P ##################...... 0.75
      R ######################## 1.00
0.6750  P ####################.... 0.83
      R ######################.. 0.93
0.6875  P ####################.... 0.85
      R ####################.... 0.81
0.8000  P #####################... 0.86
      R #################....... 0.70
0.8375  P ####################.... 0.85
      R ###############......... 0.63
0.8500  P ######################## 1.00
      R ###############......... 0.63
0.9125  P ######################## 1.00
      R ###############......... 0.63
0.9625  P ######################## 1.00
      R #############........... 0.56
0.9700  P ######################## 1.00
      R #########............... 0.37
0.9750  P ######################## 1.00
      R ########................ 0.33
0.9875  P ######################## 1.00
      R ####.................... 0.19
1.0000  P ######################## 1.00
      R ####.................... 0.15
```

## Holdout results by detector

| detector | raw precision | raw recall | expected plants | raw FP | raw FN | primary findings | canonical contributions | raw opinions | consolidated opinions | consolidation rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `aws_access_key` | 0.667 | 1.000 | 2 | 1 | 0 | 3 | 3 | 3 | 0 | 0.0% |
| `connection_string` | 0.500 | 1.000 | 2 | 2 | 0 | 4 | 4 | 4 | 0 | 0.0% |
| `credit_card` | 1.000 | 1.000 | 5 | 0 | 0 | 5 | 5 | 5 | 0 | 0.0% |
| `email` | 0.444 | 1.000 | 4 | 5 | 0 | 5 | 9 | 9 | 4 | 44.4% |
| `high_entropy_secret` | 0.056 | 1.000 | 1 | 17 | 0 | 4 | 10 | 18 | 14 | 77.8% |
| `jwt` | 1.000 | 1.000 | 4 | 0 | 0 | 4 | 4 | 4 | 0 | 0.0% |
| `password_assignment` | 0.600 | 1.000 | 3 | 2 | 0 | 5 | 5 | 5 | 0 | 0.0% |
| `phone` | 0.800 | 1.000 | 4 | 1 | 0 | 5 | 5 | 5 | 0 | 0.0% |
| `private_key_header` | 1.000 | 1.000 | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0.0% |
| `us_ssn` | 0.750 | 1.000 | 3 | 1 | 0 | 4 | 4 | 4 | 0 | 0.0% |

## Holdout results by category

| category | precision | recall | expected plants | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| `credential` | 0.619 | 1.000 | 13 | 0.765 | 8 | 0 |
| `financial` | 1.000 | 1.000 | 5 | 1.000 | 0 | 0 |
| `personal_id` | 0.786 | 1.000 | 11 | 0.880 | 3 | 0 |

## Confidence calibration

- Brier score: `0.0642` (lower is better)
- Expected calibration error: `0.0729` (lower is better)

| confidence bucket | findings | average confidence | observed precision |
|---|---:|---:|---:|
| [0.0, 0.1) | 4 | 0.016 | 0.000 |
| [0.1, 0.2) | 1 | 0.175 | 0.000 |
| [0.3, 0.4) | 3 | 0.333 | 0.000 |
| [0.6, 0.7) | 11 | 0.673 | 0.727 |
| [0.8, 0.9) | 2 | 0.819 | 1.000 |
| [0.9, 1.0] | 19 | 0.962 | 1.000 |

## Ollama comparison

Configuration: provider `Ollama`, configured model `llama3.2`, resolved server model `unavailable`, host `http://127.0.0.1:11434`, timeout `60.0` seconds.
Resolved model digest: `unavailable`.
Inference options: `{"seed": 91973, "temperature": 0}`; options SHA-256 `48edd72379a83e02a322ae0728998e1b1c739d3c0561f363a7b7203190618537`.
Prompt source SHA-256: `ed8b8e363a4b3e58e7f45dceec06a3b0bd6e1c20aab5ba4260b497cadb898026`.
Prompt path normalization: `temporary corpus root -> <EVAL_CORPUS>`.
Inference telemetry: 0 attempts, 0 successes, 0 failures.

Status: `not_requested`.

## Interpretation and limits

- All planted values are fabricated; no real credentials or personal data are used.
- The public holdout is deterministic, structurally role-separated, and excluded from automated weight/threshold selection. It is regression evidence, not a blinded external test set or a claim about all real-world repositories.
- This is a hard-negative-enriched stress corpus. False positives per 1,000 files are not an estimate of a typical production repository's incident rate.
- Per-detector rows make weak detectors and duplicate consolidation visible instead of allowing aggregate scores to hide them.
- Throughput is an indicative single-run measurement and is excluded from the deterministic stale-report comparison.

Reproduce with `python tooling/eval/run_eval.py`; verify freshness with `python tooling/eval/run_eval.py --check`.
