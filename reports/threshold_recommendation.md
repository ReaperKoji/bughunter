# Threshold Calibration Report

Generated: 2026-03-10T14:51:35.286011Z

## Dataset
Total samples: 20
Positives: 10
Negatives: 10

## Recommended Thresholds
- min_sensitivity_score: 0.68
- min_body_diff_ratio: 0.65
- baseline_score_threshold (max): 0.69

## Metrics (approx)
- precision: 1.00
- recall: 0.80
- f1: 0.89
- false_positive_rate: 0.00

## Top Candidate Thresholds
| rank | min_sens | min_body_diff | max_baseline | precision | recall | f1 | fpr |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0.68 | 0.65 | 0.69 | 1.00 | 0.80 | 0.89 | 0.00 |
| 2 | 0.68 | 0.65 | 0.71 | 1.00 | 0.80 | 0.89 | 0.00 |
| 3 | 0.68 | 0.65 | 0.76 | 1.00 | 0.80 | 0.89 | 0.00 |
| 4 | 0.68 | 0.65 | 0.73 | 1.00 | 0.80 | 0.89 | 0.00 |
| 5 | 0.71 | 0.65 | 0.69 | 1.00 | 0.80 | 0.89 | 0.00 |

## Notes
Values are derived from percentile heuristics and simple F1 optimization. Review results and adjust per program.