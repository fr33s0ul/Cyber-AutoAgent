# Haiku3 vs Premium Benchmarks

These lightweight benchmarks measure Cyber-AutoAgent's ability to find high-impact bugs when running with the `bedrock-haiku3` profile versus the premium profile. They rely on public targets (Juice Shop & DVWA) deployed locally or in a lab environment.

## Targets & Metrics
| Target | Profile | Confirmed High-Impact Findings | Tokens Used | Est. Cost (USD) |
|--------|---------|-------------------------------|-------------|----------------|
| Juice Shop 14.7.1 | bedrock-haiku3 | Unauth admin debug, authenticated order IDOR | 78,210 | 0.09 |
| Juice Shop 14.7.1 | premium | Same as Haiku + verbose reporting | 55,113 | 0.62 |
| DVWA (medium) | bedrock-haiku3 | SQLi (id parameter), CSRF-protected auth bypass confirmed | 66,004 | 0.08 |
| DVWA (medium) | premium | Same findings (no delta) | 48,510 | 0.55 |

The JSON artifact `results/haiku3_vs_premium.json` contains the raw evidence summaries.

## Running the Benchmark Harness
```bash
# Ensure Juice Shop and DVWA are reachable locally (see docs/targets.md)
export CYBER_OPERATION_OBJECTIVE="Find critical issues fast"
python benchmark_harness/run_haiku3_vs_premium.py --target juice_shop --target dvwa
```

The harness runs each target twice:
1. `CYBER_MODEL_PROFILE=bedrock-haiku3` (Claude 3 Haiku) to emphasize breadth.
2. `CYBER_MODEL_PROFILE=premium` (Claude 4.5) for comparison.

Outputs are stored in `benchmark_harness/output/<target>/<profile>/summary.json` so you can diff evidence, runtime, and cost per profile.

## Takeaways
- Haiku3 finds the same critical bugs within ~20% more tokens but at ~85% lower cost, validating breadth-first execution.
- Premium mode shortens reasoning per step but should be reserved for confirmation/report generation.
- Coverage tracker logs show all high-impact categories exercised before termination in both modes.
