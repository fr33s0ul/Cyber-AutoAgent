#!/usr/bin/env python3
"""Utility script to run Haiku3 vs premium comparison benchmarks."""

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List

TARGETS = {
    "juice_shop": {
        "target": "http://localhost:3000",
        "objective": "Exploit unauthenticated + authenticated high-impact bugs",
    },
    "dvwa": {
        "target": "http://localhost:8080",
        "objective": "Break authentication and extract data",
    },
}

PROFILES = ["bedrock-haiku3", "premium"]


def run_profile(target_key: str, profile: str, extra_args: List[str]) -> Dict[str, str]:
    data = TARGETS[target_key]
    env = os.environ.copy()
    env["CYBER_MODEL_PROFILE"] = profile
    cmd = [
        "uv",
        "run",
        "python",
        "-m",
        "cyberautoagent",
        "--target",
        data["target"],
        "--objective",
        data["objective"],
        "--max-steps",
        env.get("BENCH_MAX_STEPS", "160"),
    ] + extra_args
    print(f"\n[benchmark] Running {target_key} with profile={profile}")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    output_dir = Path("benchmark_harness") / "output" / target_key / profile
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "stdout.log").write_text(result.stdout)
    (output_dir / "stderr.log").write_text(result.stderr)
    return {
        "returncode": result.returncode,
        "stdout": str(output_dir / "stdout.log"),
        "stderr": str(output_dir / "stderr.log"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", action="append", choices=TARGETS.keys(), help="Targets to benchmark")
    parser.add_argument("--extra", nargs=argparse.REMAINDER, default=[], help="Extra CLI args for cyberautoagent")
    args = parser.parse_args()
    selected = args.target or list(TARGETS.keys())
    summary: Dict[str, Dict[str, Dict[str, str]]] = {}
    for target in selected:
        summary[target] = {}
        for profile in PROFILES:
            summary[target][profile] = run_profile(target, profile, args.extra)
    summary_path = Path("benchmark_harness/output/summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\nBenchmark summary written to {summary_path}")
if __name__ == "__main__":
    main()
