import os

from modules.coverage import coverage_summary, reset
from modules.validation.zero_day_heuristics import ZeroDayHeuristicEngine


def test_zero_day_signals_mark_coverage(tmp_path):
    op = "OP_ZERO_DAY"
    reset(op)
    os.environ["CYBER_OPERATION_ID"] = op
    engine = ZeroDayHeuristicEngine(operation_id=op)
    signals = engine.analyze("https://target/admin", response_text="Traceback: boom", headers={"X-Debug": "true"})
    assert signals
    summary = coverage_summary(op)
    assert summary.get("zero_day", 0) >= 1
