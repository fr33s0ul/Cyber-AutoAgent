from modules.telemetry import cost_tracker


def test_cost_tracker_registers_and_summarizes():
    cost_tracker.register_pricing("test-model", "bedrock", {"input_per_1k": 0.001, "output_per_1k": 0.002})
    summary = cost_tracker.record_usage("OPCOST", "bedrock", "test-model", 1000, 500)
    assert summary["prompt_tokens"] == 1000
    assert summary["completion_tokens"] == 500
    assert summary["cost"] > 0
    rollup = cost_tracker.summarize("OPCOST")
    assert rollup["cost"] == summary["cost"]
