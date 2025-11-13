from modules.coverage.tracker import can_terminate, coverage_summary, record_tool_activity, reset


def test_coverage_tracker_records_categories():
    operation_id = "OP_TEST"
    reset(operation_id)
    record_tool_activity(operation_id, "auth_chain_analyzer")
    record_tool_activity(operation_id, "shell", command="sqlmap -u http://test")
    summary = coverage_summary(operation_id)
    assert summary["auth"] == 1
    assert summary["injection"] == 1
    assert not can_terminate(operation_id, step_ratio=0.5, required_categories=3)
    assert can_terminate(operation_id, step_ratio=0.5, required_categories=2)
