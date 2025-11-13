from modules.planner.adaptive_chain import AdaptiveChainPlanner


def test_adaptive_chain_includes_steps_for_admin_indicator():
    planner = AdaptiveChainPlanner()
    plan = planner.build_chain("admin portal exposed", novel_patterns=["stack trace"])
    description = plan.describe()
    assert "Goal" in description
    assert "response_validation_tool" in description
    assert "knowledge_base_lookup" in description
