from modules.tools.knowledge_base import knowledge_base_lookup, list_high_impact_patterns


def test_knowledge_base_lookup_returns_entries():
    result = knowledge_base_lookup(bug_class="sqli")
    assert "SQL injection" in result or "SQLi" in result
    assert "payloads" in result.lower()


def test_high_impact_patterns_lists_payloads():
    summary = list_high_impact_patterns(limit=2)
    assert "auth_bypass" in summary
    assert "Payloads" in summary
