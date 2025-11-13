import json

from modules.validation.response_validation import (
    AuthBypassValidator,
    NegativeControlResult,
    ResponseBaselineStore,
    ResponseClassification,
    contains_login_indicators,
    is_same_page,
    looks_like_api_json,
    normalize_html,
)


def test_normalize_html_strips_script():
    raw = "<html><script>alert('x')</script><body> DATA </body></html>"
    normalized = normalize_html(raw)
    assert "alert" not in normalized
    assert "data" in normalized


def test_is_same_page_handles_minor_variations():
    a = "<div>Welcome User</div>"
    b = "<div>Welcome   User</div>"
    assert is_same_page(a, b)


def test_login_indicator_detection():
    text = "Please LOGIN with your account"
    assert contains_login_indicators(normalize_html(text))


def test_json_detection_by_headers():
    body = json.dumps({"password": "secret"})
    headers = {"Content-Type": "application/json"}
    assert looks_like_api_json(body, headers)


def test_auth_validator_flags_baseline_match(tmp_path):
    store = ResponseBaselineStore("example.com", "OP_TEST", base_dir=tmp_path)
    baseline_body = "<html><h1>Welcome</h1> Please Login" \
        "<div id='root'></div>"
    store.record("home", "https://example.com", baseline_body, {})
    validator = AuthBypassValidator(store)
    result = validator.evaluate(
        url="https://example.com/api/users",
        candidate_body=baseline_body,
        candidate_headers={},
        candidate_status=200,
    )
    assert result.classification == ResponseClassification.MISCONFIGURATION_OR_FALLBACK


def test_auth_validator_confirms_sensitive_json(tmp_path):
    store = ResponseBaselineStore("example.com", "OP_TEST", base_dir=tmp_path)
    validator = AuthBypassValidator(store)
    candidate = json.dumps({"user": "admin", "password": "p@ss"})
    neg = NegativeControlResult(
        url="https://example.com/api/users/missing",
        status_code=404,
        body="Not found",
        similarity=0.1,
    )
    result = validator.evaluate(
        url="https://example.com/api/users",
        candidate_body=candidate,
        candidate_headers={"Content-Type": "application/json"},
        candidate_status=200,
        negative_control=neg,
    )
    assert result.classification == ResponseClassification.CONFIRMED_AUTH_BYPASS
    assert result.contains_sensitive_data


def test_auth_validator_detects_negative_control_match(tmp_path):
    store = ResponseBaselineStore("example.com", "OP_TEST", base_dir=tmp_path)
    validator = AuthBypassValidator(store)
    body = "Generic portal"
    neg = NegativeControlResult(
        url="https://example.com/api/ghost",
        status_code=200,
        body=body,
        similarity=0.99,
    )
    result = validator.evaluate(
        url="https://example.com/api/ghost",
        candidate_body=body,
        candidate_headers={},
        candidate_status=200,
        negative_control=neg,
    )
    assert result.classification == ResponseClassification.NEGATIVE_CONTROL_MATCH
