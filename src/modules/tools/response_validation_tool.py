"""Strands tool exposing response validation utilities."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from strands import tool

from modules.validation.response_validation import (
    AuthBypassValidator,
    NegativeControlResult,
    ResponseBaselineStore,
    ResponseClassification,
    ResponseValidationResult,
    bootstrap_default_baselines,
    build_negative_control_url,
    fetch_response,
    parse_headers_input,
    store_response_artifact,
)


def _get_operation_context() -> Dict[str, str]:
    return {
        "target": os.getenv("CYBER_TARGET_NAME", os.getenv("CYBER_TARGET", "")),
        "operation_id": os.getenv("CYBER_OPERATION_ID", ""),
        "provider": os.getenv("CYBER_AGENT_PROVIDER", "bedrock"),
    }


def _init_store(ctx: Dict[str, str]) -> ResponseBaselineStore:
    target = ctx.get("target") or ""
    op = ctx.get("operation_id") or "OP_LOCAL"
    provider = ctx.get("provider") or "bedrock"
    return ResponseBaselineStore(target=target, operation_id=op, provider=provider)


def _serialize_result(result: ResponseValidationResult) -> str:
    payload = {
        "classification": result.classification.value,
        "reasoning": result.reasoning,
        "baseline_label": result.baseline_label,
        "similarity_to_baseline": result.similarity_to_baseline,
        "contains_sensitive_data": result.contains_sensitive_data,
        "negative_control_matched": result.negative_control_matched,
        "response_artifact": result.response_path,
    }
    return json.dumps(payload, indent=2)


@tool
def response_validation_tool(
    action: str,
    url: str,
    label: Optional[str] = None,
    method: str = "GET",
    headers: Optional[str] = None,
    body: Optional[str] = None,
    expected_markers: Optional[str] = None,
) -> str:
    """Perform response validation workflows (baseline, compare, auth probes)."""

    ctx = _get_operation_context()
    store = _init_store(ctx)

    if action == "record_baseline":
        status, resp_headers, text = fetch_response(url, method=method, headers=parse_headers_input(headers), data=body)
        if status is None:
            return f"Failed to fetch baseline: {text}"
        label_to_use = label or "baseline"
        store.record(label_to_use, url, text, resp_headers)
        return json.dumps(
            {
                "message": f"Baseline '{label_to_use}' stored",
                "status_code": status,
                "login_like": bool(text and "login" in text.lower()),
                "available": list(store.list_baselines().keys()),
            },
            indent=2,
        )

    if action == "compare":
        status, resp_headers, text = fetch_response(url, method=method, headers=parse_headers_input(headers), data=body)
        if status is None:
            return text
        match = store.find_similar(text)
        artifact = store_response_artifact(store, label or "comparison", text)
        return json.dumps(
            {
                "status_code": status,
                "matched_baseline": match,
                "artifact": artifact,
            },
            indent=2,
        )

    if action == "auth_probe":
        bootstrap_default_baselines(
            ctx.get("target") or url,
            ctx.get("operation_id") or "OP_LOCAL",
            ctx.get("provider") or "bedrock",
        )
        parsed_headers = parse_headers_input(headers)
        status, resp_headers, text = fetch_response(url, method=method, headers=parsed_headers, data=body)
        if status is None:
            return text
        gibberish_url = build_negative_control_url(url)
        neg_status, _, neg_body = fetch_response(gibberish_url, headers=parsed_headers, method=method)
        neg_result = None
        if neg_status is not None:
            from modules.validation.response_validation import normalize_html, compute_similarity

            neg_result = NegativeControlResult(
                url=gibberish_url,
                status_code=neg_status,
                body=neg_body,
                similarity=compute_similarity(normalize_html(text), normalize_html(neg_body)),
            )
        validator = AuthBypassValidator(store)
        markers = []
        if expected_markers:
            markers = [m.strip() for m in expected_markers.split(",") if m.strip()]
        result = validator.evaluate(
            url=url,
            candidate_body=text,
            candidate_headers=parsed_headers,
            candidate_status=status,
            negative_control=neg_result,
            additional_markers=markers,
        )
        result.response_path = store_response_artifact(store, label or "auth_probe", text)
        return _serialize_result(result)

    available = list(store.list_baselines().keys())
    return json.dumps(
        {
            "message": "Unsupported action",
            "supported": ["record_baseline", "compare", "auth_probe"],
            "available_baselines": available,
        },
        indent=2,
    )
