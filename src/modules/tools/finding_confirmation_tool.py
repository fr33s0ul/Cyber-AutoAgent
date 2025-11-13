"""Tool binding for the finding confirmation workflow."""

from __future__ import annotations

from typing import Optional

from strands import tool

from modules.validation.finding_confirmation import build_engine_from_env
from modules.validation.response_validation import parse_headers_input


@tool
def confirm_finding_tool(
    finding_type: str,
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    body: Optional[str] = None,
    comparison_url: Optional[str] = None,
    comparison_headers: Optional[str] = None,
    artifact_path: Optional[str] = None,
) -> str:
    """Confirm high-impact findings with control checks and artifact review."""

    engine = build_engine_from_env()
    result = engine.confirm(
        finding_type=finding_type,
        url=url,
        method=method,
        headers=parse_headers_input(headers),
        body=body,
        comparison_url=comparison_url,
        comparison_headers=parse_headers_input(comparison_headers),
        artifact_path=artifact_path,
    )
    return result.to_json()
