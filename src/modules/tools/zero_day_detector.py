"""Tool wrapper for zero-day heuristic detection."""

from __future__ import annotations

import json
import os
from typing import Dict, Optional

from strands import tool

from modules.validation.zero_day_heuristics import ZeroDayHeuristicEngine, summarize_signals


def _parse_headers(raw: Optional[str | Dict[str, str]]) -> Dict[str, str]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    headers: Dict[str, str] = {}
    try:
        maybe = json.loads(str(raw))
        if isinstance(maybe, dict):
            headers = {str(k): str(v) for k, v in maybe.items()}
    except Exception:
        pass
    return headers


@tool
def zero_day_pattern_scan(url: str, response_text: str = "", headers: Optional[str | Dict[str, str]] = None) -> str:
    """Analyze a response for zero-day indicators and return prioritized signals."""

    operation_id = os.getenv("CYBER_OPERATION_ID", "")
    engine = ZeroDayHeuristicEngine(operation_id=operation_id)
    parsed_headers = _parse_headers(headers)
    signals = engine.analyze(url, response_text=response_text, headers=parsed_headers)
    return summarize_signals(signals)

