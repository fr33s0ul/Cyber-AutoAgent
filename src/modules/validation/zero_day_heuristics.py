"""Zero-day heuristic detection utilities."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from modules.coverage.tracker import mark_category


DEBUG_HEADER_PATTERN = re.compile(r"x-(debug|trace|release)", re.IGNORECASE)
STACK_TRACE_PATTERN = re.compile(r"Traceback|stack trace|Segmentation fault", re.IGNORECASE)
UNVERSIONED_ADMIN = re.compile(r"/(admin|manage|console)(/|$)", re.IGNORECASE)
DEBUG_ENDPOINT = re.compile(r"/__debug__|/__internal__|/debug/|/console/", re.IGNORECASE)


@dataclass
class ZeroDaySignal:
    indicator: str
    description: str
    priority: str = "high"


class ZeroDayHeuristicEngine:
    """Detect unusual patterns that warrant chained exploitation."""

    def __init__(self, operation_id: Optional[str] = None) -> None:
        self.operation_id = operation_id or os.getenv("CYBER_OPERATION_ID", "")

    def analyze(self, url: str, response_text: str = "", headers: Optional[Dict[str, str]] = None) -> List[ZeroDaySignal]:
        signals: List[ZeroDaySignal] = []
        normalized_url = url or ""
        headers = headers or {}

        if UNVERSIONED_ADMIN.search(normalized_url):
            signals.append(
                ZeroDaySignal(
                    indicator="unversioned_admin",
                    description="Admin-like path without versioning or auth markers",
                )
            )

        if DEBUG_ENDPOINT.search(normalized_url):
            signals.append(
                ZeroDaySignal(
                    indicator="debug_endpoint",
                    description="Debug endpoint exposed publicly",
                    priority="critical",
                )
            )

        header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
        if DEBUG_HEADER_PATTERN.search(header_blob):
            signals.append(
                ZeroDaySignal(
                    indicator="debug_headers",
                    description="Response leaked debug headers",
                )
            )

        if STACK_TRACE_PATTERN.search(response_text or ""):
            signals.append(
                ZeroDaySignal(
                    indicator="stack_trace",
                    description="Stack trace exposed—prioritize exploit development",
                )
            )

        if "build" in (headers.get("etag", "") or "").lower() and "git" in headers.get("etag", ""):
            signals.append(
                ZeroDaySignal(
                    indicator="build_hash",
                    description="Potential leaked build hash—check for orphan artifacts",
                )
            )

        if signals and self.operation_id:
            mark_category(self.operation_id, "zero_day")

        return signals


def summarize_signals(signals: List[ZeroDaySignal]) -> str:
    if not signals:
        return "No zero-day indicators detected"
    lines = []
    for signal in signals:
        lines.append(f"- [{signal.priority}] {signal.indicator}: {signal.description}")
    return "\n".join(lines)

