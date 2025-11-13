"""Stop tool wrapper enforcing coverage requirements."""

from __future__ import annotations

import json
import os

from strands import tool
from strands_tools.stop import stop as base_stop

from modules.coverage.tracker import can_terminate


def _compute_step_ratio() -> float:
    try:
        current = float(os.getenv("CYBER_CURRENT_STEPS", "0"))
        max_steps = float(os.getenv("CYBER_MAX_STEPS", os.getenv("CYBER_STEP_LIMIT", "100")))
        if max_steps <= 0:
            return 0.0
        return min(1.0, current / max_steps)
    except Exception:
        return 0.0


@tool
def guarded_stop(reason: str = "", force: bool = False) -> str:
    """Terminate only when coverage requirements are satisfied."""

    operation_id = os.getenv("CYBER_OPERATION_ID", "")
    min_classes = int(os.getenv("CYBER_COVERAGE_MIN_CLASSES", "3"))
    ratio = _compute_step_ratio()
    if force:
        return base_stop(reason=reason)
    if not can_terminate(operation_id, ratio, min_classes):
        message = {
            "allowed": False,
            "reason": "Coverage incomplete",
            "required_categories": min_classes,
            "step_ratio": ratio,
        }
        return json.dumps(message, indent=2)
    return base_stop(reason=reason)
