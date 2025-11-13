"""Cost tracking utilities for model usage."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class Pricing:
    input_per_1k: float
    output_per_1k: float

    def estimate(self, prompt_tokens: float, completion_tokens: float) -> float:
        return (prompt_tokens / 1000.0) * self.input_per_1k + (completion_tokens / 1000.0) * self.output_per_1k


_PRICING: Dict[str, Pricing] = {}
_STATE: Dict[str, Dict[str, float]] = defaultdict(lambda: {"prompt_tokens": 0.0, "completion_tokens": 0.0, "cost": 0.0})


def register_pricing(model_id: str, provider: str, pricing: Optional[Dict[str, float]]) -> None:
    if not (model_id and provider and pricing):
        return
    try:
        _PRICING[f"{provider}:{model_id}"] = Pricing(
            input_per_1k=float(pricing.get("input_per_1k", 0.0)),
            output_per_1k=float(pricing.get("output_per_1k", 0.0)),
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Unable to register pricing for %s/%s: %s", provider, model_id, exc)


def record_usage(
    operation_id: str,
    provider: str,
    model_id: str,
    prompt_tokens: float,
    completion_tokens: float,
) -> Dict[str, float]:
    if not operation_id:
        return {}
    key = f"{provider}:{model_id}"
    pricing = _PRICING.get(key)
    cost = pricing.estimate(prompt_tokens, completion_tokens) if pricing else 0.0
    state = _STATE[operation_id]
    state["prompt_tokens"] += prompt_tokens
    state["completion_tokens"] += completion_tokens
    state["cost"] += cost
    logger.info(
        "Usage recorded op=%s provider=%s model=%s prompt_tokens=%.2f completion_tokens=%.2f est_cost=%.4f",
        operation_id,
        provider,
        model_id,
        prompt_tokens,
        completion_tokens,
        cost,
    )
    return state.copy()


def summarize(operation_id: str) -> Dict[str, float]:
    return dict(_STATE.get(operation_id, {}))

