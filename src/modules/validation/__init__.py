"""Validation helpers for Cyber-AutoAgent."""

from .response_validation import (
    ResponseBaselineStore,
    ResponseClassification,
    ResponseValidationResult,
    normalize_html,
    compute_similarity,
    is_same_page,
    contains_login_indicators,
    looks_like_fallback_frontend,
    looks_like_api_json,
    bootstrap_default_baselines,
    AuthBypassValidator,
    response_contains_sensitive_data,
)
from .zero_day_heuristics import ZeroDayHeuristicEngine, ZeroDaySignal

__all__ = [
    "ResponseBaselineStore",
    "ResponseClassification",
    "ResponseValidationResult",
    "normalize_html",
    "compute_similarity",
    "is_same_page",
    "contains_login_indicators",
    "looks_like_fallback_frontend",
    "looks_like_api_json",
    "bootstrap_default_baselines",
    "AuthBypassValidator",
    "response_contains_sensitive_data",
    "ZeroDayHeuristicEngine",
    "ZeroDaySignal",
]
