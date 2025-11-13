"""HTTP response validation utilities for Cyber-AutoAgent."""

from __future__ import annotations

import json
import logging
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests

from modules.config.manager import get_config_manager
from modules.handlers.utils import sanitize_target_name

logger = logging.getLogger(__name__)


LOGIN_KEYWORDS = [
    "login",
    "sign in",
    "sign-in",
    "authentication required",
    "auth required",
    "please log",
    "enter your password",
    "forgot password",
    "session expired",
    "sso",
]

FRONTEND_FALLBACK_KEYWORDS = [
    "<div id=\"root\"",
    "<div id='root'",
    "react-app",
    "angular",
    "we'll be right back",
    "maintenance",
    "portal",
    "welcome to",
    "marketing",
    "hero-section",
    "all rights reserved",
]

SENSITIVE_DATA_MARKERS = [
    "aws_access_key",
    "password",
    "private_key",
    "user_email",
    "ssn",
    "secret",
    "token",
    "config",
    "<admin",
]


class ResponseClassification(str, Enum):
    """Outcome classifications used for HTTP response validation."""

    NO_EVIDENCE = "NO_EVIDENCE"
    MISCONFIGURATION_OR_FALLBACK = "MISCONFIGURATION_OR_FALLBACK"
    POTENTIAL_AUTH_WEAKNESS = "POTENTIAL_AUTH_WEAKNESS"
    CONFIRMED_AUTH_BYPASS = "CONFIRMED_AUTH_BYPASS"
    CONFIRMED_IMPACT = "CONFIRMED_IMPACT"
    NEGATIVE_CONTROL_MATCH = "NEGATIVE_CONTROL_MATCH"


@dataclass
class ResponseValidationResult:
    """Structured result for validation decisions."""

    classification: ResponseClassification
    reasoning: str
    similarity_to_baseline: Optional[float] = None
    baseline_label: Optional[str] = None
    contains_sensitive_data: bool = False
    negative_control_matched: bool = False
    response_path: Optional[str] = None


@dataclass
class ResponseFingerprint:
    """Snapshot of a canonical baseline response."""

    url: str
    digest: str
    normalized_excerpt: str
    login_like: bool
    fallback_like: bool
    created_at: float = field(default_factory=lambda: time.time())


class ResponseBaselineStore:
    """Disk-backed store for baseline HTTP responses per operation."""

    def __init__(
        self,
        target: str,
        operation_id: str,
        provider: str = "bedrock",
        base_dir: Optional[str] = None,
    ) -> None:
        self.target = sanitize_target_name(target)
        self.operation_id = operation_id
        manager = get_config_manager()
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            path = manager.get_unified_output_path(provider, self.target, operation_id, "validation")
            self.base_dir = Path(path)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.fingerprints_path = self.base_dir / "baselines.json"
        self.responses_dir = self.base_dir / "responses"
        self.responses_dir.mkdir(exist_ok=True)
        self._fingerprints: Dict[str, ResponseFingerprint] = {}
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.fingerprints_path.exists():
            return
        try:
            data = json.loads(self.fingerprints_path.read_text())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not load baseline fingerprints: %s", exc)
            return
        for label, payload in data.items():
            self._fingerprints[label] = ResponseFingerprint(
                url=payload.get("url", ""),
                digest=payload.get("digest", ""),
                normalized_excerpt=payload.get("normalized_excerpt", ""),
                login_like=payload.get("login_like", False),
                fallback_like=payload.get("fallback_like", False),
                created_at=payload.get("created_at", time.time()),
            )

    # ------------------------------------------------------------------
    def save(self) -> None:
        payload = {
            label: {
                "url": fp.url,
                "digest": fp.digest,
                "normalized_excerpt": fp.normalized_excerpt,
                "login_like": fp.login_like,
                "fallback_like": fp.fallback_like,
                "created_at": fp.created_at,
            }
            for label, fp in self._fingerprints.items()
        }
        self.fingerprints_path.write_text(json.dumps(payload, indent=2))

    # ------------------------------------------------------------------
    def record(self, label: str, url: str, body: str, headers: Dict[str, str]) -> ResponseFingerprint:
        normalized = normalize_html(body)
        digest = _stable_digest(normalized)
        fp = ResponseFingerprint(
            url=url,
            digest=digest,
            normalized_excerpt=normalized[:4000],
            login_like=contains_login_indicators(normalized),
            fallback_like=looks_like_fallback_frontend(normalized),
        )
        self._fingerprints[label] = fp
        self.save()
        try:
            response_path = self.responses_dir / f"baseline_{label}.txt"
            response_path.write_text(body)
        except Exception as exc:  # pragma: no cover - disk guard
            logger.debug("Unable to persist baseline body: %s", exc)
        return fp

    # ------------------------------------------------------------------
    def find_similar(self, body: str, threshold: float = 0.9) -> Optional[Tuple[str, float]]:
        if not self._fingerprints:
            return None
        normalized = normalize_html(body)
        best_label = None
        best_score = 0.0
        for label, fp in self._fingerprints.items():
            score = compute_similarity(normalized, fp.normalized_excerpt)
            if score > best_score:
                best_label = label
                best_score = score
        if best_label and best_score >= threshold:
            return best_label, best_score
        return None

    # ------------------------------------------------------------------
    def list_baselines(self) -> Dict[str, ResponseFingerprint]:
        return dict(self._fingerprints)

    # ------------------------------------------------------------------
    def persist_response(self, label: str, body: str) -> str:
        safe_label = re.sub(r"[^a-zA-Z0-9._-]", "_", label)
        path = self.responses_dir / f"{safe_label}.txt"
        path.write_text(body)
        return str(path)


# ----------------------------------------------------------------------
# Normalization helpers
# ----------------------------------------------------------------------

def normalize_html(response_text: str) -> str:
    text = response_text or ""
    lowered = text.lower()
    lowered = re.sub(r"<script[\s\S]*?</script>", "", lowered)
    lowered = re.sub(r"<style[\s\S]*?</style>", "", lowered)
    lowered = re.sub(r"<!--.*?-->", " ", lowered, flags=re.S)
    lowered = re.sub(r"\s+", " ", lowered)
    return lowered.strip()


def compute_similarity(a: str, b: str) -> float:
    import difflib

    return difflib.SequenceMatcher(None, a, b).ratio()


def is_same_page(a: str, b: str, threshold: float = 0.95) -> bool:
    return compute_similarity(normalize_html(a), normalize_html(b)) >= threshold


def contains_login_indicators(text: str) -> bool:
    lt = text.lower()
    return any(keyword in lt for keyword in LOGIN_KEYWORDS)


def looks_like_fallback_frontend(text: str) -> bool:
    lt = text.lower()
    return any(keyword in lt for keyword in FRONTEND_FALLBACK_KEYWORDS)


def looks_like_api_json(text: str, headers: Optional[Dict[str, str]] = None) -> bool:
    headers = headers or {}
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "json" in content_type:
        return True
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def response_contains_sensitive_data(
    text: str, headers: Optional[Dict[str, str]] = None, additional_markers: Optional[Iterable[str]] = None
) -> bool:
    return _has_sensitive_markers(text, additional=additional_markers) or looks_like_api_json(text, headers)


def _stable_digest(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


# ----------------------------------------------------------------------
# Validation + classification
# ----------------------------------------------------------------------


def _has_sensitive_markers(text: str, additional: Optional[Iterable[str]] = None) -> bool:
    lower = text.lower()
    markers = list(SENSITIVE_DATA_MARKERS)
    if additional:
        markers.extend(m.strip().lower() for m in additional if m)
    return any(marker in lower for marker in markers)


@dataclass
class NegativeControlResult:
    url: str
    status_code: Optional[int]
    body: str
    similarity: Optional[float]


class AuthBypassValidator:
    """Classifier that compares baseline + negative control responses."""

    def __init__(self, baseline_store: ResponseBaselineStore):
        self.baseline_store = baseline_store

    def evaluate(
        self,
        url: str,
        candidate_body: str,
        candidate_headers: Dict[str, str],
        candidate_status: Optional[int],
        negative_control: Optional[NegativeControlResult] = None,
        additional_markers: Optional[List[str]] = None,
    ) -> ResponseValidationResult:
        contains_sensitive = _has_sensitive_markers(candidate_body, additional=additional_markers) or looks_like_api_json(
            candidate_body, candidate_headers
        )
        baseline_hit = self.baseline_store.find_similar(candidate_body)
        reasoning_parts: List[str] = []
        classification = ResponseClassification.POTENTIAL_AUTH_WEAKNESS
        if baseline_hit:
            label, score = baseline_hit
            reasoning_parts.append(f"Matches baseline '{label}' ({score:.2%} similar)")
            classification = ResponseClassification.MISCONFIGURATION_OR_FALLBACK
            return ResponseValidationResult(
                classification=classification,
                reasoning="; ".join(reasoning_parts),
                similarity_to_baseline=score,
                baseline_label=label,
                contains_sensitive_data=False,
                negative_control_matched=False,
            )

        if negative_control:
            if negative_control.similarity is not None and negative_control.similarity > 0.9:
                reasoning_parts.append("Negative control returned same body as candidate")
                classification = ResponseClassification.NEGATIVE_CONTROL_MATCH
                return ResponseValidationResult(
                    classification=classification,
                    reasoning="; ".join(reasoning_parts),
                    contains_sensitive_data=False,
                    negative_control_matched=True,
                )
            if negative_control.status_code == candidate_status and is_same_page(
                candidate_body, negative_control.body
            ):
                reasoning_parts.append("Negative control content matches candidate")
                classification = ResponseClassification.NEGATIVE_CONTROL_MATCH
                return ResponseValidationResult(
                    classification=classification,
                    reasoning="; ".join(reasoning_parts),
                    contains_sensitive_data=False,
                    negative_control_matched=True,
                )

        if not contains_sensitive:
            reasoning_parts.append("No sensitive markers or data payload detected")
            classification = ResponseClassification.NO_EVIDENCE
            return ResponseValidationResult(
                classification=classification,
                reasoning="; ".join(reasoning_parts) or "Fallback response detected",
                contains_sensitive_data=False,
                negative_control_matched=False,
            )

        if contains_sensitive and candidate_status and candidate_status < 400:
            reasoning_parts.append("Sensitive indicators present with successful status")
            classification = ResponseClassification.CONFIRMED_AUTH_BYPASS
        else:
            reasoning_parts.append("Sensitive markers present but response uncertain")
        return ResponseValidationResult(
            classification=classification,
            reasoning="; ".join(reasoning_parts),
            contains_sensitive_data=contains_sensitive,
            negative_control_matched=False,
        )


# ----------------------------------------------------------------------
# Fetch helpers + bootstrap
# ----------------------------------------------------------------------


def _parse_headers(text: Optional[str]) -> Dict[str, str]:
    if not text:
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def fetch_response(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    timeout: int = 20,
) -> Tuple[Optional[int], Dict[str, str], str]:
    headers = headers or {}
    try:
        resp = requests.request(method.upper(), url, headers=headers, data=data, timeout=timeout, verify=False)
        text = resp.text or ""
        return resp.status_code, dict(resp.headers or {}), text
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None, {}, f"Request to {url} failed: {exc}"


def _random_path_suffix(length: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def build_negative_control_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path + "/"
    path = path + _random_path_suffix()
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))


def bootstrap_default_baselines(target: str, operation_id: str, provider: str = "bedrock") -> None:
    """Record default baseline for target home page."""
    try:
        store = ResponseBaselineStore(target, operation_id, provider=provider)
    except Exception as exc:  # pragma: no cover - safety
        logger.debug("Unable to init baseline store: %s", exc)
        return
    if store.list_baselines():
        return
    status, headers, body = fetch_response(target)
    if status is None:
        return
    label = "home"
    store.record(label, target, body, headers)
    logger.info("Seeded baseline '%s' for %s", label, target)


def parse_headers_input(text: Optional[str]) -> Dict[str, str]:
    return _parse_headers(text)


def store_response_artifact(store: ResponseBaselineStore, label: str, body: str) -> Optional[str]:
    try:
        return store.persist_response(label, body)
    except Exception as exc:  # pragma: no cover
        logger.debug("Unable to store validation artifact: %s", exc)
        return None
