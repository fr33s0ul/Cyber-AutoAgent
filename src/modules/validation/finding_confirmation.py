"""Reusable confirmation workflow for high-impact findings."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.validation.response_validation import (
    AuthBypassValidator,
    NegativeControlResult,
    ResponseBaselineStore,
    ResponseClassification,
    build_negative_control_url,
    fetch_response,
    response_contains_sensitive_data,
    normalize_html,
    compute_similarity,
)

logger = logging.getLogger(__name__)


@dataclass
class ConfirmationResult:
    finding_type: str
    confirmed: bool
    classification: ResponseClassification
    reasoning: str
    evidence_paths: List[str] = field(default_factory=list)
    control_similarity: Optional[float] = None

    def to_json(self) -> str:
        payload = {
            "finding_type": self.finding_type,
            "confirmed": self.confirmed,
            "classification": self.classification.value,
            "reasoning": self.reasoning,
            "evidence_paths": self.evidence_paths,
            "control_similarity": self.control_similarity,
        }
        return json.dumps(payload, indent=2)


class FindingConfirmationEngine:
    """Centralized confirmation workflows."""

    def __init__(self, target: str, operation_id: str, provider: str) -> None:
        self.store = ResponseBaselineStore(target, operation_id, provider=provider)
        self.target = target
        self.operation_id = operation_id
        self.provider = provider

    # ------------------------------------------------------------------
    def confirm_auth_bypass(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> ConfirmationResult:
        headers = headers or {}
        status, resp_headers, text = fetch_response(url, method=method, headers=headers, data=body)
        if status is None:
            return ConfirmationResult(
                finding_type="auth_bypass",
                confirmed=False,
                classification=ResponseClassification.NO_EVIDENCE,
                reasoning=text,
            )
        gibberish_url = build_negative_control_url(url)
        neg_status, _, neg_body = fetch_response(gibberish_url, headers=headers, method=method)
        neg_result = None
        if neg_status is not None:
            neg_result = NegativeControlResult(
                url=gibberish_url,
                status_code=neg_status,
                body=neg_body,
                similarity=compute_similarity(normalize_html(text), normalize_html(neg_body)),
            )
        validator = AuthBypassValidator(self.store)
        result = validator.evaluate(
            url=url,
            candidate_body=text,
            candidate_headers=resp_headers,
            candidate_status=status,
            negative_control=neg_result,
        )
        confirmed = result.classification in {
            ResponseClassification.CONFIRMED_AUTH_BYPASS,
            ResponseClassification.CONFIRMED_IMPACT,
        }
        artifact = self.store.persist_response("auth_confirmation", text)
        return ConfirmationResult(
            finding_type="auth_bypass",
            confirmed=confirmed,
            classification=result.classification,
            reasoning=result.reasoning,
            evidence_paths=[artifact] if artifact else [],
            control_similarity=neg_result.similarity if neg_result else None,
        )

    # ------------------------------------------------------------------
    def confirm_idor(
        self,
        url: str,
        comparison_url: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        comparison_headers: Optional[Dict[str, str]] = None,
    ) -> ConfirmationResult:
        headers = headers or {}
        comparison_headers = comparison_headers or {}
        status, resp_headers, body = fetch_response(url, method=method, headers=headers)
        if status is None:
            return ConfirmationResult(
                finding_type="idor",
                confirmed=False,
                classification=ResponseClassification.NO_EVIDENCE,
                reasoning=body,
            )
        artifact = self.store.persist_response("idor_primary", body)
        comparison_reason = "Missing comparison request"
        similarity = None
        if comparison_url:
            c_status, _, c_body = fetch_response(comparison_url, method=method, headers=comparison_headers)
            if c_status is not None:
                from modules.validation.response_validation import normalize_html, compute_similarity

                similarity = compute_similarity(normalize_html(body), normalize_html(c_body))
                comparison_reason = (
                    f"Control returned status {c_status} with similarity {similarity:.2f}"
                )
                if c_status >= 400 and status < 400 and response_contains_sensitive_data(body, resp_headers):
                    return ConfirmationResult(
                        finding_type="idor",
                        confirmed=True,
                        classification=ResponseClassification.CONFIRMED_IMPACT,
                        reasoning="Protected resource accessible without rejection",
                        evidence_paths=[artifact] if artifact else [],
                        control_similarity=similarity,
                    )
                if similarity and similarity > 0.9 and status < 400 and response_contains_sensitive_data(body, resp_headers):
                    return ConfirmationResult(
                        finding_type="idor",
                        confirmed=True,
                        classification=ResponseClassification.CONFIRMED_IMPACT,
                        reasoning="Responses for distinct principals are nearly identical",
                        evidence_paths=[artifact] if artifact else [],
                        control_similarity=similarity,
                    )
            else:
                comparison_reason = "Control request failed"
        return ConfirmationResult(
            finding_type="idor",
            confirmed=False,
            classification=ResponseClassification.POTENTIAL_AUTH_WEAKNESS,
            reasoning=comparison_reason,
            evidence_paths=[artifact] if artifact else [],
            control_similarity=similarity,
        )

    # ------------------------------------------------------------------
    def confirm_from_artifact(self, finding_type: str, artifact_path: Optional[str]) -> ConfirmationResult:
        if not artifact_path:
            return ConfirmationResult(
                finding_type=finding_type,
                confirmed=False,
                classification=ResponseClassification.NO_EVIDENCE,
                reasoning="No artifact path provided",
            )
        path = Path(artifact_path)
        if not path.exists():
            return ConfirmationResult(
                finding_type=finding_type,
                confirmed=False,
                classification=ResponseClassification.NO_EVIDENCE,
                reasoning=f"Artifact {artifact_path} missing",
            )
        content = path.read_text(errors="ignore")
        keywords = ["is vulnerable", "exploitable", "command executed", "parameter is vulnerable"]
        matched = any(keyword.lower() in content.lower() for keyword in keywords)
        reasoning = "Evidence artifact indicates exploitation" if matched else "Artifact lacks exploit verdict"
        classification = (
            ResponseClassification.CONFIRMED_IMPACT if matched else ResponseClassification.POTENTIAL_AUTH_WEAKNESS
        )
        return ConfirmationResult(
            finding_type=finding_type,
            confirmed=matched,
            classification=classification,
            reasoning=reasoning,
            evidence_paths=[str(path)],
        )

    # ------------------------------------------------------------------
    def confirm(
        self,
        finding_type: str,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        comparison_url: Optional[str] = None,
        comparison_headers: Optional[Dict[str, str]] = None,
        artifact_path: Optional[str] = None,
    ) -> ConfirmationResult:
        ftype = finding_type.lower()
        if ftype in {"auth", "auth_bypass", "access_control"}:
            return self.confirm_auth_bypass(url, method=method, headers=headers, body=body)
        if ftype in {"idor", "business_logic"}:
            return self.confirm_idor(
                url,
                comparison_url=comparison_url,
                method=method,
                headers=headers,
                comparison_headers=comparison_headers,
            )
        if ftype in {"sqli", "sql_injection", "rce", "command_injection", "xss"}:
            return self.confirm_from_artifact(ftype, artifact_path)
        return ConfirmationResult(
            finding_type=finding_type,
            confirmed=False,
            classification=ResponseClassification.NO_EVIDENCE,
            reasoning="Unsupported confirmation type",
        )


def build_engine_from_env() -> FindingConfirmationEngine:
    target = os.getenv("CYBER_TARGET_NAME", os.getenv("CYBER_TARGET", ""))
    operation_id = os.getenv("CYBER_OPERATION_ID", "OP_LOCAL")
    provider = os.getenv("CYBER_AGENT_PROVIDER", "bedrock")
    return FindingConfirmationEngine(target, operation_id, provider)
