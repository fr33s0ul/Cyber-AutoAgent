"""Offline vulnerability knowledge base tools."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

from strands import tool

logger = logging.getLogger(__name__)

KB_PATH = Path("docs/knowledge_base/offline_kb.yaml")


@lru_cache(maxsize=1)
def _load_kb() -> Dict[str, Dict[str, List[str]]]:
    if not KB_PATH.exists():
        logger.warning("Knowledge base file missing: %s", KB_PATH)
        return {}
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(KB_PATH.read_text()) or {}
        return payload.get("bug_classes", {}) if isinstance(payload, dict) else {}
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to load knowledge base: %s", exc)
        return {}


def _match_classes(query: str, bug_class: str | None = None) -> Dict[str, Dict[str, List[str]]]:
    kb = _load_kb()
    if not kb:
        return {}
    if bug_class:
        entry = kb.get(bug_class) or kb.get(bug_class.lower())
        return {bug_class: entry} if entry else {}
    if not query:
        return kb
    q = query.lower()
    results = {}
    for name, entry in kb.items():
        blob = json.dumps(entry).lower()
        if q in blob or q in name.lower():
            results[name] = entry
    return results


def _format_entry(name: str, entry: Dict[str, List[str]]) -> str:
    lines = [f"### {name}"]
    if entry.get("description"):
        lines.append(entry["description"])
    for key in ("cves", "ttps", "payloads", "validation"):
        values = entry.get(key) or []
        if values:
            lines.append(f"- **{key}:**")
            for item in values:
                lines.append(f"  - {item}")
    return "\n".join(lines)


@tool
def knowledge_base_lookup(query: str = "", bug_class: str | None = None, limit: int = 3) -> str:
    """Return targeted entries from the offline vulnerability knowledge base."""

    results = _match_classes(query, bug_class)
    if not results:
        return "No knowledge base entries matched"
    snippets = []
    for name, entry in list(results.items())[: max(1, limit)]:
        snippets.append(_format_entry(name, entry))
    return "\n\n".join(snippets)


@tool
def list_high_impact_patterns(limit: int = 5) -> str:
    """List high-impact bug classes and their top payload heuristics."""

    kb = _load_kb()
    if not kb:
        return "Knowledge base unavailable"
    snippets: List[str] = []
    for name in ("auth_bypass", "sqli", "rce", "ssrf", "zero_day"):
        entry = kb.get(name)
        if not entry:
            continue
        payloads = entry.get("payloads", [])[:limit]
        ttps = entry.get("ttps", [])[:limit]
        snippet = [f"### {name}"]
        if payloads:
            snippet.append("Payloads:")
            snippet.extend(f"- {p}" for p in payloads)
        if ttps:
            snippet.append("TTPs:")
            snippet.extend(f"- {t}" for t in ttps)
        snippets.append("\n".join(snippet))
    return "\n\n".join(snippets)

