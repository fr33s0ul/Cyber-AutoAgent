"""Adaptive exploit chaining helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

from strands import tool


@dataclass
class ChainStep:
    goal: str
    action: str
    success_signal: str
    failure_pivot: str


@dataclass
class AdaptiveChainPlan:
    trigger: str
    steps: List[ChainStep] = field(default_factory=list)

    def describe(self) -> str:
        lines = [f"Trigger: {self.trigger}"]
        for idx, step in enumerate(self.steps, start=1):
            lines.append(
                f"{idx}. Goal: {step.goal} | Action: {step.action} | Success: {step.success_signal} | Pivot: {step.failure_pivot}"
            )
        return "\n".join(lines)


class AdaptiveChainPlanner:
    """Build exploitation chains from reconnaissance signals."""

    def build_chain(self, indicator: str, novel_patterns: Sequence[str] | None = None) -> AdaptiveChainPlan:
        patterns = [p.lower() for p in (novel_patterns or [])]
        steps: List[ChainStep] = []

        if "admin" in indicator or "console" in indicator:
            steps.extend(
                [
                    ChainStep(
                        goal="Validate unauthenticated access",
                        action="response_validation_tool(action='compare', tag='baseline_admin')",
                        success_signal="Content diverges from baseline",
                        failure_pivot="Capture auth workflow via http_request",
                    ),
                    ChainStep(
                        goal="Extract privileged action",
                        action="confirm_finding_tool(kind='auth', request='/admin')",
                        success_signal="Admin-only data retrieved",
                        failure_pivot="Attempt IDOR on admin APIs",
                    ),
                    ChainStep(
                        goal="Select credentialed payload",
                        action="knowledge_base_lookup(bug_class='auth_bypass')",
                        success_signal="Payload references known auth bypass TTP",
                        failure_pivot="List high impact patterns and try SSRF",
                    ),
                ]
            )

        if any(p for p in patterns if "debug" in p or "stack" in p):
            steps.append(
                ChainStep(
                    goal="Leverage debug surface",
                    action="python_repl craft payload to toggle debug endpoint",
                    success_signal="Debug variable dump obtained",
                    failure_pivot="Use SSRF to reach internal debug endpoints",
                )
            )

        if "stack" in indicator or "stack" in patterns:
            steps.append(
                ChainStep(
                    goal="Convert stack trace to exploit",
                    action="knowledge_base_lookup(query='deserialization')",
                    success_signal="Payload referencing specific stack frame",
                    failure_pivot="Switch to fuzzing template injection",
                )
            )

        if not steps:
            steps.append(
                ChainStep(
                    goal="Escalate reconnaissance",
                    action="list_high_impact_patterns()",
                    success_signal="New payload candidate identified",
                    failure_pivot="Pivot to different bug class",
                )
            )

        return AdaptiveChainPlan(trigger=indicator, steps=steps)


@tool
def adaptive_chain_plan(indicator: str, novel_patterns: List[str] | None = None) -> str:
    """Return an exploitation chain plan for a given indicator."""

    planner = AdaptiveChainPlanner()
    plan = planner.build_chain(indicator, novel_patterns=novel_patterns)
    return plan.describe()

