"""Implementation details for sot contracts."""

from __future__ import annotations

from typing import Protocol

from .domain import NetworkSnapshot, Recommendation, RemediationPlan, Risk
from .pipeline import PipelineContext, StageResult


class CollectorPlugin(Protocol):
    """Represent collectorplugin."""
    name: str

    async def collect(self, context: PipelineContext) -> StageResult: ...


class NormalizerPlugin(Protocol):
    """Represent normalizerplugin."""
    name: str

    async def normalize(self, context: PipelineContext) -> StageResult: ...


class CorrelationPlugin(Protocol):
    """Represent correlationplugin."""
    name: str
    requires: tuple[str, ...]

    async def correlate(self, snapshot: NetworkSnapshot, context: PipelineContext) -> StageResult: ...


class TopologyStage(Protocol):
    """Represent topologystage."""
    name: str

    async def build_graph(self, snapshot: NetworkSnapshot, context: PipelineContext) -> StageResult: ...


class RiskRule(Protocol):
    """Represent riskrule."""
    rule_id: str

    async def evaluate(self, snapshot: NetworkSnapshot, context: PipelineContext) -> list[Risk]: ...


class RecommendationRule(Protocol):
    """Represent recommendationrule."""
    rule_id: str

    async def build(self, snapshot: NetworkSnapshot, risks: list[Risk], context: PipelineContext) -> list[Recommendation]: ...


class RemediationPlanner(Protocol):
    """Represent remediationplanner."""
    planner_id: str

    async def plan(
        self,
        snapshot: NetworkSnapshot,
        risks: list[Risk],
        recommendations: list[Recommendation],
        context: PipelineContext,
    ) -> RemediationPlan: ...
