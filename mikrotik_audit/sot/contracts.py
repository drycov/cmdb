from __future__ import annotations

from typing import Protocol

from .domain import NetworkSnapshot, Recommendation, RemediationPlan, Risk
from .pipeline import PipelineContext, StageResult


class CollectorPlugin(Protocol):
    name: str

    async def collect(self, context: PipelineContext) -> StageResult: ...


class NormalizerPlugin(Protocol):
    name: str

    async def normalize(self, context: PipelineContext) -> StageResult: ...


class CorrelationPlugin(Protocol):
    name: str
    requires: tuple[str, ...]

    async def correlate(self, snapshot: NetworkSnapshot, context: PipelineContext) -> StageResult: ...


class TopologyStage(Protocol):
    name: str

    async def build_graph(self, snapshot: NetworkSnapshot, context: PipelineContext) -> StageResult: ...


class RiskRule(Protocol):
    rule_id: str

    async def evaluate(self, snapshot: NetworkSnapshot, context: PipelineContext) -> list[Risk]: ...


class RecommendationRule(Protocol):
    rule_id: str

    async def build(self, snapshot: NetworkSnapshot, risks: list[Risk], context: PipelineContext) -> list[Recommendation]: ...


class RemediationPlanner(Protocol):
    planner_id: str

    async def plan(
        self,
        snapshot: NetworkSnapshot,
        risks: list[Risk],
        recommendations: list[Recommendation],
        context: PipelineContext,
    ) -> RemediationPlan: ...
