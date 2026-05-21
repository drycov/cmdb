from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .repositories import SqlAlchemySnapshotRepository
from .schemas import (
    BroadcastDomainResponse,
    DeviceDetailResponse,
    DeviceSummaryResponse,
    RawEvidenceResponse,
    RecommendationResponse,
    RemediationPlanRequest,
    RemediationPlanResponse,
    RiskResponse,
    SnapshotCreateRequest,
    SnapshotDetailResponse,
    SnapshotJobResponse,
    SnapshotSummaryResponse,
    TopologyGraphResponse,
    VlanPropagationResponse,
)
from .service import SnapshotService

router = APIRouter(prefix="/api/v1", tags=["snapshots"])


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session


def get_snapshot_service(session: AsyncSession = Depends(get_session)) -> SnapshotService:
    from .repositories import (
        SqlAlchemyDeviceRepository,
        SqlAlchemyEvidenceRepository,
        SqlAlchemyL2Repository,
        SqlAlchemyRecommendationRepository,
        SqlAlchemyRemediationRepository,
        SqlAlchemyRiskRepository,
        SqlAlchemyTopologyRepository,
    )

    return SnapshotService(
        SqlAlchemySnapshotRepository(session),
        SqlAlchemyDeviceRepository(session),
        SqlAlchemyTopologyRepository(session),
        SqlAlchemyEvidenceRepository(session),
        SqlAlchemyL2Repository(session),
        SqlAlchemyRecommendationRepository(session),
        SqlAlchemyRemediationRepository(session),
        SqlAlchemyRiskRepository(session),
    )


@router.get("/health", tags=["system"])
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/snapshots", response_model=SnapshotJobResponse, status_code=202)
async def create_snapshot(
    payload: SnapshotCreateRequest,
    service: SnapshotService = Depends(get_snapshot_service),
) -> SnapshotJobResponse:
    snapshot = await service.create_snapshot(payload)
    return SnapshotJobResponse(snapshot_id=snapshot.metadata.snapshot_id, status=snapshot.metadata.status)


@router.get("/snapshots", response_model=dict[str, list[SnapshotSummaryResponse]])
async def list_snapshots(
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[SnapshotSummaryResponse]]:
    items = await service.list_snapshots()
    return {
        "items": [
            SnapshotSummaryResponse(
                snapshot_id=item.metadata.snapshot_id,
                started_at=item.metadata.started_at,
                completed_at=item.metadata.completed_at,
                status=item.metadata.status,
                device_count=len(item.devices),
                risk_count=len(item.risks),
                link_count=len(item.topology_links),
            )
            for item in items
        ]
    }


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotDetailResponse)
async def get_snapshot(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> SnapshotDetailResponse:
    snapshot = await service.get_snapshot(snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    metadata = snapshot.metadata
    return SnapshotDetailResponse(
        snapshot_id=metadata.snapshot_id,
        started_at=metadata.started_at,
        completed_at=metadata.completed_at,
        status=metadata.status,
        device_count=len(snapshot.devices),
        risk_count=len(snapshot.risks),
        link_count=len(snapshot.topology_links),
        scope=metadata.scope,
        collector_version=metadata.collector_version,
        parser_version=metadata.parser_version,
        tags=metadata.tags,
    )


@router.get("/devices", response_model=dict[str, list[DeviceSummaryResponse]])
async def list_devices(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[DeviceSummaryResponse]]:
    return {"items": await service.list_devices(snapshot_id)}


@router.get("/devices/{device_id}", response_model=DeviceDetailResponse)
async def get_device_detail(
    device_id: str,
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> DeviceDetailResponse:
    device = await service.get_device_detail(snapshot_id, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/topology/graph", response_model=TopologyGraphResponse, tags=["topology"])
async def get_topology_graph(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> TopologyGraphResponse:
    return await service.get_topology_graph(snapshot_id)


@router.get("/risks", response_model=dict[str, list[RiskResponse]], tags=["intelligence"])
async def list_risks(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[RiskResponse]]:
    return {"items": await service.list_risks(snapshot_id)}


@router.get("/evidence/raw", response_model=dict[str, list[RawEvidenceResponse]], tags=["evidence"])
async def list_raw_evidence(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[RawEvidenceResponse]]:
    return {"items": await service.list_raw_evidence(snapshot_id)}


@router.get("/recommendations", response_model=dict[str, list[RecommendationResponse]], tags=["intelligence"])
async def list_recommendations(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[RecommendationResponse]]:
    return {"items": await service.list_recommendations(snapshot_id)}


@router.post("/remediations/plan", response_model=RemediationPlanResponse, tags=["automation"])
async def create_remediation_plan(
    payload: RemediationPlanRequest,
    service: SnapshotService = Depends(get_snapshot_service),
) -> RemediationPlanResponse:
    return await service.create_remediation_plan(payload)


@router.get("/l2/broadcast-domains", response_model=dict[str, list[BroadcastDomainResponse]], tags=["l2"])
async def list_broadcast_domains(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[BroadcastDomainResponse]]:
    return {"items": await service.list_broadcast_domains(snapshot_id)}


@router.get("/l2/vlan-propagation", response_model=dict[str, list[VlanPropagationResponse]], tags=["l2"])
async def list_vlan_propagations(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[VlanPropagationResponse]]:
    return {"items": await service.list_vlan_propagations(snapshot_id)}
