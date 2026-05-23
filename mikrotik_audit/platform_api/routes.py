"""FastAPI route layer for auth, CLI jobs, and snapshot exploration.

These handlers intentionally stay lightweight: they translate HTTP requests
into service calls, shape response DTOs, and keep orchestration logic out of
the web layer so the same domain workflows remain reusable elsewhere.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from mikrotik_audit.config import (
    AppConfig,
    as_dict,
    as_list,
    load_yaml_file,
    normalize_inventory_data,
)

from .auth import (
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    authenticate_credentials,
    create_access_token,
    create_refresh_token,
    get_current_user,
    verify_refresh_token,
)
from .command_runner import CommandRunner
from .repositories import SqlAlchemySnapshotRepository
from .schemas import (
    BroadcastDomainResponse,
    CommandDefinitionResponse,
    CommandJobRequest,
    CommandJobResponse,
    DeviceDetailResponse,
    DeviceSummaryResponse,
    InventoryEntryResponse,
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
    """Provide one SQLAlchemy async session per request scope."""
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session


def get_command_runner(request: Request) -> CommandRunner:
    """Return the application-level CLI command runner stored on app state."""
    return request.app.state.command_runner


def get_snapshot_service(session: AsyncSession = Depends(get_session)) -> SnapshotService:
    """Assemble the snapshot service with request-scoped repositories."""
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


def _inventory_entries() -> list[InventoryEntryResponse]:
    """Build API inventory DTOs from the normalized YAML inventory file."""
    config = AppConfig.from_env()
    inventory = normalize_inventory_data(load_yaml_file(config.inventory_file))
    items: list[InventoryEntryResponse] = []

    vlan_index: dict[tuple[str, str], dict] = {}
    for entry in as_list(inventory.get("vlans")):
        vlan = as_dict(entry)
        key = (
            str(vlan.get("inventory_type", "") or "").strip(),
            str(vlan.get("inventory_group", "") or "").strip(),
        )
        if key != ("", ""):
            vlan_index[key] = vlan

    for entry in as_list(inventory.get("target_networks")):
        network_item = as_dict(entry)
        subnet = str(network_item.get("subnet", "") or "").strip()
        if not subnet:
            continue

        inventory_type = str(network_item.get("inventory_type", "") or "").strip()
        inventory_group = str(network_item.get("inventory_group", "") or "").strip()
        vlan = vlan_index.get((inventory_type, inventory_group), {})
        ospf = as_dict(vlan.get("ospf"))
        ignored_from_vlan = [str(item).strip() for item in as_list(vlan.get("ignored_ips")) if str(item).strip()]
        network_ignored = [
            str(item).strip()
            for item in as_list(network_item.get("ignored_ips"))
            if str(item).strip()
        ]
        items.append(
            InventoryEntryResponse(
                inventory_type=inventory_type,
                inventory_group=inventory_group,
                vlan_id=vlan.get("id"),
                vlan_name=str(vlan.get("name", "") or "").strip() or None,
                subnet=subnet,
                gateway=str(network_item.get("gateway", "") or "").strip() or None,
                ignored_ips=network_ignored or ignored_from_vlan,
                ospf_instance=str(ospf.get("instance", "") or "").strip() or None,
                ospf_area=str(ospf.get("area", "") or "").strip() or None,
            )
        )

    return items


@router.get("/health", tags=["system"])
async def healthcheck() -> dict[str, str]:
    """Expose a minimal liveness probe for deployments and reverse proxies."""
    return {"status": "ok"}


@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(payload: LoginRequest, request: Request) -> TokenResponse:
    """Authenticate a user and mint a fresh access and refresh token pair."""
    username = authenticate_credentials(request, payload.username, payload.password)
    access_token = create_access_token(username, request)
    refresh_token = create_refresh_token(username, request)
    request.app.state.refresh_tokens.add(refresh_token)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/auth/refresh", response_model=TokenResponse, tags=["auth"])
async def refresh_tokens(payload: RefreshRequest, request: Request) -> TokenResponse:
    """Rotate a refresh token and issue a new access token pair."""
    username = verify_refresh_token(request, payload.refresh_token)
    request.app.state.refresh_tokens.discard(payload.refresh_token)
    access_token = create_access_token(username, request)
    refresh_token = create_refresh_token(username, request)
    request.app.state.refresh_tokens.add(refresh_token)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.get("/auth/me", tags=["auth"])
async def get_me(current_user: str = Depends(get_current_user)) -> dict[str, str]:
    """Return the username represented by the current bearer token."""
    return {"username": current_user}


@router.get("/cli/commands", response_model=dict[str, list[CommandDefinitionResponse]], tags=["cli"])
async def list_cli_commands(
    runner: CommandRunner = Depends(get_command_runner),
) -> dict[str, list[CommandDefinitionResponse]]:
    """Describe the CLI-style jobs that can be launched through the API."""
    return {
        "items": [
            CommandDefinitionResponse(
                name=item.name,
                title=item.title,
                description=item.description,
                requires_ip=item.requires_ip,
                supports_ip=item.supports_ip,
                supports_export=item.supports_export,
                supports_progress=item.supports_progress,
                supports_apply=item.supports_apply,
                supports_domains=item.supports_domains,
            )
            for item in runner.list_commands()
        ]
    }


@router.post("/cli/jobs", response_model=CommandJobResponse, status_code=202, tags=["cli"])
async def create_cli_job(
    payload: CommandJobRequest,
    runner: CommandRunner = Depends(get_command_runner),
) -> CommandJobResponse:
    """Submit a background CLI job and return its initial tracking state."""
    job = await runner.submit(payload.command, payload.model_dump())
    return CommandJobResponse(
        job_id=job.job_id,
        command=job.command,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        summary=job.summary,
        output=job.output,
        artifacts=job.artifacts,
        error=job.error,
        parameters=job.parameters,
    )


@router.get("/cli/jobs", response_model=dict[str, list[CommandJobResponse]], tags=["cli"])
async def list_cli_jobs(
    runner: CommandRunner = Depends(get_command_runner),
) -> dict[str, list[CommandJobResponse]]:
    """List previously submitted CLI jobs for polling-style clients."""
    jobs = await runner.list_jobs()
    return {
        "items": [
            CommandJobResponse(
                job_id=job.job_id,
                command=job.command,
                status=job.status,
                created_at=job.created_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
                summary=job.summary,
                output=job.output,
                artifacts=job.artifacts,
                error=job.error,
                parameters=job.parameters,
            )
            for job in jobs
        ]
    }


@router.get("/cli/jobs/{job_id}", response_model=CommandJobResponse, tags=["cli"])
async def get_cli_job(
    job_id: str,
    runner: CommandRunner = Depends(get_command_runner),
) -> CommandJobResponse:
    """Fetch one CLI job by id or raise a 404 when it does not exist."""
    from uuid import UUID

    job = await runner.get_job(UUID(job_id))
    if job is None:
        raise HTTPException(status_code=404, detail="CLI job not found")
    return CommandJobResponse(
        job_id=job.job_id,
        command=job.command,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        summary=job.summary,
        output=job.output,
        artifacts=job.artifacts,
        error=job.error,
        parameters=job.parameters,
    )


@router.post("/snapshots", response_model=SnapshotJobResponse, status_code=202)
async def create_snapshot(
    payload: SnapshotCreateRequest,
    service: SnapshotService = Depends(get_snapshot_service),
) -> SnapshotJobResponse:
    """Start snapshot creation and return the initial snapshot job state."""
    snapshot = await service.create_snapshot(payload)
    return SnapshotJobResponse(snapshot_id=snapshot.metadata.snapshot_id, status=snapshot.metadata.status)


@router.get("/snapshots", response_model=dict[str, list[SnapshotSummaryResponse]])
async def list_snapshots(
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[SnapshotSummaryResponse]]:
    """List available snapshots with lightweight aggregate counts."""
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
    """Return detailed metadata for one snapshot."""
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
    """List device summaries that belong to a snapshot."""
    return {"items": await service.list_devices(snapshot_id)}


@router.get("/inventory", response_model=dict[str, list[InventoryEntryResponse]], tags=["inventory"])
async def list_inventory() -> dict[str, list[InventoryEntryResponse]]:
    """Expose normalized inventory entries directly from the source YAML."""
    return {"items": _inventory_entries()}


@router.get("/devices/{device_id}", response_model=DeviceDetailResponse)
async def get_device_detail(
    device_id: str,
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> DeviceDetailResponse:
    """Return the detailed device view for one snapshot-scoped device id."""
    device = await service.get_device_detail(snapshot_id, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/topology/graph", response_model=TopologyGraphResponse, tags=["topology"])
async def get_topology_graph(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> TopologyGraphResponse:
    """Return the graph representation of the snapshot topology."""
    return await service.get_topology_graph(snapshot_id)


@router.get("/risks", response_model=dict[str, list[RiskResponse]], tags=["intelligence"])
async def list_risks(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[RiskResponse]]:
    """List inferred risks associated with a snapshot."""
    return {"items": await service.list_risks(snapshot_id)}


@router.get("/evidence/raw", response_model=dict[str, list[RawEvidenceResponse]], tags=["evidence"])
async def list_raw_evidence(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[RawEvidenceResponse]]:
    """List stored raw evidence records for a snapshot."""
    return {"items": await service.list_raw_evidence(snapshot_id)}


@router.get("/recommendations", response_model=dict[str, list[RecommendationResponse]], tags=["intelligence"])
async def list_recommendations(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[RecommendationResponse]]:
    """List recommendations derived from snapshot intelligence."""
    return {"items": await service.list_recommendations(snapshot_id)}


@router.post("/remediations/plan", response_model=RemediationPlanResponse, tags=["automation"])
async def create_remediation_plan(
    payload: RemediationPlanRequest,
    service: SnapshotService = Depends(get_snapshot_service),
) -> RemediationPlanResponse:
    """Generate a remediation plan from snapshot findings and user intent."""
    return await service.create_remediation_plan(payload)


@router.get("/l2/broadcast-domains", response_model=dict[str, list[BroadcastDomainResponse]], tags=["l2"])
async def list_broadcast_domains(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[BroadcastDomainResponse]]:
    """List broadcast-domain objects derived from the snapshot L2 view."""
    return {"items": await service.list_broadcast_domains(snapshot_id)}


@router.get("/l2/vlan-propagation", response_model=dict[str, list[VlanPropagationResponse]], tags=["l2"])
async def list_vlan_propagations(
    snapshot_id: str,
    service: SnapshotService = Depends(get_snapshot_service),
) -> dict[str, list[VlanPropagationResponse]]:
    """List inferred VLAN propagation paths for a snapshot."""
    return {"items": await service.list_vlan_propagations(snapshot_id)}
