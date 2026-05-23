/**
 * Frontend module for api snapshots.
 */
import { apiGet, apiPost } from "./client";
import type {
  BroadcastDomainResponse,
  CommandDefinitionResponse,
  CommandJobRequest,
  CommandJobResponse,
  DeviceSummaryResponse,
  InventoryEntryResponse,
  SnapshotJobResponse,
  SnapshotSummaryResponse,
  TopologyGraphResponse,
} from "../types/api";

export async function healthCheck(): Promise<{ status: string }> {
  return apiGet("/api/v1/health");
}

export async function createSnapshot(payload: { scope?: string; ips?: string[] }): Promise<SnapshotJobResponse> {
  return apiPost("/api/v1/snapshots", payload);
}

export async function listSnapshots(): Promise<{ items: SnapshotSummaryResponse[] }> {
  return apiGet("/api/v1/snapshots");
}

export async function listDevices(snapshotId: string): Promise<{ items: DeviceSummaryResponse[] }> {
  return apiGet(`/api/v1/devices?snapshot_id=${encodeURIComponent(snapshotId)}`);
}

export async function listInventory(): Promise<{ items: InventoryEntryResponse[] }> {
  return apiGet("/api/v1/inventory");
}

export async function getTopologyGraph(snapshotId: string): Promise<TopologyGraphResponse> {
  return apiGet(`/api/v1/topology/graph?snapshot_id=${encodeURIComponent(snapshotId)}`);
}

export async function listBroadcastDomains(snapshotId: string): Promise<{ items: BroadcastDomainResponse[] }> {
  return apiGet(`/api/v1/l2/broadcast-domains?snapshot_id=${encodeURIComponent(snapshotId)}`);
}

export async function listCliCommands(): Promise<{ items: CommandDefinitionResponse[] }> {
  return apiGet("/api/v1/cli/commands");
}

export async function createCliJob(payload: CommandJobRequest): Promise<CommandJobResponse> {
  return apiPost("/api/v1/cli/jobs", payload);
}

export async function listCliJobs(): Promise<{ items: CommandJobResponse[] }> {
  return apiGet("/api/v1/cli/jobs");
}

export async function getCliJob(jobId: string): Promise<CommandJobResponse> {
  return apiGet(`/api/v1/cli/jobs/${encodeURIComponent(jobId)}`);
}
/**
 * API helpers and shared request utilities for snapshot-oriented screens.
 */
