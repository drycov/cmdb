/**
 * Frontend module for types api.
 */
export interface SnapshotSummaryResponse {
  snapshot_id: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  device_count: number;
  risk_count: number;
  link_count: number;
}

export interface SnapshotJobResponse {
  snapshot_id: string;
  status: string;
  accepted_at: string;
}

export interface DeviceSummaryResponse {
  device_id: string;
  snapshot_id: string;
  identity: string;
  management_ip: string | null;
  role: string;
  vendor: string;
  model: string | null;
  board_name: string | null;
  ros_version: string | null;
  platform: string | null;
  architecture: string | null;
}

export interface InventoryEntryResponse {
  inventory_type: string;
  inventory_group: string;
  vlan_id: number | null;
  vlan_name: string | null;
  subnet: string;
  gateway: string | null;
  ignored_ips: string[];
  ospf_instance: string | null;
  ospf_area: string | null;
}

export interface TopologyGraphNodeResponse {
  device_id: string;
  identity: string;
  management_ip: string | null;
  role: string;
  vendor: string;
  model: string | null;
}

export interface TopologyGraphEdgeResponse {
  link_id: string;
  layer: string;
  source_device_id: string;
  source_interface: string;
  target_device_id: string | null;
  target_interface: string | null;
  relation: string;
  confidence: number;
}

export interface TopologyGraphResponse {
  snapshot_id: string;
  nodes: TopologyGraphNodeResponse[];
  edges: TopologyGraphEdgeResponse[];
}

export interface BroadcastDomainResponse {
  broadcast_domain_id: string;
  name: string;
  vlan_id: number | null;
  bridge_names: string[];
  device_ids: string[];
  interface_refs: string[];
  mac_count: number;
  risk_score: number;
}

export interface CommandDefinitionResponse {
  name: string;
  title: string;
  description: string;
  requires_ip: boolean;
  supports_ip: boolean;
  supports_export: boolean;
  supports_progress: boolean;
  supports_apply: boolean;
  supports_domains: boolean;
}

export interface CommandJobRequest {
  command:
    | "audit"
    | "export"
    | "phpipam-report"
    | "topology"
    | "generate-script"
    | "backup-configs"
    | "upload-firmware"
    | "ospf-create"
    | "remediate"
    | "radius-fix"
    | "scheduler-fix"
    | "targets";
  ip?: string | null;
  show_progress?: boolean;
  export_report?: boolean;
  apply_changes?: boolean;
  domains?: string[];
  limit?: number | null;
}

export interface CommandJobResponse {
  job_id: string;
  command: string;
  status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  summary: string;
  output: string[];
  artifacts: string[];
  error: string | null;
  parameters: Record<string, unknown>;
}
/**
 * Shared TypeScript models mirroring the backend API payloads.
 */
