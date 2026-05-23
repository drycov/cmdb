/**
 * Frontend module for types network.
 */
export interface Device {
  id: string;
  identity: string;
  hostname: string;
  model?: string;
  boardName?: string;
  serial?: string;
  rosVersion?: string;
  switchChip?: string;
  architecture?: string;
  license?: string;
  uptimeSeconds?: number;
  managementIp?: string;
}

export interface Interface {
  id: string;
  deviceId: string;
  name: string;
  type: string;
  status: "up" | "down" | "disabled";
  role?: string;
  speedMbps?: number;
  pvid?: number;
  taggedVlans?: number[];
  untaggedVlans?: number[];
  comment?: string;
}
/**
 * Frontend-specific network and graph view models.
 */
