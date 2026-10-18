export interface LineageNode {
  id: string;
  type: 'artifact' | 'proof' | 'contract' | 'deployment';
  label: string;
  metadata: Record<string, unknown>;
  // Privacy-preserving: sensitive fields are hashed or omitted in UI context
  hash?: string;
  timestamp: number;
  status: 'active' | 'expired' | 'revoked' | 'malformed' | 'unsupported';
  parentId?: string;
  childrenIds: string[];
}

export interface LineageGraph {
  nodes: Map<string, LineageNode>;
  edges: Array<{ from: string; to: string }>;
  rootId: string;
  version: string;
  integrityHash: string;
}

export interface VirtualizationConfig {
  containerHeight: number;
  itemHeight: number;
  overscanCount: number;
  threshold: number; // Max nodes before virtualization kicks in
}

export interface RenderRequest {
  nodeIds: string[];
  viewport: {
    start: number;
    end: number;
  };
}

export interface RenderResponse {
  nodes: LineageNode[];
  layout: Record<string, { x: number; y: number; width: number; height: number }>;
  error?: string;
}