// Layout worker for the LineageGraph. Computes node depths and x / y
// coordinates from the node graph so the main thread does not block.

export interface LineageWorkerNode {
  id: string;
  label: string;
  parentId?: string | null;
  children?: string[];
}

export interface LineageLayoutRequest {
  type: 'layout';
  nodes: LineageWorkerNode[];
  rowHeight?: number;
  columnWidth?: number;
}

export interface LayoutNode {
  id: string;
  label: string;
  parentId: string | null;
  children: string[];
  depth: number;
  x: number;
  y: number;
  index: number;
}

export interface LineageLayoutResponse {
  type: 'layout-result';
  nodes: LayoutNode[];
  width: number;
  height: number;
}

export function computeLayout(
  req: LineageLayoutRequest,
): LineageLayoutResponse {
  const rowHeight = req.rowHeight ?? 32;
  const columnWidth = req.columnWidth ?? 24;
  const byId = new Map<string, LineageWorkerNode>();
  for (const n of req.nodes) byId.set(n.id, n);

  const roots = req.nodes.filter(
    (n) => !n.parentId || !byId.has(n.parentId),
  );

  const out: LayoutNode[] = [];
  const visited = new Set<string>();
  let maxDepth = 0;

  const walk = (node: LineageWorkerNode, depth: number, parentId: string | null) => {
    if (visited.has(node.id)) return;
    visited.add(node.id);
    const children = (node.children ?? []).filter((id) => byId.has(id));
    const index = out.length;
    out.push({
      id: node.id,
      label: node.label,
      parentId,
      children,
      depth,
      x: (depth - 1) * columnWidth,
      y: index * rowHeight,
      index,
    });
    maxDepth = Math.max(maxDepth, depth);
    for (const childId of children) {
      const child = byId.get(childId);
      if (child) walk(child, depth + 1, node.id);
    }
  };

  for (const root of roots) walk(root, 1, null);
  for (const n of req.nodes) {
    if (!visited.has(n.id)) walk(n, 1, null);
  }

  return {
    type: 'layout-result',
    nodes: out,
    width: maxDepth * columnWidth,
    height: out.length * rowHeight,
  };
}

// Worker entrypoint. Only wire up when running in a Worker context.
if (typeof self !== 'undefined' && typeof (self as unknown as Worker).postMessage === 'function') {
  const workerScope = self as unknown as DedicatedWorkerGlobalScope;
  workerScope.addEventListener('message', (event: MessageEvent<LineageLayoutRequest>) => {
    const data = event.data;
    if (!data || data.type !== 'layout') return;
    const response = computeLayout(data);
    workerScope.postMessage(response);
  });
}
