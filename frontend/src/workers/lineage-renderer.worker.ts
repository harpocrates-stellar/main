import type { LineageNode, RenderRequest, RenderResponse } from '../types/lineage';

// Simple layout algorithm for lineage graphs
// In production, this would use a proper graph layout library
function computeLayout(nodes: LineageNode[]): Record<string, { x: number; y: number; width: number; height: number }> {
  const layout: Record<string, { x: number; y: number; width: number; height: number }> = {};
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  
  // Find roots
  const roots = nodes.filter(n => !n.parentId || !nodeMap.has(n.parentId));
  
  let yOffset = 0;
  const nodeWidth = 200;
  const nodeHeight = 60;
  const horizontalGap = 50;
  const verticalGap = 30;

  function layoutNode(nodeId: string, x: number, depth: number): void {
    const node = nodeMap.get(nodeId);
    if (!node) return;

    layout[nodeId] = {
      x,
      y: yOffset + depth * (nodeHeight + verticalGap),
      width: nodeWidth,
      height: nodeHeight
    };

    const children = nodes.filter(n => n.parentId === nodeId);
    children.forEach((child, index) => {
      layoutNode(child.id, x + index * (nodeWidth + horizontalGap), depth + 1);
    });
  }

  roots.forEach((root, index) => {
    layoutNode(root.id, index * (nodeWidth + horizontalGap), 0);
  });

  return layout;
}

self.onmessage = function(e: MessageEvent<RenderRequest>): void {
  try {
    const { nodeIds: _nodeIds, viewport: _viewport } = e.data;
    const response: RenderResponse = {
      nodes: [],
      layout: computeLayout([]),
      error: undefined
    };

    self.postMessage(response);
  } catch (error) {
    const response: RenderResponse = {
      nodes: [],
      layout: {},
      error: error instanceof Error ? error.message : 'Unknown error'
    };
    self.postMessage(response);
  }
};