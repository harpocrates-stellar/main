import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { LineageNode, LineageGraph, VirtualizationConfig } from '../types/lineage';
import { VirtualizedList } from '../lib/virtualized-list';

interface LineageGraphProps {
  graph: LineageGraph;
  config?: Partial<VirtualizationConfig>;
  onNodeClick?: (nodeId: string) => void;
  className?: string;
}

const DEFAULT_CONFIG: VirtualizationConfig = {
  containerHeight: 600,
  itemHeight: 60,
  overscanCount: 5,
  threshold: 100
};

export const LineageGraph: React.FC<LineageGraphProps> = ({
  graph,
  config: userConfig,
  onNodeClick,
  className
}) => {
  const config = { ...DEFAULT_CONFIG, ...userConfig };
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [nodes, setNodes] = useState<LineageNode[]>([]);
  const [layout, setLayout] = useState<Record<string, { x: number; y: number; width: number; height: number }>>({});

  // Initialize nodes from graph
  useEffect(() => {
    try {
      // Validate graph integrity
      if (!graph.rootId || !graph.nodes) {
        setError('Invalid lineage graph structure');
        return;
      }

      // Convert Map to array for rendering
      const nodeArray: LineageNode[] = Array.from(graph.nodes.values());
      
      // Filter out malformed or unsupported nodes for UI
      const validNodes = nodeArray.filter(node => 
        node.status === 'active' || node.status === 'expired'
      );

      setNodes(validNodes);
      setError(null);
    } catch (err) {
      setError('Failed to load lineage graph');
    }
  }, [graph]);

  // Create virtualized list
  const virtualizedList = new VirtualizedList(config, nodes);

  // Handle scroll
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const target = e.currentTarget;
    setScrollTop(target.scrollTop);
  }, []);

  // Handle node click
  const handleNodeClick = useCallback((nodeId: string) => {
    if (onNodeClick) {
      onNodeClick(nodeId);
    }
  }, [onNodeClick]);

  // Render node component
  const renderNode = useCallback((node: LineageNode) => {
    const isExpired = node.status === 'expired';
    const isRevoked = node.status === 'revoked';
    const isMalformed = node.status === 'malformed';
    
    return (
      <div
        key={node.id}
        className={`lineage-node ${isExpired ? 'expired' : ''} ${isRevoked ? 'revoked' : ''} ${isMalformed ? 'malformed' : ''}`}
        onClick={() => handleNodeClick(node.id)}
        role="button"
        tabIndex={0}
        aria-label={`Lineage node: ${node.label}`}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleNodeClick(node.id);
          }
        }}
      >
        <div className="lineage-node-label">{node.label}</div>
        <div className="lineage-node-type">{node.type}</div>
        {node.hash && (
          <div className="lineage-node-hash" title={node.hash}>
            {node.hash.substring(0, 8)}...
          </div>
        )}
        {isExpired && <span className="badge expired">Expired</span>}
        {isRevoked && <span className="badge revoked">Revoked</span>}
        {isMalformed && <span className="badge malformed">Malformed</span>}
      </div>
    );
  }, [handleNodeClick]);

  // Render visible nodes
  const visibleItems = virtualizedList.visibleItems;
  const offsetY = virtualizedList.offsetY;

  if (error) {
    return (
      <div className="lineage-graph-error" role="alert">
        <p>Error loading lineage graph: {error}</p>
        <p>Note: No sensitive data has been exposed.</p>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`lineage-graph-container ${className || ''}`}
      style={{ height: config.containerHeight, overflow: 'auto' }}
      onScroll={handleScroll}
      role="tree"
      aria-label="Lineage graph"
    >
      <div
        style={{
          height: virtualizedList.totalHeight,
          position: 'relative'
        }}
      >
        <div style={{ transform: `translateY(${offsetY}px)` }}>
          {visibleItems.map(node => renderNode(node))}
        </div>
      </div>
      {virtualizedList.shouldVirtualize && (
        <div className="virtualization-indicator">
          Showing {visibleItems.length} of {nodes.length} nodes
        </div>
      )}
    </div>
  );
};

export default LineageGraph;