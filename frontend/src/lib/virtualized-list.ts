import type { LineageNode, VirtualizationConfig } from '../types/lineage';

export class VirtualizedList {
  private config: VirtualizationConfig;
  private items: LineageNode[];
  private scrollTop: number = 0;
  private containerHeight: number;
  private itemHeight: number;
  private overscanCount: number;
  private threshold: number;

  constructor(config: VirtualizationConfig, items: LineageNode[]) {
    this.config = config;
    this.items = items;
    this.containerHeight = config.containerHeight;
    this.itemHeight = config.itemHeight;
    this.overscanCount = config.overscanCount;
    this.threshold = config.threshold;
  }

  get shouldVirtualize(): boolean {
    return this.items.length > this.threshold;
  }

  get totalHeight(): number {
    return this.items.length * this.itemHeight;
  }

  get startIndex(): number {
    if (!this.shouldVirtualize) return 0;
    return Math.max(0, Math.floor(this.scrollTop / this.itemHeight) - this.overscanCount);
  }

  get endIndex(): number {
    if (!this.shouldVirtualize) return this.items.length;
    const visibleCount = Math.ceil(this.containerHeight / this.itemHeight);
    return Math.min(
      this.items.length,
      Math.floor(this.scrollTop / this.itemHeight) + visibleCount + this.overscanCount
    );
  }

  get visibleItems(): LineageNode[] {
    if (!this.shouldVirtualize) return this.items;
    return this.items.slice(this.startIndex, this.endIndex);
  }

  get offsetY(): number {
    if (!this.shouldVirtualize) return 0;
    return this.startIndex * this.itemHeight;
  }

  updateScroll(scrollTop: number): void {
    this.scrollTop = scrollTop;
  }

  updateItems(items: LineageNode[]): void {
    this.items = items;
  }

  // Privacy-safe: never exposes full node data, only IDs for rendering
  getVisibleNodeIds(): string[] {
    return this.visibleItems.map(node => node.id);
  }
}