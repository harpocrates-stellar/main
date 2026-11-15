export interface NoirClientLike {
  execute: (inputs: Record<string, unknown>) => Promise<unknown>;
}

export interface CircuitArtifacts {
  bytecode: string;
  abi: unknown;
}

export interface CircuitLoader {
  fetchCircuit: () => Promise<CircuitArtifacts>;
}

let circuitPromise: Promise<CircuitArtifacts> | null = null;

export async function fetchCircuit(url: string): Promise<CircuitArtifacts> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch circuit artifacts: ${response.status} ${response.statusText}`);
  }
  const bytecode = await response.text();
  const abi = await response.json().catch(() => null);
  return { bytecode, abi };
}

export async function getCircuitArtifacts(
  url: string,
  loader: CircuitLoader = { fetchCircuit: () => fetchCircuit(url) },
): Promise<CircuitArtifacts> {
  if (circuitPromise === null) {
    circuitPromise = loader.fetchCircuit().catch((error) => {
      circuitPromise = null;
      throw error;
    });
  }
  return circuitPromise;
}

export function resetCircuitCache(): void {
  circuitPromise = null;
}

export async function initializeSelectiveDisclosureClient(
  url: string,
  loader?: CircuitLoader,
): Promise<CircuitArtifacts> {
  return await getCircuitArtifacts(url, loader);
}
