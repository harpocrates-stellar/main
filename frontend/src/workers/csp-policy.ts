import type { CSPPolicyConfig } from './proof.worker.types';

const DEFAULT_CONFIG: CSPPolicyConfig = {
  maxMemoryMB: 256,
  maxExecutionTimeMs: 30000,
  allowedOrigins: ['https://evidence-studio.example.com', 'https://verification.example.com'],
  sandbox: true,
};

export function validateCSPPolicy(config: Partial<CSPPolicyConfig>): CSPPolicyConfig {
  const merged = { ...DEFAULT_CONFIG, ...config };

  if (merged.maxMemoryMB <= 0 || merged.maxMemoryMB > 1024) {
    throw new Error('Invalid maxMemoryMB: must be between 1 and 1024');
  }

  if (merged.maxExecutionTimeMs <= 0 || merged.maxExecutionTimeMs > 300000) {
    throw new Error('Invalid maxExecutionTimeMs: must be between 1 and 300000');
  }

  if (!Array.isArray(merged.allowedOrigins)) {
    throw new Error('Invalid allowedOrigins: must be an array');
  }

  return merged;
}

export function isOriginAllowed(origin: string, config: CSPPolicyConfig): boolean {
  return config.allowedOrigins.includes(origin);
}

export function createCSPHeaders(config: CSPPolicyConfig): Record<string, string> {
  const headers: Record<string, string> = {};

  if (config.sandbox) {
    headers['Content-Security-Policy'] = [
      "default-src 'none'",
      "script-src 'self'",
      "worker-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'none'",
    ].join('; ');
  }

  headers['X-Content-Type-Options'] = 'nosniff';
  headers['X-Frame-Options'] = 'DENY';
  headers['X-XSS-Protection'] = '1; mode=block';

  return headers;
}