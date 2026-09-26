type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: Record<string, unknown>;
}

export class ProofWorkerLogger {
  private logs: LogEntry[] = [];
  private maxLogs: number;
  private enabled: boolean;

  constructor(options?: { maxLogs?: number; enabled?: boolean }) {
    this.maxLogs = options?.maxLogs ?? 100;
    this.enabled = options?.enabled ?? true;
  }

  log(level: LogLevel, message: string, context?: Record<string, unknown>): void {
    if (!this.enabled) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
    };

    this.logs.push(entry);

    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }

    if (level === 'error') {
      console.error(`[ProofWorker] ${message}`, context || '');
    } else if (level === 'warn') {
      console.warn(`[ProofWorker] ${message}`, context || '');
    } else if (level === 'info') {
      console.info(`[ProofWorker] ${message}`, context || '');
    } else {
      console.debug(`[ProofWorker] ${message}`, context || '');
    }
  }

  info(message: string, context?: Record<string, unknown>): void {
    this.log('info', message, context);
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.log('warn', message, context);
  }

  error(message: string, context?: Record<string, unknown>): void {
    this.log('error', message, context);
  }

  debug(message: string, context?: Record<string, unknown>): void {
    this.log('debug', message, context);
  }

  getLogs(): LogEntry[] {
    return [...this.logs];
  }

  clear(): void {
    this.logs = [];
  }
}