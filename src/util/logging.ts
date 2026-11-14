/**
 * Minimal structured logger. Token values, secrets and codes are never logged.
 */
export interface Logger {
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

const SENSITIVE_KEY = /token|secret|password|code|proof|authorization|cookie/i;

function redact(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = SENSITIVE_KEY.test(key) ? '[redacted]' : value;
  }
  return out;
}

function emit(level: 'info' | 'warn' | 'error', message: string, fields?: Record<string, unknown>): void {
  const record = {
    ts: new Date().toISOString(),
    level,
    message,
    ...(fields ? redact(fields) : {}),
  };
  const line = JSON.stringify(record);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export const logger: Logger = {
  info: (message, fields) => emit('info', message, fields),
  warn: (message, fields) => emit('warn', message, fields),
  error: (message, fields) => emit('error', message, fields),
};

export function silentLogger(): Logger {
  return { info() {}, warn() {}, error() {} };
}

/** Collects records for assertions in tests. */
export function collectingLogger(): Logger & { records: Array<Record<string, unknown>> } {
  const records: Array<Record<string, unknown>> = [];
  const push = (level: string, message: string, fields?: Record<string, unknown>) => {
    records.push({ level, message, ...(fields ?? {}) });
  };
  return {
    records,
    info: (m, f) => push('info', m, f),
    warn: (m, f) => push('warn', m, f),
    error: (m, f) => push('error', m, f),
  };
}
