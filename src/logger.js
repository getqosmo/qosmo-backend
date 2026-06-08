// Minimal timestamped logger. Keeps output readable when the engine runs
// unattended on a schedule.
const COLORS = {
  info: '\x1b[36m', // cyan
  warn: '\x1b[33m', // yellow
  error: '\x1b[31m', // red
  success: '\x1b[32m', // green
  reset: '\x1b[0m',
};

function stamp() {
  return new Date().toISOString();
}

function emit(level, label, args) {
  const color = COLORS[level] || '';
  const prefix = `${color}[${stamp()}] ${label}${COLORS.reset}`;
  const stream = level === 'error' || level === 'warn' ? console.error : console.log;
  stream(prefix, ...args);
}

export const logger = {
  info: (...args) => emit('info', 'INFO ', args),
  warn: (...args) => emit('warn', 'WARN ', args),
  error: (...args) => emit('error', 'ERROR', args),
  success: (...args) => emit('success', 'OK   ', args),
};
