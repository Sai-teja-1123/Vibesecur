// ============================================================
//  Vibesecur — utils/logger.js
// ============================================================
import pino from 'pino';

export function createLogger(name) {
  return pino({
    name,
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    redact: {
      paths: ['password', 'passwordHash', 'key', 'token', 'authorization', 'email'],
      censor: '[REDACTED]',
    },
  });
}
