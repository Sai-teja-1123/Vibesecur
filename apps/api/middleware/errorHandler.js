// ============================================================
//  Vibesecur — middleware/errorHandler.js
// ============================================================
import { createLogger } from '../utils/logger.js';
const log = createLogger('error');

export const errorHandler = (err, req, res, _next) => {
  log.error({ err, path: req.path, method: req.method }, 'Unhandled error');

  // Never expose internal error details to client
  const isDev = process.env.NODE_ENV === 'development';

  if (err.code === '23505') { // Postgres unique violation
    return res.status(409).json({ success: false, error: 'Resource already exists' });
  }
  if (err.code === '23503') { // Postgres foreign key violation
    return res.status(400).json({ success: false, error: 'Invalid reference' });
  }

  res.status(500).json({
    success: false,
    error:   'Internal server error',
    ...(isDev && { detail: err.message }),
  });
};
