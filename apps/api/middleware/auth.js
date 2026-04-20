// ============================================================
//  Vibesecur — middleware/auth.js
// ============================================================
import jwt from 'jsonwebtoken';

export const requireAuth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  try {
    const token   = header.slice(7);
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: payload.user_id, plan: payload.plan };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, error: 'Session expired — please log in again' });
    }
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

export const optionalAuth = (req, _res, next) => {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET);
      req.user = { id: payload.user_id, plan: payload.plan };
    } catch {}
  }
  next();
};
