// ============================================================
//  Vibesecur — middleware/projectQuota.js
// ============================================================
import crypto from 'crypto';
import { query } from '../utils/db.js';

const PLAN_PROJECT_LIMITS = {
  free: parseInt(process.env.PROJECT_SCAN_QUOTA_FREE || '100', 10),
  solo: parseInt(process.env.PROJECT_SCAN_QUOTA_SOLO || '1000', 10),
  pro: parseInt(process.env.PROJECT_SCAN_QUOTA_PRO || '5000', 10),
  admin: -1,
};

const ANON_PROJECT_LIMIT = parseInt(process.env.PROJECT_SCAN_QUOTA_ANON || '25', 10);

const clampLimit = (value) => (Number.isFinite(value) && value >= 0 ? value : 0);

const getPlanLimit = (plan) => {
  if (plan && Object.prototype.hasOwnProperty.call(PLAN_PROJECT_LIMITS, plan)) {
    const configured = PLAN_PROJECT_LIMITS[plan];
    return configured < 0 ? null : clampLimit(configured);
  }
  return clampLimit(ANON_PROJECT_LIMIT);
};

const getSessionIdFromReq = (req) => {
  const raw = req.headers['x-session-id'];
  if (typeof raw === 'string' && raw.trim().length > 0) {
    return raw.trim().slice(0, 64);
  }

  // Fallback keeps anonymous usage stable even if header is absent.
  const fingerprint = `${req.ip || 'unknown'}:${req.headers['user-agent'] || 'unknown'}`;
  return crypto.createHash('sha256').update(fingerprint).digest('hex').slice(0, 64);
};

const resolveActor = (req) => {
  if (req.user?.id) {
    return { userId: req.user.id, sessionId: null, plan: req.user.plan || 'free' };
  }

  return { userId: null, sessionId: getSessionIdFromReq(req), plan: 'anonymous' };
};

const getUsageCount = async ({ projectHash, userId, sessionId }) => {
  const sql = userId
    ? `SELECT scan_count FROM project_usage WHERE project_hash = $1 AND user_id = $2`
    : `SELECT scan_count FROM project_usage WHERE project_hash = $1 AND user_id IS NULL AND session_id = $2`;

  const params = userId ? [projectHash, userId] : [projectHash, sessionId];
  const result = await query(sql, params);
  return result.rows[0]?.scan_count || 0;
};

export const getProjectQuota = async (req, projectHash) => {
  const actor = resolveActor(req);
  const used = await getUsageCount({ projectHash, userId: actor.userId, sessionId: actor.sessionId });
  const limit = getPlanLimit(actor.plan);
  const remaining = limit === null ? null : Math.max(limit - used, 0);

  return {
    projectHash,
    used,
    limit,
    remaining,
    hasQuota: limit === null ? true : used < limit,
  };
};

export const checkProjectQuota = async (req, res, next) => {
  try {
    const projectHash = req.body?.projectHash;
    if (typeof projectHash !== 'string' || projectHash.length !== 64) {
      return next();
    }

    const quota = await getProjectQuota(req, projectHash);
    if (!quota.hasQuota) {
      return res.status(402).json({
        success: false,
        error: 'Project scan quota exceeded',
        quota,
      });
    }

    req.projectQuota = quota;
    next();
  } catch (err) {
    next(err);
  }
};

export const incrementProjectUsage = async (req, projectHash) => {
  const actor = resolveActor(req);

  if (actor.userId) {
    await query(
      `INSERT INTO project_usage (project_hash, user_id, scan_count, updated_at)
       VALUES ($1, $2, 1, now())
       ON CONFLICT (project_hash, user_id) WHERE user_id IS NOT NULL
       DO UPDATE SET scan_count = project_usage.scan_count + 1, updated_at = now()`,
      [projectHash, actor.userId]
    );
  } else {
    await query(
      `INSERT INTO project_usage (project_hash, session_id, scan_count, updated_at)
       VALUES ($1, $2, 1, now())
       ON CONFLICT (project_hash, session_id) WHERE user_id IS NULL
       DO UPDATE SET scan_count = project_usage.scan_count + 1, updated_at = now()`,
      [projectHash, actor.sessionId]
    );
  }

  return getProjectQuota(req, projectHash);
};
