// ============================================================
//  Vibesecur — routes/mcp.js
// ============================================================
import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import { requireAuth } from '../middleware/auth.js';
import { query } from '../utils/db.js';
import {
  buildLockedInstallToken,
  buildLockedRootHash,
  buildInstallTokenHash,
  normalizeLockedRoot,
} from '../middleware/mcpInstallLock.js';

const router = Router();

const resolveApiBase = (req) => {
  if (process.env.PUBLIC_API_BASE && process.env.PUBLIC_API_BASE.trim()) {
    return process.env.PUBLIC_API_BASE.trim().replace(/\/$/, '');
  }
  const host = req.get('host');
  const proto = req.get('x-forwarded-proto') || req.protocol || 'https';
  return `${proto}://${host}`;
};

router.post(
  '/bind',
  requireAuth,
  body('lockedRootPath').isString().isLength({ min: 2, max: 1000 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: errors.array()[0].msg });
      }

      const lockedRootPath = req.body.lockedRootPath;
      const normalizedRoot = normalizeLockedRoot(lockedRootPath);
      if (!normalizedRoot) {
        return res.status(400).json({ success: false, error: 'Invalid lockedRootPath' });
      }

      const lockedRootHash = buildLockedRootHash(normalizedRoot);
      const installToken = buildLockedInstallToken();
      const installTokenHash = buildInstallTokenHash(installToken);

      await query(
        'UPDATE mcp_installs SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL',
        [req.user.id],
      );

      const insert = await query(
        `INSERT INTO mcp_installs (user_id, install_token_hash, locked_root_hash, locked_root_hint)
         VALUES ($1, $2, $3, $4)
         RETURNING id, created_at`,
        [req.user.id, installTokenHash, lockedRootHash, normalizedRoot],
      );

      const apiBase = resolveApiBase(req);
      const config = {
        mcpServers: {
          vibesecur: {
            command: 'npx',
            args: ['-y', '@vibesecur/mcp-server'],
            cwd: normalizedRoot,
            env: {
              VIBESECUR_API_BASE: apiBase,
              VIBESECUR_INSTALL_TOKEN: installToken,
              VIBESECUR_LOCKED_ROOT: normalizedRoot,
              VIBESECUR_STRICT_LOCK: 'true',
            },
          },
        },
      };

      return res.status(201).json({
        success: true,
        data: {
          installId: insert.rows[0].id,
          lockedRootPath: normalizedRoot,
          lockedRootHash,
          installToken,
          createdAt: insert.rows[0].created_at,
          mcpConfig: config,
        },
      });
    } catch (err) {
      return next(err);
    }
  },
);

router.get('/binding', requireAuth, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, locked_root_hash, locked_root_hint, created_at
       FROM mcp_installs
       WHERE user_id = $1 AND revoked_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [req.user.id],
    );
    return res.json({ success: true, data: { binding: result.rows[0] || null } });
  } catch (err) {
    return next(err);
  }
});

export default router;
