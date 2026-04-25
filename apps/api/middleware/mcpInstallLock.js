// ============================================================
//  Vibesecur — middleware/mcpInstallLock.js
// ============================================================
import crypto from 'crypto';
import { query } from '../utils/db.js';

const sha256Hex = (value) => crypto.createHash('sha256').update(value, 'utf8').digest('hex');

export const normalizeLockedRoot = (rawPath = '') => {
  if (typeof rawPath !== 'string') return '';
  const trimmed = rawPath.trim();
  if (!trimmed) return '';
  const slashed = trimmed.replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  const withoutTrailing = slashed.replace(/\/+$/, '');
  return withoutTrailing.toLowerCase();
};

const buildLockedProjectHash = (lockedRootHash) => sha256Hex(`vibesecur:mcp:project:${lockedRootHash}`);

const extractInstallToken = (req) => {
  const fromHeader = req.headers['x-vs-install-token'];
  if (typeof fromHeader === 'string' && fromHeader.trim().length > 0) return fromHeader.trim();
  if (typeof req.body?.installToken === 'string' && req.body.installToken.trim().length > 0) {
    return req.body.installToken.trim();
  }
  return '';
};

export const verifyMcpInstallLock = async (req, res, next) => {
  try {
    const platform = req.body?.platform;
    const source = req.body?.source;
    const isMcpRequest = platform === 'mcp' || source === 'mcp';
    if (!isMcpRequest) return next();

    const installToken = extractInstallToken(req);
    const lockedRootHash = typeof req.body?.lockedRootHash === 'string'
      ? req.body.lockedRootHash.trim().toLowerCase()
      : '';
    const projectHash = typeof req.body?.projectHash === 'string'
      ? req.body.projectHash.trim().toLowerCase()
      : '';

    if (!/^[a-f0-9]{64}$/.test(installToken) || !/^[a-f0-9]{64}$/.test(lockedRootHash)) {
      return res.status(403).json({
        success: false,
        error: 'MCP install lock verification failed',
        code: 'MCP_INSTALL_LOCK_MISSING',
      });
    }

    const installTokenHash = sha256Hex(installToken);
    const result = await query(
      `SELECT mi.id, mi.user_id, mi.locked_root_hash, mi.revoked_at, u.plan
       FROM mcp_installs mi
       JOIN users u ON u.id = mi.user_id
       WHERE mi.install_token_hash = $1
       LIMIT 1`,
      [installTokenHash],
    );
    const install = result.rows[0];
    if (!install || install.revoked_at) {
      return res.status(403).json({
        success: false,
        error: 'MCP install is revoked or invalid',
        code: 'MCP_INSTALL_LOCK_INVALID',
      });
    }

    if (install.locked_root_hash !== lockedRootHash) {
      return res.status(403).json({
        success: false,
        error: 'MCP install is locked to a different folder',
        code: 'MCP_INSTALL_LOCK_MISMATCH',
      });
    }

    const expectedProjectHash = buildLockedProjectHash(lockedRootHash);
    if (projectHash && projectHash !== expectedProjectHash) {
      return res.status(403).json({
        success: false,
        error: 'Project hash does not match locked folder',
        code: 'MCP_PROJECT_HASH_MISMATCH',
      });
    }

    req.user = { id: install.user_id, plan: install.plan };
    req.mcpInstall = {
      id: install.id,
      userId: install.user_id,
      lockedRootHash: install.locked_root_hash,
      projectHash: expectedProjectHash,
    };
    req.body.projectHash = expectedProjectHash;
    return next();
  } catch (err) {
    return next(err);
  }
};

export const buildLockedRootHash = (lockedRootPath) => sha256Hex(`vibesecur:mcp:root:${normalizeLockedRoot(lockedRootPath)}`);

export const buildLockedInstallToken = () => crypto.randomBytes(32).toString('hex');

export const buildInstallTokenHash = (installToken) => sha256Hex(String(installToken || ''));
