import crypto from 'crypto';
import path from 'path';

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/** Stable session for anonymous MCP usage (override with VIBESECUR_SESSION_ID). */
export function getMcpSessionId() {
  const fromEnv = process.env.VIBESECUR_SESSION_ID;
  if (typeof fromEnv === 'string' && fromEnv.trim().length > 0) {
    return fromEnv.trim().slice(0, 64);
  }
  const basis = `mcp:${process.env.USER || process.env.USERNAME || 'anon'}:${process.cwd()}`;
  return sha256Hex(basis);
}

/** One row per logical repo / cwd for quota + analytics. */
export function getProjectHashForPath(rootPath) {
  const resolved = path.resolve(rootPath || '.');
  return sha256Hex(`vibesecur:mcp:${resolved}`);
}

export function normalizeLockedRoot(raw) {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const slashed = trimmed.replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  return slashed.replace(/\/+$/, '').toLowerCase();
}

export function buildLockedRootHash(lockedRoot) {
  return sha256Hex(`vibesecur:mcp:root:${normalizeLockedRoot(lockedRoot)}`);
}

export function buildLockedProjectHash(lockedRootHash) {
  return sha256Hex(`vibesecur:mcp:project:${lockedRootHash}`);
}

export function getMcpLockContext() {
  const strictRaw = String(process.env.VIBESECUR_STRICT_LOCK || '').toLowerCase();
  const strict = strictRaw === '1' || strictRaw === 'true' || strictRaw === 'yes';
  const lockedRoot = normalizeLockedRoot(process.env.VIBESECUR_LOCKED_ROOT || '');
  const lockedRootHash = lockedRoot ? buildLockedRootHash(lockedRoot) : '';
  const installToken = (process.env.VIBESECUR_INSTALL_TOKEN || '').trim();
  return { strict, lockedRoot, lockedRootHash, installToken };
}

function normalizeApiBase(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const u = raw.trim().replace(/\/$/, '');
  return u.endsWith('/api/v1') ? u : `${u}/api/v1`;
}

/**
 * POST /scan/local on the hosted API (quota + server rule engine).
 * Set VIBESECUR_API_BASE (e.g. https://api.vibesecur.dev or http://localhost:4000).
 */
export async function postRemoteLocalScan({
  code,
  lang = 'auto',
  projectRoot = '.',
  platform = 'mcp',
  token,
} = {}) {
  const lock = getMcpLockContext();
  const apiBase = normalizeApiBase(process.env.VIBESECUR_API_BASE || process.env.VIBESECUR_API_URL || '');
  if (lock.strict && !apiBase) {
    return {
      skipped: false,
      status: 412,
      ok: false,
      json: {
        success: false,
        error: 'Strict MCP lock requires VIBESECUR_API_BASE',
        code: 'MCP_LOCK_API_REQUIRED',
      },
    };
  }
  if (!apiBase) {
    return { skipped: true, reason: 'VIBESECUR_API_BASE not set' };
  }

  if (lock.strict && (!lock.lockedRootHash || !/^[a-f0-9]{64}$/.test(lock.installToken))) {
    return {
      skipped: false,
      status: 412,
      ok: false,
      json: {
        success: false,
        error: 'Strict MCP lock requires VIBESECUR_LOCKED_ROOT and VIBESECUR_INSTALL_TOKEN',
        code: 'MCP_LOCK_BINDING_REQUIRED',
      },
    };
  }

  const projectHash = lock.lockedRootHash
    ? buildLockedProjectHash(lock.lockedRootHash)
    : getProjectHashForPath(projectRoot);
  const headers = {
    'Content-Type': 'application/json',
    'x-session-id': getMcpSessionId(),
  };
  if (lock.installToken) {
    headers['x-vs-install-token'] = lock.installToken;
  }
  const bearer = token || process.env.VIBESECUR_AUTH_TOKEN || process.env.VIBESECUR_TOKEN;
  if (bearer) {
    headers.Authorization = bearer.startsWith('Bearer ') ? bearer : `Bearer ${bearer}`;
  }

  const res = await fetch(`${apiBase}/scan/local`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      code,
      lang,
      platform,
      projectHash,
      installToken: lock.installToken || undefined,
      lockedRootHash: lock.lockedRootHash || undefined,
    }),
  });

  const json = await res.json().catch(() => ({}));
  return { apiBase, status: res.status, ok: res.ok, json };
}
