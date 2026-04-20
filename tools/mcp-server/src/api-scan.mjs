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
  const apiBase = normalizeApiBase(process.env.VIBESECUR_API_BASE || process.env.VIBESECUR_API_URL || '');
  if (!apiBase) {
    return { skipped: true, reason: 'VIBESECUR_API_BASE not set' };
  }

  const projectHash = getProjectHashForPath(projectRoot);
  const headers = {
    'Content-Type': 'application/json',
    'x-session-id': getMcpSessionId(),
  };
  const bearer = token || process.env.VIBESECUR_AUTH_TOKEN || process.env.VIBESECUR_TOKEN;
  if (bearer) {
    headers.Authorization = bearer.startsWith('Bearer ') ? bearer : `Bearer ${bearer}`;
  }

  const res = await fetch(`${apiBase}/scan/local`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ code, lang, platform, projectHash }),
  });

  const json = await res.json().catch(() => ({}));
  return { apiBase, status: res.status, ok: res.ok, json };
}
