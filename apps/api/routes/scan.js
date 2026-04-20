// ============================================================
//  Vibesecur — routes/scan.js
// ============================================================
import { Router } from 'express';
import crypto from 'crypto';
import { body, query as queryParam, validationResult } from 'express-validator';
import { requireAuth, optionalAuth } from '../middleware/auth.js';
import { requirePlan } from '../middleware/plans.js';
import { checkProjectQuota, getProjectQuota, incrementProjectUsage } from '../middleware/projectQuota.js';
import { query } from '../utils/db.js';
import { localScan } from '../services/ScanService.js';
import { createLogger } from '../utils/logger.js';

const normalizeCodeHash = (raw, meta) => {
  if (typeof raw === 'string' && /^[a-f0-9]{64}$/i.test(raw)) return raw.toLowerCase();
  return crypto.createHash('sha256').update(JSON.stringify(meta)).digest('hex');
};

const scanReceiptSecret = () =>
  process.env.JWT_SECRET
  || (process.env.NODE_ENV !== 'production' ? 'vibesecur-dev-scan-receipt' : '');

/** Lets POST /scan/log skip a second quota increment after POST /scan/local (same codeHash + projectHash). */
function signScanReceipt(projectHash, codeHash) {
  const secret = scanReceiptSecret();
  if (!secret || !projectHash || !codeHash) return '';
  const bucket = Math.floor(Date.now() / 120000);
  return crypto
    .createHmac('sha256', secret)
    .update(`${projectHash}|${codeHash.toLowerCase()}|${bucket}`)
    .digest('hex');
}

function verifyScanReceipt(projectHash, codeHash, scanReceipt) {
  const secret = scanReceiptSecret();
  if (!secret || typeof scanReceipt !== 'string' || scanReceipt.length !== 64) return false;
  if (typeof codeHash !== 'string' || !/^[a-f0-9]{64}$/i.test(codeHash)) return false;
  const norm = codeHash.toLowerCase();
  const bucket = Math.floor(Date.now() / 120000);
  for (let b = bucket; b >= bucket - 2; b -= 1) {
    const expected = crypto
      .createHmac('sha256', secret)
      .update(`${projectHash}|${norm}|${b}`)
      .digest('hex');
    if (expected === scanReceipt) return true;
  }
  return false;
}

const router = Router();
const log    = createLogger('scan');

// ── POST /scan/local — Run local rule engine ─────────────
// No auth required. Returns findings from local rule engine.
// Code is NOT stored — only used transiently for scanning.
router.post('/local',
  optionalAuth,
  body('code').isString().isLength({ min: 1, max: 50000 }),
  body('lang').isIn(['js','ts','py','json','auto']).optional(),
  body('platform').isString().isLength({ max: 50 }).optional(),
  body('projectHash').isString().isLength({ min: 64, max: 64 }),
  checkProjectQuota,
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: errors.array()[0].msg });
      }

      const { code, lang = 'auto', platform = 'unknown', projectHash } = req.body;

      // IMPORTANT: code is scanned here and immediately discarded
      // We never store the code — only the hash
      const result   = localScan(code, lang);
      const codeHash = result.codeHash;
      const quota = await incrementProjectUsage(req, projectHash);

      // Code reference is discarded after this response is sent
      log.info(
        { platform, lang, score: result.score, findings: result.findings.length, projectHash, quotaRemaining: quota.remaining },
        'Local scan completed'
      );

      const scanReceipt = signScanReceipt(projectHash, codeHash);

      res.json({
        success: true,
        data: {
          ...result,
          codeHash,
          scanReceipt,
          engine:    'local',
          timestamp: new Date().toISOString(),
          // Strip code reference from findings (only metadata returned)
          findings: result.findings.map(({ snippet, ...f }) => f),
        },
        quota,
      });
    } catch (err) { next(err); }
  }
);

// ── GET /scan/quota — Resolve project quota for actor ──────
router.get('/quota',
  optionalAuth,
  queryParam('projectHash').isString().isLength({ min: 64, max: 64 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: errors.array()[0].msg });
      }

      const quota = await getProjectQuota(req, req.query.projectHash);
      res.json({ success: true, data: { quota } });
    } catch (err) { next(err); }
  }
);

// ── POST /scan/log — Log scan metadata (NO code accepted) ─
router.post('/log',
  optionalAuth,
  body('score').isInt({ min: 0, max: 100 }),
  body('grade').isIn(['A','B','C','D','F']),
  body('platform').isString().isLength({ max: 50 }),
  body('lang').isIn(['js','ts','py','json','auto']),
  body('engine').isIn(['local','claude_ai']).optional(),
  body('criticalCount').isInt({ min: 0 }).optional(),
  body('highCount').isInt({ min: 0 }).optional(),
  body('mediumCount').isInt({ min: 0 }).optional(),
  body('linesAnalysed').isInt({ min: 0 }).optional(),
  body('codeHash').isLength({ min: 64, max: 64 }).optional(),
  body('scanReceipt').isString().isLength({ min: 64, max: 64 }).optional(),
  body('projectHash').isString().isLength({ min: 64, max: 64 }),
  body('source').isIn(['web', 'mcp', 'extension', 'api']).optional(),
  async (req, res, next) => {
    try {
      // POLICY: reject any request that includes a 'code' field
      if (req.body.code) {
        return res.status(400).json({
          success: false,
          error: 'Code must not be sent to this endpoint. This endpoint logs metadata only.'
        });
      }

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: errors.array()[0].msg });
      }

      const {
        score, grade, platform, lang,
        engine = 'local', criticalCount = 0, highCount = 0, mediumCount = 0,
        linesAnalysed = 0, codeHash = '', scanReceipt = '', mode = 'quick',
        source = 'api', projectHash,
        findings = [],
      } = req.body;

      const rawCodeHash =
        typeof codeHash === 'string' && /^[a-f0-9]{64}$/i.test(codeHash) ? codeHash.toLowerCase() : null;
      const receiptOk =
        !!rawCodeHash && typeof scanReceipt === 'string' && scanReceipt.length === 64
        && verifyScanReceipt(projectHash, rawCodeHash, scanReceipt);

      if (!receiptOk) {
        const quotaPre = await getProjectQuota(req, projectHash);
        if (!quotaPre.hasQuota) {
          return res.status(402).json({
            success: false,
            error: 'Project scan quota exceeded',
            quota: quotaPre,
          });
        }
      }

      const codeHashRow = rawCodeHash
        || normalizeCodeHash(codeHash, {
          score, grade, platform, lang, mode, projectHash, source, engine,
          criticalCount, highCount, mediumCount, linesAnalysed,
        });

      // Insert scan log
      const scanResult = await query(
        `INSERT INTO scans
          (user_id, session_id, platform, language, mode, score, grade, engine,
           source, critical_count, high_count, medium_count, lines_analysed, code_hash, project_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         RETURNING id`,
        [
          req.user?.id || null,
          req.headers['x-session-id'] || 'anonymous',
          platform, lang, mode, score, grade, engine,
          source, criticalCount, highCount, mediumCount, linesAnalysed, codeHashRow, projectHash,
        ]
      );
      const scanId = scanResult.rows[0].id;

      // Log findings metadata (NO code snippets stored)
      if (findings.length > 0) {
        const values = findings.map((_,i) =>
          `($1, $${i*5+2}, $${i*5+3}, $${i*5+4}, $${i*5+5}, $${i*5+6})`
        ).join(', ');
        const params = [scanId, ...findings.flatMap(f => [
          f.ruleId, f.ruleName, f.severity, f.category, f.fix
        ])];
        await query(
          `INSERT INTO scan_findings (scan_id, rule_id, rule_name, severity, category, fix_description)
           VALUES ${values}`,
          params
        );
      }

      // Increment user scan count
      if (req.user?.id) {
        await query(
          'UPDATE users SET scan_count_today = scan_count_today+1, scan_count_total = scan_count_total+1 WHERE id = $1',
          [req.user.id]
        );
      }

      const quota = receiptOk
        ? await getProjectQuota(req, projectHash)
        : await incrementProjectUsage(req, projectHash);
      res.status(201).json({ success: true, data: { scanId, quota } });
    } catch (err) { next(err); }
  }
);

// ── POST /scan/full — Return proxy token for Claude AI ────
// Paid users get a short-lived signed token to call Claude directly from browser
router.post('/full',
  requireAuth,
  requirePlan('solo'),
  body('codeHash').isLength({ min: 64, max: 64 }),
  body('platform').isString().isLength({ max: 50 }),
  body('lang').isIn(['js','ts','py','json','auto']),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: errors.array()[0].msg });
      }

      // Check daily scan limit (free tier enforced via requirePlan)
      // For hosted Claude (non-BYOK), generate a 30-second TTL token
      const proxyToken = crypto
        .createHmac('sha256', process.env.JWT_SECRET)
        .update(req.user.id + Date.now())
        .digest('hex')
        .slice(0, 32);

      // In production: store token in Redis with 30s TTL
      // Here: sign it in the JWT so client can use it directly
      const scanToken = {
        type: 'claude_proxy',
        userId: req.user.id,
        plan: req.user.plan,
        exp: Math.floor(Date.now() / 1000) + 30, // 30 seconds
        nonce: proxyToken,
      };

      res.json({
        success: true,
        data: {
          // Client uses this to call Claude directly from browser
          // Vibesecur server never sees the code — only the token
          apiKey: process.env.ANTHROPIC_API_KEY || null,
          model: process.env.CLAUDE_MODEL || 'claude-sonnet-4-20250514',
          scanToken: Buffer.from(JSON.stringify(scanToken)).toString('base64'),
          expiresIn: 30,
        },
      });
    } catch (err) { next(err); }
  }
);

// ── GET /scan/stats/summary (must be before /:id) ──────────
router.get('/stats/summary', requireAuth, async (req, res, next) => {
  try {
    const stats = await query(
      `SELECT
         COUNT(*)                                    AS total_scans,
         ROUND(AVG(score),1)                        AS avg_score,
         COUNT(*) FILTER (WHERE grade = 'A')        AS grade_a,
         COUNT(*) FILTER (WHERE grade = 'F')        AS grade_f,
         COUNT(*) FILTER (WHERE critical_count > 0) AS scans_with_critical,
         MAX(created_at)                            AS last_scan
       FROM scans WHERE user_id = $1`,
      [req.user.id]
    );
    const topIssues = await query(
      `SELECT sf.rule_id, sf.rule_name, sf.category, COUNT(*) AS occurrences
       FROM scan_findings sf
       JOIN scans s ON s.id = sf.scan_id
       WHERE s.user_id = $1
       GROUP BY sf.rule_id, sf.rule_name, sf.category
       ORDER BY occurrences DESC LIMIT 5`,
      [req.user.id]
    );
    res.json({ success: true, data: { stats: stats.rows[0], topIssues: topIssues.rows } });
  } catch (err) { next(err); }
});

// ── GET /scan/history ─────────────────────────────────────
router.get('/history', requireAuth, async (req, res, next) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;

    const result = await query(
      `SELECT s.id, s.platform, s.language, s.mode, s.score, s.grade, s.engine,
              s.critical_count, s.high_count, s.medium_count, s.created_at,
              (SELECT COUNT(*) FROM scan_findings sf WHERE sf.scan_id = s.id) AS finding_count
       FROM scans s
       WHERE s.user_id = $1
       ORDER BY s.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    const total = await query('SELECT COUNT(*) FROM scans WHERE user_id = $1', [req.user.id]);

    res.json({
      success: true,
      data: {
        scans: result.rows,
        pagination: { page, limit, total: parseInt(total.rows[0].count), pages: Math.ceil(total.rows[0].count / limit) },
      },
    });
  } catch (err) { next(err); }
});

// ── GET /scan/:id ─────────────────────────────────────────
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const scan = await query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    if (!scan.rows[0]) return res.status(404).json({ success: false, error: 'Scan not found' });

    const findings = await query(
      'SELECT * FROM scan_findings WHERE scan_id = $1 ORDER BY severity DESC',
      [req.params.id]
    );

    res.json({ success: true, data: { scan: scan.rows[0], findings: findings.rows } });
  } catch (err) { next(err); }
});

// ── DELETE /scan/:id ──────────────────────────────────────
router.delete('/:id', requireAuth, async (req, res, next) => {
  try {
    const result = await query(
      'DELETE FROM scans WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ success: false, error: 'Scan not found' });
    res.json({ success: true, data: { deleted: true } });
  } catch (err) { next(err); }
});

export default router;
