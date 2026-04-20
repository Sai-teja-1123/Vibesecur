// ============================================================
//  Vibesecur — routes/passport.js
// ============================================================
import { Router } from 'express';
import crypto from 'crypto';
import { body, validationResult } from 'express-validator';
import { requireAuth } from '../middleware/auth.js';
import { requirePlan } from '../middleware/plans.js';
import { query } from '../utils/db.js';

const router = Router();

// POST /passport/generate
router.post('/generate',
  requireAuth, requirePlan('solo'),
  body('scanId').isUUID(),
  body('projectName').isString().isLength({ min:1, max:200 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ success:false, error: errors.array()[0].msg });

      const { scanId, projectName } = req.body;
      const scan = await query(
        'SELECT id, platform, language, score, grade, code_hash FROM scans WHERE id=$1 AND user_id=$2',
        [scanId, req.user.id]
      );
      if (!scan.rows[0]) return res.status(404).json({ success:false, error:'Scan not found' });
      const s = scan.rows[0];

      const timestamp   = new Date().toISOString();
      const fingerprint = crypto.createHash('sha256')
        .update(s.code_hash + req.user.id + timestamp).digest('hex');
      const watermarkId = crypto.createHmac('sha256', process.env.WATERMARK_SECRET || 'dev-secret')
        .update(fingerprint).digest('base64url').slice(0,16);

      const result = await query(
        `INSERT INTO ip_passports
           (user_id,scan_id,project_name,fingerprint,watermark_id,language,platform,score_at_issue)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, issued_at`,
        [req.user.id, scanId, projectName, fingerprint, watermarkId, s.language, s.platform, s.score]
      );

      res.status(201).json({ success:true, data:{
        passportId:  result.rows[0].id,
        fingerprint, watermarkId, issuedAt: result.rows[0].issued_at,
        projectName, score: s.score, grade: s.grade,
        downloadUrl: `/api/v1/passport/${result.rows[0].id}/download`,
      }});
    } catch(err){ next(err); }
  }
);

// GET /passport
router.get('/', requireAuth, requirePlan('solo'), async (req,res,next) => {
  try {
    const r = await query(
      'SELECT id,project_name,fingerprint,watermark_id,language,platform,score_at_issue,issued_at FROM ip_passports WHERE user_id=$1 ORDER BY issued_at DESC',
      [req.user.id]
    );
    res.json({ success:true, data:{ passports: r.rows }});
  } catch(err){ next(err); }
});

// GET /passport/:id
router.get('/:id', requireAuth, requirePlan('solo'), async (req,res,next) => {
  try {
    const r = await query(
      'SELECT * FROM ip_passports WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!r.rows[0]) return res.status(404).json({ success:false, error:'Passport not found' });
    res.json({ success:true, data:{ passport: r.rows[0] }});
  } catch(err){ next(err); }
});

// POST /passport/verify  — public endpoint to verify a watermark
router.post('/verify',
  body('watermarkId').isString().isLength({ min:8, max:32 }),
  body('fingerprint').isString().isLength({ min:64, max:64 }),
  async (req,res,next) => {
    try {
      const { watermarkId, fingerprint } = req.body;
      const expected = crypto.createHmac('sha256', process.env.WATERMARK_SECRET || 'dev-secret')
        .update(fingerprint).digest('base64url').slice(0,16);
      const valid = watermarkId.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(watermarkId), Buffer.from(expected));

      if (!valid) return res.json({ success:true, data:{ valid:false }});

      const r = await query(
        `SELECT ip.project_name, ip.issued_at, ip.score_at_issue, ip.platform,
                u.email
         FROM ip_passports ip JOIN users u ON u.id = ip.user_id
         WHERE ip.watermark_id=$1`,
        [watermarkId]
      );
      res.json({ success:true, data:{ valid:true, passport: r.rows[0] || null }});
    } catch(err){ next(err); }
  }
);

export default router;
