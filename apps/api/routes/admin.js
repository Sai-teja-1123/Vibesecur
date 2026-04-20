// ============================================================
//  Vibesecur — routes/admin.js
// ============================================================
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { requirePlan } from '../middleware/plans.js';
import { query } from '../utils/db.js';
import { localScan } from '../services/ScanService.js';
import fs from 'fs';

const router = Router();
const USE_ADMIN = (req,res,next) => { requireAuth(req,res,()=>requirePlan('admin')(req,res,next)); };

router.get('/stats', USE_ADMIN, async (req,res,next) => {
  try {
    const [users,scans,today] = await Promise.all([
      query('SELECT COUNT(*) total, COUNT(*) FILTER (WHERE plan=\'solo\') solo, COUNT(*) FILTER (WHERE plan=\'pro\') pro FROM users'),
      query('SELECT COUNT(*) total, ROUND(AVG(score),1) avg_score FROM scans'),
      query('SELECT COUNT(*) FROM scans WHERE created_at >= CURRENT_DATE'),
    ]);
    res.json({ success:true, data:{ users: users.rows[0], scans: scans.rows[0], today: today.rows[0] }});
  } catch(err){ next(err); }
});

router.get('/users', USE_ADMIN, async (req,res,next) => {
  try {
    const r = await query(
      'SELECT id,email,plan,scan_count_total,created_at,last_login_at FROM users ORDER BY created_at DESC LIMIT 100'
    );
    res.json({ success:true, data:{ users: r.rows }});
  } catch(err){ next(err); }
});

router.get('/audit', USE_ADMIN, async (req,res,next) => {
  try {
    const r = await query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200');
    res.json({ success:true, data:{ logs: r.rows }});
  } catch(err){ next(err); }
});

// Self-security scan — Vibesecur scans its own server.js
router.get('/self-check', USE_ADMIN, async (req,res,next) => {
  try {
    const ownCode = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
    const result  = localScan(ownCode, 'js');
    res.json({ success:true, data:{
      message: 'Vibesecur self-security scan complete',
      score:   result.score,
      grade:   result.grade,
      findings: result.findings.length,
      details: result,
    }});
  } catch(err){ next(err); }
});

export default router;
