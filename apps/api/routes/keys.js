// ============================================================
//  Vibesecur — routes/keys.js
// ============================================================
import { Router } from 'express';
import crypto from 'crypto';
import { body, validationResult } from 'express-validator';
import { requireAuth } from '../middleware/auth.js';
import { query } from '../utils/db.js';

const router = Router();

router.get('/', requireAuth, async (req,res,next) => {
  try {
    const r = await query(
      'SELECT id,label,key_prefix,status,last_used_at,use_count,created_at,revoked_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ success:true, data:{ keys: r.rows }});
  } catch(err){ next(err); }
});

router.post('/',
  requireAuth,
  body('label').isString().isLength({ min:1, max:100 }),
  body('key').isString().isLength({ min:20, max:300 }),
  async (req,res,next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ success:false, error: errors.array()[0].msg });
      const { label, key } = req.body;
      if (!key.startsWith('sk-ant')) return res.status(400).json({ success:false, error:'Must be a valid Claude API key (sk-ant-...)' });
      const keyHash   = crypto.createHash('sha256').update(key).digest('hex');
      const keyPrefix = key.substring(0,16)+'...'+key.slice(-4);
      const r = await query(
        `INSERT INTO api_keys (user_id,label,key_hash,key_prefix) VALUES ($1,$2,$3,$4) RETURNING id,label,key_prefix,status,created_at`,
        [req.user.id, label, keyHash, keyPrefix]
      );
      res.status(201).json({ success:true, data:{ key: r.rows[0] }});
    } catch(err){ next(err); }
  }
);

router.delete('/:id', requireAuth, async (req,res,next) => {
  try {
    const r = await query('DELETE FROM api_keys WHERE id=$1 AND user_id=$2 RETURNING id', [req.params.id, req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ success:false, error:'Key not found' });
    res.json({ success:true, data:{ deleted:true }});
  } catch(err){ next(err); }
});

router.post('/:id/revoke', requireAuth, async (req,res,next) => {
  try {
    const r = await query(
      `UPDATE api_keys SET status='revoked', revoked_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING id`,
      [req.params.id, req.user.id]
    );
    if (!r.rows[0]) return res.status(404).json({ success:false, error:'Key not found' });
    res.json({ success:true, data:{ revoked:true }});
  } catch(err){ next(err); }
});

export default router;
