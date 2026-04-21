// ============================================================
//  Vibesecur — routes/waitlist.js  (public landing signups)
// ============================================================
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import { query } from '../utils/db.js';
import { createLogger } from '../utils/logger.js';

const router = Router();
const log = createLogger('waitlist');

const waitlistLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: parseInt(process.env.WAITLIST_RATE_MAX, 10) || 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many waitlist attempts — try again later' },
});

router.post(
  '/',
  waitlistLimit,
  body('email').isEmail().normalizeEmail(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
      }

      const email = req.body.email;

      let row;
      const insert = await query(
        `INSERT INTO waitlist_signups (email) VALUES ($1)
         ON CONFLICT (email) DO NOTHING
         RETURNING id, created_at`,
        [email],
      );

      if (insert.rowCount > 0) {
        row = insert.rows[0];
      } else {
        const existing = await query(
          'SELECT id, created_at FROM waitlist_signups WHERE email = $1',
          [email],
        );
        if (existing.rows.length === 0) {
          return res.status(500).json({ success: false, error: 'Something went wrong — please try again' });
        }
        row = existing.rows[0];
      }

      const [rankRes, totalRes] = await Promise.all([
        query(
          `SELECT COUNT(*)::int AS position FROM waitlist_signups WHERE created_at <= $1`,
          [row.created_at],
        ),
        query(`SELECT COUNT(*)::int AS total FROM waitlist_signups`),
      ]);

      const position = rankRes.rows[0]?.position ?? 1;
      const totalSignups = totalRes.rows[0]?.total ?? position;

      log.info({ waitlistId: row.id, alreadySigned: insert.rowCount === 0 }, 'waitlist signup');

      res.status(201).json({
        success: true,
        data: {
          position,
          totalSignups,
          alreadyOnList: insert.rowCount === 0,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
