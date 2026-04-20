// ============================================================
//  Vibesecur — routes/auth.js
// ============================================================
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import { query } from '../utils/db.js';
import { requireAuth } from '../middleware/auth.js';
import { createLogger } from '../utils/logger.js';
import { sendWelcomeEmail } from '../services/EmailService.js';

const router = Router();
const log    = createLogger('auth');

// ── POST /auth/signup ─────────────────────────────────────
router.post('/signup',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be 8+ characters'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: errors.array()[0].msg });
      }

      const { email, password } = req.body;

      const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
      if (existing.rows.length > 0) {
        return res.status(409).json({ success: false, error: 'Email already registered' });
      }

      const passwordHash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);

      const result = await query(
        `INSERT INTO users (email, password_hash, plan) VALUES ($1, $2, 'free')
         RETURNING id, email, plan, created_at`,
        [email, passwordHash]
      );
      const user = result.rows[0];

      const token = jwt.sign(
        { user_id: user.id, plan: user.plan },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      // Fire-and-forget welcome email
      sendWelcomeEmail(email).catch(err => log.warn({ err }, 'Welcome email failed'));

      // Audit log
      await query(
        `INSERT INTO audit_logs (user_id, action, resource, result, ip_address)
         VALUES ($1, 'auth.signup', 'user:'||$1::text, 'success', $2)`,
        [user.id, req.ip]
      );

      log.info({ userId: user.id }, 'New user registered');
      res.status(201).json({ success: true, data: { token, user: { id: user.id, email: user.email, plan: user.plan } } });
    } catch (err) { next(err); }
  }
);

// ── POST /auth/login ──────────────────────────────────────
router.post('/login',
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Invalid email or password' });
      }

      const { email, password } = req.body;

      const result = await query(
        'SELECT id, email, password_hash, plan FROM users WHERE email = $1',
        [email]
      );
      const user = result.rows[0];

      // Timing-safe comparison (always compare even if user not found)
      const dummyHash = '$2a$12$dummy.hash.to.prevent.timing.attacks.dummy';
      const valid = user
        ? await bcrypt.compare(password, user.password_hash)
        : await bcrypt.compare(password, dummyHash) && false;

      if (!valid) {
        await query(
          `INSERT INTO audit_logs (action, resource, result, ip_address)
           VALUES ('auth.login', $1, 'failure', $2)`,
          [email, req.ip]
        );
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
      }

      const token = jwt.sign(
        { user_id: user.id, plan: user.plan },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      await query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

      log.info({ userId: user.id }, 'User logged in');
      res.json({ success: true, data: { token, user: { id: user.id, email: user.email, plan: user.plan } } });
    } catch (err) { next(err); }
  }
);

// ── GET /auth/me ──────────────────────────────────────────
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, email, plan, scan_count_today, scan_count_total,
              created_at, last_login_at, email_verified
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, data: { user: result.rows[0] } });
  } catch (err) { next(err); }
});

// ── POST /auth/logout ─────────────────────────────────────
router.post('/logout', requireAuth, (req, res) => {
  // JWT is stateless — client should discard token
  // For token invalidation at scale, maintain a denylist (Redis)
  res.json({ success: true, data: { message: 'Logged out' } });
});

export default router;
