// ============================================================
//  Vibesecur API Server — server.js
//  AI-powered security platform for vibe-coded applications
//  Version 1.0.0 · April 2026
// ============================================================
import './utils/loadEnv.js';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pinoHttp from 'pino-http';
import { createLogger } from './utils/logger.js';

// Route imports
import authRoutes    from './routes/auth.js';
import scanRoutes    from './routes/scan.js';
import keyRoutes     from './routes/keys.js';
import passportRoutes from './routes/passport.js';
import billingRoutes from './routes/billing.js';
import adminRoutes   from './routes/admin.js';
import waitlistRoutes from './routes/waitlist.js';
import mcpRoutes     from './routes/mcp.js';
import { errorHandler } from './middleware/errorHandler.js';

const requireEnv = (name, options = {}) => {
  const value = process.env[name];
  if (!value || !String(value).trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  if (options.rejectValues?.includes(value)) {
    throw new Error(`Unsafe value for environment variable: ${name}`);
  }
  return value;
};

const validateEnv = () => {
  const env = process.env.NODE_ENV || 'development';
  requireEnv('JWT_SECRET', {
    rejectValues: ['REPLACE_WITH_64_CHAR_RANDOM_STRING', 'vibesecur-dev-scan-receipt', 'dev-secret'],
  });
  requireEnv('WATERMARK_SECRET', {
    rejectValues: ['REPLACE_WITH_64_CHAR_RANDOM_STRING', 'dev-secret'],
  });

  if (env === 'production') {
    requireEnv('CORS_ORIGIN');
  }
};

validateEnv();

const app  = express();
const log  = createLogger('server');
const PORT = process.env.PORT || 4000;

// ── Security headers ──────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'"],
      styleSrc:    ["'self'", "'unsafe-inline'"],
      connectSrc:  ["'self'", 'https://api.anthropic.com'],
      imgSrc:      ["'self'", 'data:'],
      frameAncestors: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ── CORS ──────────────────────────────────────────────────
const configuredOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);
const devOrigins = ['http://localhost:3000', 'http://127.0.0.1:3000'];
const allowedOrigins = new Set(
  (process.env.NODE_ENV === 'production'
    ? configuredOrigins
    : [...configuredOrigins, ...devOrigins]),
);

app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin/non-browser requests with no Origin header.
    if (!origin) return cb(null, true);
    if (allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error(`CORS origin not allowed: ${origin}`));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-session-id', 'x-vs-install-token'],
  credentials: true,
}));

// ── Body parsing ──────────────────────────────────────────
app.use('/api/v1/billing/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '50kb' }));  // Small — we never accept code bodies
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ── Structured logging (redact sensitive fields) ──────────
app.use(pinoHttp({
  logger: createLogger('http'),
  redact: ['req.headers.authorization', 'req.body.password',
           'req.body.key', 'req.body.email', 'res.body.token'],
  serializers: {
    req: (req) => ({ method: req.method, url: req.url, id: req.id }),
  },
}));

// ── Global rate limiting ──────────────────────────────────
const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests — please slow down' },
});
app.use('/api/', globalLimit);

// ── Auth rate limit (strict) ──────────────────────────────
const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many auth attempts — try again in 15 minutes' },
});
app.use('/api/v1/auth/', authLimit);

// ── Health check ──────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  version: '1.0.0',
  env: process.env.NODE_ENV,
  timestamp: new Date().toISOString(),
}));

// ── API Routes ────────────────────────────────────────────
app.use('/api/v1/auth',     authRoutes);
app.use('/api/v1/scan',     scanRoutes);
app.use('/api/v1/keys',     keyRoutes);
app.use('/api/v1/passport', passportRoutes);
app.use('/api/v1/billing',  billingRoutes);
app.use('/api/v1/admin',    adminRoutes);
app.use('/api/v1/waitlist', waitlistRoutes);
app.use('/api/v1/mcp',      mcpRoutes);

// ── 404 handler ───────────────────────────────────────────
app.use((req, res) => res.status(404).json({
  success: false,
  error: `Endpoint ${req.method} ${req.path} not found`,
}));

// ── Error handler ─────────────────────────────────────────
app.use(errorHandler);

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  log.info(`Vibesecur API running on port ${PORT} [${process.env.NODE_ENV}]`);
});

export default app;
