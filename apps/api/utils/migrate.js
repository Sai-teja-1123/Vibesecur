// ============================================================
//  Apply database schema — run from apps/api: npm run db:migrate
// ============================================================
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.join(__dirname, '..');
const repoRoot = path.join(__dirname, '..', '..', '..');

// Do not rely on process.cwd() — npm may run this with cwd = apps/api or repo root.
dotenv.config({ path: path.join(repoRoot, '.env') });
dotenv.config({ path: path.join(apiDir, '.env') });

/** @param {string | undefined} raw */
function normalizeDatabaseUrl(raw) {
  let u = String(raw ?? '').trim();
  if (
    (u.startsWith('"') && u.endsWith('"')) ||
    (u.startsWith("'") && u.endsWith("'"))
  ) {
    u = u.slice(1, -1).trim();
  }
  return u;
}

let url = normalizeDatabaseUrl(process.env.DATABASE_URL);
if (!url) {
  const example = path.join(apiDir, '.env.example');
  console.error('DATABASE_URL is not set.');
  console.error(`Create ${path.join(apiDir, '.env')} (copy from .env.example) and set DATABASE_URL.`);
  console.error(`Example file: ${example}`);
  process.exit(1);
}

if (/YOUR-PASSWORD|your-password|\[YOUR-PASSWORD\]/i.test(url)) {
  console.error(
    'DATABASE_URL still contains a placeholder password. Replace it with your real DB password from Supabase → Project Settings → Database.',
  );
  process.exit(1);
}

if (!/^postgres(ql)?:\/\//i.test(url)) {
  console.error(
    'DATABASE_URL must start with postgresql:// or postgres:// (one line, no spaces before the URL).',
  );
  process.exit(1);
}

const migrationFull = path.join(__dirname, 'migration.sql');
const migrationInc = path.join(__dirname, 'migration-incremental.sql');

const useSsl =
  /sslmode=require|sslmode=verify-full|ssl=true/i.test(url) ||
  /supabase\.co/i.test(url) ||
  process.env.NODE_ENV === 'production';

async function main() {
  let client;
  try {
    client = new pg.Client({
      connectionString: url,
      ssl: useSsl ? { rejectUnauthorized: false } : false,
    });
  } catch (err) {
    if (err && (err.code === 'ERR_INVALID_URL' || /invalid url/i.test(String(err.message)))) {
      console.error('DATABASE_URL is not a valid Postgres connection URI.');
      console.error(
        'Common fixes: remove wrapping quotes; use one line only; if the password contains @ # : / ? % or spaces, URL-encode it (e.g. @ → %40, # → %23).',
      );
      process.exit(1);
    }
    throw err;
  }

  try {
    await client.connect();

    const { rows } = await client.query(
      `SELECT 1 AS ok FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name = 'users'
       LIMIT 1`,
    );

    const useIncremental = rows.length > 0;
    const file = useIncremental ? migrationInc : migrationFull;
    const sql = fs.readFileSync(file, 'utf8');

    await client.query(sql);

    console.log(
      useIncremental
        ? `db:migrate — applied incremental schema (${path.basename(file)}).`
        : `db:migrate — applied full schema (${path.basename(file)}).`,
    );
  } finally {
    await client.end().catch(() => {});
  }
}

main().catch((err) => {
  console.error('db:migrate failed:', err.message || err);
  process.exit(1);
});
