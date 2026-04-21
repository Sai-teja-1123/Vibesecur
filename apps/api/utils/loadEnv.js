import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.join(__dirname, '..');
const repoRoot = path.join(apiDir, '..', '..');

// Monorepo root .env first; apps/api/.env wins on duplicate keys.
dotenv.config({ path: path.join(repoRoot, '.env') });
dotenv.config({ path: path.join(apiDir, '.env'), override: true });

