/**
 * CLI helper for the Vibesecur Cursor extension.
 * Prints one JSON object to stdout (same shape as MCP scanRepo summary + topRiskFiles).
 */
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const vibesecurRoot = process.env.VIBESECUR_ROOT
  ? path.resolve(process.env.VIBESECUR_ROOT)
  : path.resolve(__dirname, '..', '..');

const scanRoot = process.env.REPO_ROOT
  ? path.resolve(process.env.REPO_ROOT)
  : process.cwd();

const maxFiles = Math.min(5000, Math.max(1, parseInt(process.env.MAX_FILES || '400', 10) || 400));

const repoScanPath = path.join(vibesecurRoot, 'tools', 'mcp-server', 'src', 'repo-scan.mjs');
const { gatherRepoScan, DEFAULT_INCLUDE, DEFAULT_EXCLUDE } = await import(pathToFileURL(repoScanPath).href);

try {
  const { matchedFiles, limitedFiles, aggregate, topRiskFiles } = await gatherRepoScan(
    scanRoot,
    DEFAULT_INCLUDE,
    DEFAULT_EXCLUDE,
    maxFiles,
  );

  const payload = {
    rootPath: scanRoot,
    vibesecurRoot,
    scannedFiles: limitedFiles.length,
    matchedFiles: matchedFiles.length,
    cappedByMaxFiles: matchedFiles.length > maxFiles,
    summary: aggregate.summary,
    checklist: aggregate.checklist,
    topRiskFiles,
  };
  process.stdout.write(JSON.stringify(payload, null, 2));
} catch (err) {
  process.stderr.write(String(err?.stack || err?.message || err));
  process.exit(1);
}
