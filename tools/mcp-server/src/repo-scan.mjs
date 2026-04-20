import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import fg from 'fast-glob';
import { CHECKLIST, localScan } from '@vibesecur/rule-engine';

export const DEFAULT_INCLUDE = [
  '**/*.{js,jsx,ts,tsx,mjs,cjs,py,json,go,java,kt,kts,rb,php,cs,rs,swift,scala,sh,bash,zsh,yml,yaml,toml,ini,env,sql}',
];
export const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.cursor/**',
  '**/AppData/**',
  '**/Application Data/**',
  '**/$RECYCLE.BIN/**',
  '**/System Volume Information/**',
];

export function inferLang(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.py') return 'py';
  if (ext === '.json') return 'json';
  if (ext === '.ts' || ext === '.tsx') return 'ts';
  return 'js';
}

export function normalizeRootPath(rootPath) {
  const raw = (rootPath || process.cwd()).trim();
  if (!raw || raw.includes('your-other-repo')) {
    return process.cwd();
  }
  if (raw.startsWith('~')) {
    return path.resolve(process.env.USERPROFILE || process.env.HOME || '', raw.slice(1));
  }
  return path.resolve(raw);
}

export function isUnsafeWorkspaceRoot(candidatePath) {
  const normalized = candidatePath.replace(/\//g, '\\').toLowerCase();
  return (
    normalized.includes('\\application data') ||
    normalized.includes('\\appdata\\') ||
    normalized.includes('\\windows\\') ||
    normalized.includes('\\program files')
  );
}

export function isHomePath(candidatePath) {
  const home = path.resolve(os.homedir()).toLowerCase();
  const resolved = path.resolve(candidatePath).toLowerCase();
  return resolved === home;
}

export function detectWorkspacePath() {
  const candidates = [
    process.env.CURSOR_WORKSPACE_PATH,
    process.env.CURSOR_PROJECT_PATH,
    process.env.WORKSPACE_PATH,
    process.env.PWD,
    process.env.INIT_CWD,
    process.cwd(),
  ].filter(Boolean);

  for (const candidate of candidates) {
    const resolved = normalizeRootPath(candidate);
    if (resolved && !isUnsafeWorkspaceRoot(resolved) && !isHomePath(resolved)) return resolved;
  }
  return process.cwd();
}

export async function ensureDirectory(targetPath) {
  const stat = await fs.stat(targetPath);
  if (!stat.isDirectory()) {
    throw new Error(`Path is not a directory: ${targetPath}`);
  }
}

export function aggregateScanResults(fileResults) {
  const allFindings = fileResults.flatMap((r) => r.result.findings || []);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of allFindings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
  }

  const totalIssues =
    bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low;
  let score = 100;
  score -= bySeverity.critical * 20;
  score -= bySeverity.high * 10;
  score -= bySeverity.medium * 5;
  score -= bySeverity.low * 2;
  score = Math.max(0, Math.min(100, Math.round(score)));

  const checklist = CHECKLIST.map((item) => ({
    id: item.id,
    item: item.item,
    critical: item.critical,
    pass: !item.ruleIds.some((rid) => allFindings.some((f) => f.ruleId === rid)),
  }));

  return {
    summary: {
      filesScanned: fileResults.length,
      totalIssues,
      bySeverity,
      score,
    },
    checklist,
  };
}

export async function readGitignoreChecks(rootPath) {
  const gitignorePath = path.join(rootPath, '.gitignore');
  try {
    const content = await fs.readFile(gitignorePath, 'utf8');
    const hasEnvPattern = /(^|\n)\s*\.env(\.\*)?\s*($|\n)/m.test(content);
    return {
      gitignoreExists: true,
      hasEnvPattern,
      gitignorePath,
    };
  } catch {
    return {
      gitignoreExists: false,
      hasEnvPattern: false,
      gitignorePath,
    };
  }
}

export async function gatherRepoScan(rootPath, includeGlobs, excludeGlobs, maxFiles) {
  const files = await fg(includeGlobs, {
    cwd: rootPath,
    onlyFiles: true,
    absolute: true,
    ignore: excludeGlobs,
    suppressErrors: true,
    followSymbolicLinks: false,
  });

  const matchedFiles =
    files.length === 0
      ? await fg(['**/*'], {
          cwd: rootPath,
          onlyFiles: true,
          absolute: true,
          ignore: [
            ...excludeGlobs,
            '**/*.png',
            '**/*.jpg',
            '**/*.jpeg',
            '**/*.gif',
            '**/*.webp',
            '**/*.pdf',
            '**/*.zip',
          ],
          suppressErrors: true,
          followSymbolicLinks: false,
        })
      : files;

  const limitedFiles = matchedFiles.slice(0, maxFiles);
  const fileResults = [];
  for (const absPath of limitedFiles) {
    const code = await fs.readFile(absPath, 'utf8');
    const lang = inferLang(absPath);
    const result = localScan(code, lang);
    fileResults.push({
      filePath: absPath,
      lang,
      result,
    });
  }

  const aggregate = aggregateScanResults(fileResults);
  const topRiskFiles = fileResults
    .map((f) => ({
      filePath: f.filePath,
      score: f.result.score,
      findings: f.result.findings.length,
      critical: f.result.findings.filter((x) => x.severity === 'critical').length,
      high: f.result.findings.filter((x) => x.severity === 'high').length,
    }))
    .sort((a, b) => b.critical - a.critical || b.high - a.high || b.findings - a.findings)
    .slice(0, 20);

  return {
    matchedFiles,
    limitedFiles,
    fileResults,
    aggregate,
    topRiskFiles,
  };
}
