import { createRequire } from 'module';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import * as z from 'zod';
import fs from 'fs/promises';
import path from 'path';
import {
  CHECKLIST,
  JS_RULES,
  PY_RULES,
  buildClaudePrompt,
  localScan,
} from '@vibesecur/rule-engine';
import {
  DEFAULT_INCLUDE,
  DEFAULT_EXCLUDE,
  inferLang,
  normalizeRootPath,
  ensureDirectory,
  gatherRepoScan,
  readGitignoreChecks,
  detectWorkspacePath,
  isHomePath,
} from './repo-scan.mjs';
import { postRemoteLocalScan, getMcpLockContext } from './api-scan.mjs';

const require = createRequire(import.meta.url);
const mcpPkg = require('../package.json');

const server = new McpServer({
  name: 'vibesecur-mcp-server',
  version: mcpPkg.version || '1.0.0',
});

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function isPathWithin(parentPath, childPath) {
  const parent = path.resolve(parentPath).toLowerCase();
  const child = path.resolve(childPath).toLowerCase();
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function enforceLockedRootOrThrow(targetPath) {
  const lock = getMcpLockContext();
  if (!lock.strict || !lock.lockedRoot) return;
  if (!isPathWithin(lock.lockedRoot, targetPath)) {
    throw new Error(
      `This MCP install is locked to "${lock.lockedRoot}". ` +
      `Requested path "${path.resolve(targetPath)}" is outside the allowed folder.`,
    );
  }
}

function buildScanMeta(resolvedRoot, includeGlobs, excludeGlobs, maxFiles, matchedLength, scannedLength) {
  return {
    resolvedRoot,
    includeGlobsUsed: includeGlobs,
    excludeGlobsUsed: excludeGlobs,
    maxFiles,
    matchedFiles: matchedLength,
    scannedFiles: scannedLength,
    cappedByMaxFiles: matchedLength > maxFiles,
  };
}

function humanRepoScanSummary(meta, aggregate) {
  const { bySeverity, score, totalIssues } = aggregate.summary;
  const parts = [
    `Scanned ${meta.scannedFiles} file(s) of ${meta.matchedFiles} matched under "${meta.resolvedRoot}".`,
  ];
  if (meta.cappedByMaxFiles) {
    parts.push(`More files matched than maxFiles (${meta.maxFiles}); increase maxFiles for full coverage.`);
  }
  parts.push(
    `Score ${score} — ${totalIssues} issue(s): ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low.`,
  );
  return parts.join(' ');
}

function humanChecklistSummary(meta, aggregate, checklistRows) {
  const passed = checklistRows.filter((c) => c.pass).length;
  const total = checklistRows.length;
  return `${humanRepoScanSummary(meta, aggregate)} Checklist: ${passed}/${total} items pass.`;
}

function flattenRepoFindings(fileResults) {
  return fileResults.flatMap((fr) =>
    (fr.result.findings || []).map((f) => ({
      ...f,
      filePath: fr.filePath,
    })),
  );
}

function pickTopFindings(fileResults, n) {
  const flat = flattenRepoFindings(fileResults);
  flat.sort((a, b) => {
    const da = SEVERITY_ORDER[a.severity] ?? 9;
    const db = SEVERITY_ORDER[b.severity] ?? 9;
    if (da !== db) return da - db;
    return (a.filePath || '').localeCompare(b.filePath || '');
  });
  return flat.slice(0, n).map((f) => ({
    filePath: f.filePath,
    lineNumber: f.lineNumber,
    ruleId: f.ruleId,
    ruleName: f.ruleName,
    severity: f.severity,
    snippetPreview: (f.snippet || '').slice(0, 120),
  }));
}

server.registerTool(
  'health',
  {
    title: 'MCP Health',
    description: 'Server version, rule counts, and workspace path hints (for debugging MCP setup).',
    inputSchema: {
      detail: z.enum(['brief', 'full']).default('brief').describe('brief = smaller JSON for chat'),
    },
  },
  async ({ detail = 'brief' }) => {
    const cwd = process.cwd();
    const detected = detectWorkspacePath();
    const payload = {
      ok: true,
      server: {
        name: 'vibesecur-mcp-server',
        version: mcpPkg.version,
      },
      rules: {
        jsRuleCount: JS_RULES.length,
        pyRuleCount: PY_RULES.length,
        totalRules: JS_RULES.length + PY_RULES.length,
        checklistItems: CHECKLIST.length,
      },
      paths: {
        processCwd: cwd,
        detectedWorkspace: detected,
        detectedIsUserHome: isHomePath(detected),
      },
    };
    if (detail === 'full') {
      payload.envHints = {
        CURSOR_WORKSPACE_PATH: process.env.CURSOR_WORKSPACE_PATH ?? null,
        CURSOR_PROJECT_PATH: process.env.CURSOR_PROJECT_PATH ?? null,
        WORKSPACE_PATH: process.env.WORKSPACE_PATH ?? null,
        INIT_CWD: process.env.INIT_CWD ?? null,
      };
    }
    const text =
      detail === 'full'
        ? JSON.stringify(payload, null, 2)
        : JSON.stringify(
            {
              ok: true,
              version: mcpPkg.version,
              totalRules: JS_RULES.length + PY_RULES.length,
              processCwd: cwd,
              detectedWorkspace: detected,
            },
            null,
            2,
          );
    return {
      content: [{ type: 'text', text }],
      structuredContent: payload,
    };
  },
);

server.registerTool(
  'scanSummary',
  {
    title: 'Scan Summary (chat-sized)',
    description:
      'Scan a repo and return a compact summary: score, counts, top findings — safe to paste in chat.',
    inputSchema: {
      rootPath: z.string().default('.').describe('Repository root'),
      includeGlobs: z.array(z.string()).default(DEFAULT_INCLUDE),
      excludeGlobs: z.array(z.string()).default(DEFAULT_EXCLUDE),
      maxFiles: z.number().int().min(1).max(5000).default(200),
      topFindings: z.number().int().min(1).max(50).default(20),
    },
  },
  async ({
    rootPath,
    includeGlobs = DEFAULT_INCLUDE,
    excludeGlobs = DEFAULT_EXCLUDE,
    maxFiles = 200,
    topFindings = 20,
  }) => {
    try {
      const resolvedRoot = normalizeRootPath(rootPath);
      enforceLockedRootOrThrow(resolvedRoot);
      await ensureDirectory(resolvedRoot);
      const { matchedFiles, limitedFiles, fileResults, aggregate } = await gatherRepoScan(
        resolvedRoot,
        includeGlobs,
        excludeGlobs,
        maxFiles,
      );
      const meta = buildScanMeta(
        resolvedRoot,
        includeGlobs,
        excludeGlobs,
        maxFiles,
        matchedFiles.length,
        limitedFiles.length,
      );
      const humanSummary = humanRepoScanSummary(meta, aggregate);
      const top = pickTopFindings(fileResults, topFindings);
      const checklistPassed = aggregate.checklist.filter((c) => c.pass).length;
      const payload = {
        meta,
        humanSummary,
        summary: aggregate.summary,
        checklist: {
          passed: checklistPassed,
          total: aggregate.checklist.length,
        },
        topFindings: top,
      };
      return {
        content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload,
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `scanSummary failed: ${error.message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  'localScan',
  {
    title: 'Local Security Scan',
    description:
      'Run Vibesecur local rule-engine scan for code input. If VIBESECUR_API_BASE is set, runs through the hosted API (project quota + x-session-id). Otherwise runs fully offline.',
    inputSchema: {
      code: z.string().min(1).max(50000).describe('Source code to scan'),
      lang: z.enum(['js', 'ts', 'py', 'json', 'auto']).default('auto'),
      projectRoot: z
        .string()
        .default('.')
        .describe('Directory used for projectHash quota (defaults to process cwd / ".")'),
    },
  },
  async ({ code, lang = 'auto', projectRoot = '.' }) => {
    try {
      enforceLockedRootOrThrow(projectRoot);
    } catch (error) {
      return {
        content: [{ type: 'text', text: error.message }],
        isError: true,
      };
    }
    const remote = await postRemoteLocalScan({ code, lang, projectRoot, platform: 'mcp' });
    if (!remote.skipped && !remote.ok && remote.status !== 402) {
      return {
        content: [{ type: 'text', text: JSON.stringify(remote.json || { error: 'Remote scan failed' }, null, 2) }],
        isError: true,
      };
    }
    if (!remote.skipped && remote.status === 402) {
      return {
        content: [{ type: 'text', text: JSON.stringify(remote.json, null, 2) }],
        isError: true,
      };
    }
    if (!remote.skipped && remote.ok && remote.json?.success && remote.json?.data) {
      const data = remote.json.data;
      const humanSummary = `${data.verdict || ''} Score ${data.score} (${data.grade}) — ${(data.findings || []).length} finding(s).`;
      const enriched = {
        ...data,
        humanSummary,
        engineVersion: mcpPkg.version,
        quota: remote.json.quota,
        remoteApi: remote.apiBase,
      };
      return {
        content: [{ type: 'text', text: JSON.stringify(enriched, null, 2) }],
        structuredContent: enriched,
      };
    }

    const result = localScan(code, lang);
    const humanSummary = `${result.verdict} Score ${result.score} (${result.grade}) — ${result.findings.length} finding(s).`;
    const enriched = { ...result, humanSummary, engineVersion: mcpPkg.version };
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(enriched, null, 2),
        },
      ],
      structuredContent: enriched,
    };
  },
);

server.registerTool(
  'scanFile',
  {
    title: 'Scan Repository File',
    description: 'Scan a file from disk and return security findings.',
    inputSchema: {
      filePath: z.string().min(1).describe('Absolute or relative file path'),
      lang: z.enum(['js', 'ts', 'py', 'json', 'auto']).default('auto'),
    },
  },
  async ({ filePath, lang = 'auto' }) => {
    try {
      const resolvedPath = path.resolve(filePath);
      enforceLockedRootOrThrow(resolvedPath);
      const code = await fs.readFile(resolvedPath, 'utf8');
      const useLang = lang === 'auto' ? inferLang(resolvedPath) : lang;
      const projectRoot = path.dirname(resolvedPath);
      const remote = await postRemoteLocalScan({
        code,
        lang: useLang,
        projectRoot,
        platform: 'mcp',
      });
      let result;
      if (!remote.skipped && remote.ok && remote.json?.success && remote.json?.data) {
        result = remote.json.data;
      } else if (!remote.skipped && remote.status === 402) {
        return {
          content: [{ type: 'text', text: JSON.stringify(remote.json, null, 2) }],
          isError: true,
        };
      } else if (!remote.skipped && !remote.ok) {
        return {
          content: [{ type: 'text', text: JSON.stringify(remote.json || { error: 'Remote scan failed' }, null, 2) }],
          isError: true,
        };
      } else {
        result = localScan(code, useLang);
      }
      const meta = {
        resolvedPath,
        lang: useLang,
        maxFiles: 1,
        matchedFiles: 1,
        scannedFiles: 1,
        cappedByMaxFiles: false,
        includeGlobsUsed: null,
        excludeGlobsUsed: null,
      };
      const findingsList = result.findings || [];
      const bySeverity = findingsList.reduce(
        (acc, f) => {
          acc[f.severity] = (acc[f.severity] || 0) + 1;
          return acc;
        },
        { critical: 0, high: 0, medium: 0, low: 0 },
      );
      const humanSummary = `File "${resolvedPath}": score ${result.score} (${result.grade}), ${findingsList.length} issue(s) — critical ${bySeverity.critical}, high ${bySeverity.high}, medium ${bySeverity.medium}, low ${bySeverity.low}.`;
      const body = {
        meta,
        humanSummary,
        filePath: resolvedPath,
        lang: useLang,
        score: result.score,
        grade: result.grade,
        findings: findingsList.length,
        bySeverity,
        checklist: result.checklist,
        result,
      };
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(body, null, 2),
          },
        ],
        structuredContent: body,
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Failed to scan file: ${error.message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  'scanRepo',
  {
    title: 'Scan Repository',
    description: 'Scan multiple files in a repo and aggregate findings.',
    inputSchema: {
      rootPath: z.string().default('.').describe('Repository root path (optional, defaults to current process cwd)'),
      includeGlobs: z.array(z.string()).default(DEFAULT_INCLUDE),
      excludeGlobs: z.array(z.string()).default(DEFAULT_EXCLUDE),
      maxFiles: z.number().int().min(1).max(5000).default(300),
    },
  },
  async ({
    rootPath,
    includeGlobs = DEFAULT_INCLUDE,
    excludeGlobs = DEFAULT_EXCLUDE,
    maxFiles = 300,
  }) => {
    try {
      const resolvedRoot = normalizeRootPath(rootPath);
      enforceLockedRootOrThrow(resolvedRoot);
      await ensureDirectory(resolvedRoot);
      const { matchedFiles, limitedFiles, fileResults, aggregate, topRiskFiles } =
        await gatherRepoScan(resolvedRoot, includeGlobs, excludeGlobs, maxFiles);

      const meta = buildScanMeta(
        resolvedRoot,
        includeGlobs,
        excludeGlobs,
        maxFiles,
        matchedFiles.length,
        limitedFiles.length,
      );
      const humanSummary = humanRepoScanSummary(meta, aggregate);
      const body = {
        meta,
        humanSummary,
        rootPath: resolvedRoot,
        scannedFiles: limitedFiles.length,
        matchedFiles: matchedFiles.length,
        cappedByMaxFiles: matchedFiles.length > maxFiles,
        summary: aggregate.summary,
        checklist: aggregate.checklist,
        topRiskFiles,
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(body, null, 2),
          },
        ],
        structuredContent: {
          ...body,
          fileResults,
        },
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Failed to scan repo: ${error.message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  'scanCurrentWorkspace',
  {
    title: 'Scan Current Workspace',
    description:
      'Scan the current workspace path detected from client environment, without requiring rootPath.',
    inputSchema: {
      includeGlobs: z.array(z.string()).default(DEFAULT_INCLUDE),
      excludeGlobs: z.array(z.string()).default(DEFAULT_EXCLUDE),
      maxFiles: z.number().int().min(1).max(5000).default(300),
    },
  },
  async ({
    includeGlobs = DEFAULT_INCLUDE,
    excludeGlobs = DEFAULT_EXCLUDE,
    maxFiles = 300,
  }) => {
    try {
      const resolvedRoot = detectWorkspacePath();
      enforceLockedRootOrThrow(resolvedRoot);
      if (isHomePath(resolvedRoot)) {
        return {
          content: [
            {
              type: 'text',
              text:
                `Could not safely detect a repo workspace path (resolved to home: ${resolvedRoot}). ` +
                'Use scanRepo with an explicit rootPath, e.g. O:\\Octaspace\\Virtual Trail Room.',
            },
          ],
          isError: true,
        };
      }
      await ensureDirectory(resolvedRoot);
      const { matchedFiles, limitedFiles, fileResults, aggregate, topRiskFiles } =
        await gatherRepoScan(resolvedRoot, includeGlobs, excludeGlobs, maxFiles);

      const meta = buildScanMeta(
        resolvedRoot,
        includeGlobs,
        excludeGlobs,
        maxFiles,
        matchedFiles.length,
        limitedFiles.length,
      );
      const humanSummary = humanRepoScanSummary(meta, aggregate);
      const body = {
        meta,
        humanSummary,
        rootPath: resolvedRoot,
        scannedFiles: limitedFiles.length,
        matchedFiles: matchedFiles.length,
        cappedByMaxFiles: matchedFiles.length > maxFiles,
        summary: aggregate.summary,
        checklist: aggregate.checklist,
        topRiskFiles,
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(body, null, 2),
          },
        ],
        structuredContent: {
          ...body,
          fileResults,
        },
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Failed to scan current workspace: ${error.message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  'projectChecklist',
  {
    title: 'Project Checklist',
    description: 'Check repository-wide security checklist status with evidence.',
    inputSchema: {
      rootPath: z.string().default('.').describe('Repository root path (optional, defaults to current process cwd)'),
      includeGlobs: z.array(z.string()).default(DEFAULT_INCLUDE),
      excludeGlobs: z.array(z.string()).default(DEFAULT_EXCLUDE),
      maxFiles: z.number().int().min(1).max(5000).default(300),
    },
  },
  async ({
    rootPath,
    includeGlobs = DEFAULT_INCLUDE,
    excludeGlobs = DEFAULT_EXCLUDE,
    maxFiles = 300,
  }) => {
    try {
      const resolvedRoot = normalizeRootPath(rootPath);
      await ensureDirectory(resolvedRoot);
      const { matchedFiles, limitedFiles, fileResults, aggregate } = await gatherRepoScan(
        resolvedRoot,
        includeGlobs,
        excludeGlobs,
        maxFiles,
      );

      const gitignoreChecks = await readGitignoreChecks(resolvedRoot);

      const checklistWithEvidence = aggregate.checklist.map((item) => {
        if (item.id === 'CL02') {
          return {
            ...item,
            pass: gitignoreChecks.hasEnvPattern,
            evidence: gitignoreChecks,
          };
        }

        const ruleIds = CHECKLIST.find((c) => c.id === item.id)?.ruleIds || [];
        const violations = fileResults.flatMap((fr) =>
          fr.result.findings
            .filter((f) => ruleIds.includes(f.ruleId))
            .map((f) => ({
              filePath: fr.filePath,
              ruleId: f.ruleId,
              ruleName: f.ruleName,
              severity: f.severity,
              lineNumber: f.lineNumber,
            })),
        );

        return {
          ...item,
          pass: violations.length === 0,
          evidence: violations.slice(0, 30),
        };
      });

      const meta = buildScanMeta(
        resolvedRoot,
        includeGlobs,
        excludeGlobs,
        maxFiles,
        matchedFiles.length,
        limitedFiles.length,
      );
      const humanSummary = humanChecklistSummary(meta, aggregate, checklistWithEvidence);

      const body = {
        meta,
        humanSummary,
        rootPath: resolvedRoot,
        scannedFiles: limitedFiles.length,
        matchedFiles: matchedFiles.length,
        summary: aggregate.summary,
        checklist: checklistWithEvidence,
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(body, null, 2),
          },
        ],
        structuredContent: body,
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Failed to evaluate checklist: ${error.message}` }],
        isError: true,
      };
    }
  },
);

server.registerTool(
  'buildClaudePrompt',
  {
    title: 'Build Claude Prompt',
    description: 'Build a Vibesecur prompt for deep AI security analysis.',
    inputSchema: {
      code: z.string().min(1).max(50000).describe('Source code to scan'),
      platform: z.string().min(1).max(50).default('cursor'),
      mode: z.enum(['quick', 'deep', 'supabase', 'ownership']).default('quick'),
      lang: z.enum(['js', 'ts', 'py', 'json', 'auto']).default('auto'),
    },
  },
  async ({ code, platform = 'cursor', mode = 'quick', lang = 'auto' }) => {
    const prompt = buildClaudePrompt(code, platform, mode, lang);
    const meta = {
      platform,
      mode,
      lang,
      codeChars: code.length,
      engineVersion: mcpPkg.version,
    };
    const humanSummary = `Built Claude prompt (${meta.codeChars} chars of code, mode=${mode}, lang=${lang}). Paste into your Anthropic client to run AI analysis.`;
    return {
      content: [
        {
          type: 'text',
          text: prompt,
        },
      ],
      structuredContent: { meta, humanSummary, prompt },
    };
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error('Vibesecur MCP server error:', error);
  process.exit(1);
});
