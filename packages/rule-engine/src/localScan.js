import crypto from 'crypto';
import { JS_RULES, PY_RULES, CHECKLIST } from './rules.js';
import { calculateScore, getGrade, getVerdict } from './score.js';

// ── Main Local Scan ──────────────────────────────────────────────────────────
export function localScan(code, lang = 'js') {
  const rules = lang === 'py'
    ? PY_RULES
    : lang === 'auto'
      ? [...JS_RULES, ...PY_RULES]
      : JS_RULES;

  const findings = [];

  for (const rule of rules) {
    const matches = [...code.matchAll(rule.re)];
    for (const match of matches) {
      const lineNumber = code.substring(0, match.index).split('\n').length;
      const snippet = match[0].substring(0, 80) + (match[0].length > 80 ? '...' : '');
      findings.push({
        ruleId:      rule.id,
        ruleName:    rule.name,
        severity:    rule.sev,
        category:    rule.cat,
        lineNumber,
        snippet,
        fix:         rule.fix,
      });
    }
  }

  const score     = calculateScore(findings);
  const grade     = getGrade(score);
  const verdict   = getVerdict(score);
  const codeHash  = crypto.createHash('sha256').update(code).digest('hex');

  const checklist = CHECKLIST.map(cl => ({
    ...cl,
    pass: !cl.ruleIds.some(rid => findings.find(f => f.ruleId === rid)),
  }));

  return {
    score,
    grade,
    verdict,
    findings,
    checklist,
    codeHash,
    linesAnalysed: code.split('\n').length,
    engine: 'local',
    summary: `Local engine found ${findings.length} issue${findings.length !== 1 ? 's' : ''}. ${
      findings.length === 0
        ? 'No common vibe coding vulnerabilities detected.'
        : 'Fix critical items before deploying to production.'
    }`,
  };
}
