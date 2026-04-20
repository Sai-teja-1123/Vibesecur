// ── Score Calculation ────────────────────────────────────────────────────────
export function calculateScore(findings) {
  const WEIGHTS = { critical: 20, high: 10, medium: 5, low: 2 };
  let score = 100;
  for (const f of findings) score -= (WEIGHTS[f.severity] || 2);
  const cats = new Set(findings.map(f => f.category));
  if (cats.size >= 4) score -= 5;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function getGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function getVerdict(score) {
  if (score >= 80) return '✅ Safe to Deploy';
  if (score >= 60) return '⚠️ Review Before Deploy';
  return '🚫 Critical Issues — Do Not Ship';
}
