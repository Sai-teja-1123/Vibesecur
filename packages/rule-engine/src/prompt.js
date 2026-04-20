// ── Claude AI Prompt Builder ─────────────────────────────────────────────────
export function buildClaudePrompt(code, platform, mode, lang) {
  const isSupabase = mode === 'supabase' || code.toLowerCase().includes('supabase');
  const isPython   = lang === 'py' || code.includes('import os') || code.includes('def ');
  const deepMode   = mode === 'deep' ? 'DEEP MODE: find subtle and complex issues.' : '';
  const sbMode     = isSupabase ? 'Focus especially on Supabase RLS policies and service key exposure.' : '';

  return `You are Vibesecur, an expert AI security scanner for AI-generated code. Analyse this ${lang.toUpperCase()} code from ${platform}.
Return ONLY valid JSON — no markdown, no explanation, no backticks.

\`\`\`${lang}
${code.substring(0, 8000)}
\`\`\`

Return exactly this JSON structure:
{
  "score": <0-100>,
  "grade": "<A|B|C|D|F>",
  "verdict": "<one sentence>",
  "summary": "<2-3 sentences about this specific codebase's risk profile>",
  "findings": [
    {
      "ruleId": "<S001|RLS1|P001 etc>",
      "ruleName": "<descriptive name>",
      "severity": "<critical|high|medium|low>",
      "lineNumber": <integer or null>,
      "category": "<Secrets|Auth|Injection|CORS|RLS|Exposure|Python|SSRF>",
      "description": "<what was found — be specific>",
      "fix": "<exact actionable code fix>"
    }
  ],
  "checklist": [
    {"id":"CL01","item":"No API keys hardcoded","critical":true,"pass":<bool>},
    {"id":"CL02","item":".env in .gitignore","critical":true,"pass":<bool>},
    {"id":"CL03","item":"bcrypt/argon2 for passwords","critical":true,"pass":<bool>},
    {"id":"CL04","item":"JWT expiry set","critical":true,"pass":<bool>},
    {"id":"CL05","item":"Rate limiting on auth","critical":true,"pass":<bool>},
    {"id":"CL06","item":"CORS restricted","critical":true,"pass":<bool>},
    {"id":"CL07","item":"No SQL injection","critical":true,"pass":<bool>},
    {"id":"CL08","item":"Supabase RLS enabled","critical":${isSupabase},"pass":<bool>},
    {"id":"CL09","item":"Firebase rules restricted","critical":false,"pass":<bool>},
    {"id":"CL10","item":"No stack traces","critical":false,"pass":<bool>},
    {"id":"CL11","item":"eval() not used","critical":true,"pass":<bool>},
    {"id":"CL12","item":"No debug mode","critical":false,"pass":<bool>}
  ],
  "aiInsight": "<3-4 sentences of specific insight about this codebase's security posture>",
  "envVars": ["<VAR_NAME: what it replaces>"],
  "policies": ["<specific action: exact detail>"]
}

Scoring: start 100, subtract 20 per critical, 10 per high, 5 per medium. ${deepMode} ${sbMode}
Be specific about ${isPython ? 'Python eval/pickle/subprocess patterns' : 'auth patterns and Supabase RLS'}.`;
}
