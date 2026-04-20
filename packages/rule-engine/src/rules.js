// ── Rule Definitions ────────────────────────────────────────────────────────
export const JS_RULES = [
  // Secrets
  { id:'S001', name:'Hardcoded API Key',        sev:'critical', re:/api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,           fix:'Move to .env: process.env.API_KEY',                   cat:'Secrets' },
  { id:'S002', name:'Hardcoded Password',       sev:'critical', re:/password\s*[:=]\s*['"][^'"]{4,}['"]/gi,                          fix:'Use env var: process.env.PASSWORD',                   cat:'Secrets' },
  { id:'S003', name:'JWT Secret Hardcoded',     sev:'critical', re:/jwt[_-]?secret\s*[:=]\s*['"][^'"]{6,}['"]/gi,                   fix:'Move to .env: JWT_SECRET=...',                        cat:'Secrets' },
  { id:'S004', name:'Database URL Exposed',     sev:'critical', re:/(mongodb|mysql|postgres|supabase):\/\/[^\s'"]{8,}/gi,            fix:'Move to .env: DATABASE_URL=...',                      cat:'Secrets' },
  { id:'S005', name:'AWS Access Key',           sev:'critical', re:/AKIA[0-9A-Z]{16}/g,                                             fix:'Rotate immediately. Use IAM roles.',                  cat:'Secrets' },
  { id:'S006', name:'Stripe Key Exposed',       sev:'critical', re:/(sk_live|sk_test)_[a-zA-Z0-9]{20,}/g,                           fix:'Move to .env: STRIPE_SECRET_KEY=...',                 cat:'Secrets' },
  { id:'S007', name:'Private Key in Code',      sev:'critical', re:/-----BEGIN[A-Z ]*PRIVATE KEY-----/g,                            fix:'Never commit private keys. Use a secrets manager.',   cat:'Secrets' },
  // Auth
  { id:'A001', name:'MD5 Password Hashing',     sev:'critical', re:/md5\s*\(/gi,                                                    fix:'Use bcrypt: await bcrypt.hash(password, 12)',          cat:'Auth'    },
  { id:'A002', name:'SHA1 Password Hashing',    sev:'critical', re:/sha1\s*\(/gi,                                                   fix:'Use bcrypt or argon2 for passwords',                  cat:'Auth'    },
  { id:'A003', name:'JWT Without Expiry',       sev:'critical', re:/jwt\.sign\s*\([^)]{0,200}\)/g,                                  fix:'Add: { expiresIn: "1h" }',                            cat:'Auth'    },
  { id:'A004', name:'eval() Usage',             sev:'critical', re:/\beval\s*\(/g,                                                  fix:'Never use eval() — arbitrary code execution',         cat:'Injection'},
  { id:'A005', name:'SQL Injection Risk',       sev:'critical', re:/(SELECT|INSERT|UPDATE|DELETE)[^;]{0,80}\+\s*(req\.|user\.)/gi,  fix:'Use parameterized queries: db.query("?", [val])',      cat:'Injection'},
  { id:'A006', name:'Wildcard CORS',            sev:'critical', re:/origin\s*:\s*['"]\*['"]/gi,                                     fix:'cors({ origin: process.env.ALLOWED_ORIGIN })',        cat:'CORS'    },
  { id:'A007', name:'Missing Rate Limit',       sev:'high',     re:/app\.(post|put)\s*\(['"]\/(login|auth|register)/gi,             fix:'Add rateLimit({ windowMs:900000, max:5 }) middleware', cat:'Auth'    },
  // RLS / Firebase
  { id:'RLS1', name:'Supabase — Missing RLS',   sev:'critical', re:/supabase\.from\(['"`][^'"`]+['"`]\)\.(select|insert|update|delete)/gi, fix:'ENABLE ROW LEVEL SECURITY on this table',     cat:'RLS'     },
  { id:'RLS2', name:'Supabase Service Key FE',  sev:'critical', re:/service_role|supabase_service/gi,                              fix:'Service key must be server-side only — never in browser',cat:'RLS'  },
  { id:'RLS3', name:'Firebase Open Rules',      sev:'critical', re:/allow read, write:\s*if true/gi,                               fix:'Restrict: allow read if request.auth != null',         cat:'RLS'     },
  // Exposure
  { id:'E001', name:'Credentials in Logs',      sev:'high',     re:/console\.log\(.*?(password|token|secret|key)/gi,               fix:'Remove console.log with sensitive data',               cat:'Exposure'},
  { id:'E002', name:'Debug Mode On',            sev:'high',     re:/debug\s*[:=]\s*true/gi,                                         fix:'Set debug: false in production',                      cat:'Exposure'},
  { id:'E003', name:'Stack Trace Exposed',      sev:'high',     re:/res\.(send|json)\(.*?err\.(stack|message)/gi,                   fix:'return { error: "Server error" } only',               cat:'Exposure'},
  { id:'E004', name:'TODO Security Note',       sev:'medium',   re:/\/\/\s*(TODO|FIXME).*?(auth|security|password|token)/gi,       fix:'Resolve all security TODOs before deploy',            cat:'Exposure'},
  { id:'E005', name:'Sensitive GET Params',     sev:'medium',   re:/\?.*?(token|password|secret|key)=/gi,                          fix:'Use POST body — never sensitive data in URL params',   cat:'Exposure'},
];

export const PY_RULES = [
  { id:'P001', name:'Python eval()',            sev:'critical', re:/\beval\s*\(/g,                                                   fix:'Never use eval() — arbitrary code execution',         cat:'Injection'},
  { id:'P002', name:'Python pickle.loads()',    sev:'critical', re:/pickle\.loads?\s*\(/g,                                          fix:'Never unpickle untrusted data — use JSON',            cat:'Injection'},
  { id:'P003', name:'Python SQL Concatenation', sev:'critical', re:/cursor\.execute\s*\([^)]*%\s*|f"SELECT.*\{/gi,                  fix:'Use parameterized queries: cursor.execute("?", (v,))', cat:'Injection'},
  { id:'P004', name:'Python Hardcoded Secret',  sev:'critical', re:/(password|api_key|secret|token)\s*=\s*['"][^'"]{6,}['"]/gi,    fix:'Use os.environ.get("SECRET")',                        cat:'Secrets' },
  { id:'P005', name:'Python subprocess shell',  sev:'high',     re:/subprocess\.[^(]+\([^)]*shell\s*=\s*True/gi,                   fix:'Avoid shell=True — use list args',                    cat:'Injection'},
  { id:'P006', name:'Python MD5 Passwords',     sev:'critical', re:/hashlib\.(md5|sha1)/gi,                                         fix:'Use bcrypt or argon2-cffi for passwords',             cat:'Auth'    },
  { id:'P007', name:'Python DEBUG=True',        sev:'high',     re:/DEBUG\s*=\s*True/g,                                             fix:'Set DEBUG=False in production settings',              cat:'Exposure'},
  { id:'P008', name:'Python Open Redirect',     sev:'medium',   re:/redirect\s*\([^)]*request\.(args|form|params)/gi,              fix:'Validate redirect URLs against allowlist',            cat:'Auth'    },
  { id:'P009', name:'Python SSRF Risk',         sev:'high',     re:/requests\.(get|post)\s*\([^)]*request\./gi,                    fix:'Validate and allowlist URLs before fetching',         cat:'SSRF'    },
];

export const CHECKLIST = [
  { id:'CL01', item:'No API keys hardcoded',          critical:true,  ruleIds:['S001','S002','S003','S005','S006','P004'] },
  { id:'CL02', item:'.env in .gitignore',             critical:true,  ruleIds:[] },
  { id:'CL03', item:'bcrypt/argon2 for passwords',    critical:true,  ruleIds:['A001','A002','P006'] },
  { id:'CL04', item:'JWT expiry set',                 critical:true,  ruleIds:['A003'] },
  { id:'CL05', item:'Rate limiting on auth routes',   critical:true,  ruleIds:['A007'] },
  { id:'CL06', item:'CORS restricted',                critical:true,  ruleIds:['A006'] },
  { id:'CL07', item:'No SQL injection patterns',      critical:true,  ruleIds:['A005','P003'] },
  { id:'CL08', item:'Supabase RLS enabled',           critical:true,  ruleIds:['RLS1','RLS2'] },
  { id:'CL09', item:'Firebase rules restricted',      critical:false, ruleIds:['RLS3'] },
  { id:'CL10', item:'No stack traces exposed',        critical:false, ruleIds:['E003'] },
  { id:'CL11', item:'eval() not used',                critical:true,  ruleIds:['A004','P001','P002'] },
  { id:'CL12', item:'No debug mode in production',    critical:false, ruleIds:['E002','P007'] },
];
