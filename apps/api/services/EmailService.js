// ============================================================
//  Vibesecur — services/EmailService.js
// ============================================================
export async function sendWelcomeEmail(email) {
  if (!process.env.RESEND_API_KEY) return; // Skip in dev
  const { Resend } = await import('resend');
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from:    process.env.FROM_EMAIL || 'hello@vibesecur.dev',
    to:      email,
    subject: '🛡 Welcome to Vibesecur — your code is safer already',
    html: `
      <div style="font-family:monospace;background:#07090E;color:#B0B8CC;padding:32px;border-radius:12px;max-width:560px">
        <h1 style="color:#00F5A8;margin-bottom:8px">Welcome to Vibesecur 🛡</h1>
        <p style="color:#B0B8CC">Your account is ready. Here's how to get started:</p>
        <ol style="color:#B0B8CC;line-height:1.8">
          <li>Open the <a href="${process.env.CORS_ORIGIN}/scanner" style="color:#00C8FF">Web Scanner</a> and paste your code</li>
          <li>Install the <a href="${process.env.CORS_ORIGIN}/mcp" style="color:#00C8FF">MCP Server</a> for Cursor (3-min setup)</li>
          <li>Get your first <a href="${process.env.CORS_ORIGIN}/passport" style="color:#00C8FF">IP Passport</a> for investor due diligence</li>
        </ol>
        <p style="color:#4A5270;font-size:12px;margin-top:24px">Your code is never stored. Zero data. Always.</p>
      </div>
    `,
  });
}
