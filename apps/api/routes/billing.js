// ============================================================
//  Vibesecur — routes/billing.js
// ============================================================
import { Router } from 'express';
import Stripe from 'stripe';
import { requireAuth } from '../middleware/auth.js';
import { query } from '../utils/db.js';

const router  = Router();
const stripeSecret = process.env.STRIPE_SECRET_KEY;
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
const billingEnabled = Boolean(stripeSecret && stripeWebhookSecret);
const stripe = billingEnabled ? new Stripe(stripeSecret) : null;

const ensureBillingEnabled = (res) => {
  if (billingEnabled) return true;
  res.status(503).json({
    success: false,
    error: 'Billing is not configured yet',
    code: 'BILLING_DISABLED',
  });
  return false;
};

const PLANS = {
  free:  { name:'Free',  price:0,    scans:10,   features:['10 scans/month','Local engine','Basic checklist'] },
  solo:  { name:'Solo',  price:900,  scans:-1,   features:['Unlimited scans','Claude AI','IP Passport 1/mo','All MCP tools'] },
  pro:   { name:'Pro',   price:2900, scans:-1,   features:['5 projects','Everything in Solo','Watermarking','Investor PDF report','Team access'] },
};

router.get('/plans', (_req,res) => res.json({ success:true, data:{ plans: PLANS }}));

router.get('/status', requireAuth, async (req,res,next) => {
  try {
    const r = await query(
      'SELECT plan, stripe_subscription_id, scan_count_today, scan_count_total FROM users WHERE id=$1',
      [req.user.id]
    );
    res.json({ success:true, data:{ billing: r.rows[0] }});
  } catch(err){ next(err); }
});

router.post('/checkout', requireAuth, async (req,res,next) => {
  try {
    if (!ensureBillingEnabled(res)) return;
    const { plan } = req.body;
    if (!['solo','pro'].includes(plan)) return res.status(400).json({ success:false, error:'Invalid plan' });

    const user = await query('SELECT email, stripe_customer_id FROM users WHERE id=$1', [req.user.id]);
    let customerId = user.rows[0].stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.rows[0].email, metadata:{ vibesecur_id: req.user.id }});
      customerId = customer.id;
      await query('UPDATE users SET stripe_customer_id=$1 WHERE id=$2', [customerId, req.user.id]);
    }

    const priceId = plan === 'solo' ? process.env.STRIPE_PRICE_SOLO : process.env.STRIPE_PRICE_PRO;
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: priceId, quantity:1 }],
      success_url: `${process.env.CORS_ORIGIN}/upgrade-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.CORS_ORIGIN}/pricing`,
    });
    res.json({ success:true, data:{ url: session.url }});
  } catch(err){ next(err); }
});

router.post('/webhook', async (req,res,next) => {
  try {
    if (!ensureBillingEnabled(res)) return;
    const sig   = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.body, sig, stripeWebhookSecret);

    if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.created') {
      const sub  = event.data.object;
      const plan = sub.items.data[0]?.price?.id === process.env.STRIPE_PRICE_PRO ? 'pro' : 'solo';
      await query(
        'UPDATE users SET plan=$1, stripe_subscription_id=$2 WHERE stripe_customer_id=$3',
        [plan, sub.id, sub.customer]
      );
    }
    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      await query('UPDATE users SET plan=\'free\', stripe_subscription_id=NULL WHERE stripe_customer_id=$1', [sub.customer]);
    }
    res.json({ received:true });
  } catch(err){ res.status(400).json({ error: err.message }); }
});

export default router;
