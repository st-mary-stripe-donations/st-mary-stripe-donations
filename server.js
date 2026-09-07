/**
 * Stripe backend for the JNCC La Gonave donation form.
 *
 * Install:
 *   npm install express stripe
 *
 * Required environment variables:
 *   STRIPE_SECRET_KEY=sk_live_...
 *   STRIPE_PUBLISHABLE_KEY=pk_live_...
 *   ALLOWED_ORIGINS=https://www.jnccfaith.org,https://jnccfaith.org
 *   DONATION_RETURN_URL=https://www.jnccfaith.org/parroise-st.-marie-madleine(-lagonave)
 *
 * Never put STRIPE_SECRET_KEY in the HTML/browser.
 */

const express = require('express');
const Stripe = require('stripe');

const app = express();
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const stripePublishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
const returnUrl = process.env.DONATION_RETURN_URL;
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://www.jnccfaith.org,https://jnccfaith.org')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

if (!stripeSecretKey || !stripePublishableKey || !returnUrl) {
  console.error('Missing STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, or DONATION_RETURN_URL.');
  process.exit(1);
}

const stripe = new Stripe(stripeSecretKey);

app.disable('x-powered-by');
app.use(express.json({ limit: '25kb' }));

// Restrict browser calls to the parish website.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function originAllowed(req) {
  const origin = req.headers.origin;
  // Non-browser server checks can omit Origin; browser requests must match.
  return !origin || allowedOrigins.includes(origin);
}

function buildReturnUrl() {
  const separator = returnUrl.includes('?') ? '&' : '?';
  return `${returnUrl}${separator}donation=success&session_id={CHECKOUT_SESSION_ID}`;
}

app.get('/stripe-config', (req, res) => {
  if (!originAllowed(req)) return res.status(403).json({ error: 'Origin not allowed.' });
  res.json({ publishableKey: stripePublishableKey });
});

app.post('/create-donation-session', async (req, res) => {
  if (!originAllowed(req)) return res.status(403).json({ error: 'Origin not allowed.' });

  try {
    const amount = Number(req.body && req.body.amount);
    const frequency = String((req.body && req.body.frequency) || 'one_time');
    const allowedFrequencies = new Set(['one_time', 'weekly', 'monthly', 'yearly']);

    if (!Number.isFinite(amount) || amount < 1 || amount > 100000) {
      return res.status(400).json({ error: 'Donation amount must be between $1 and $100,000.' });
    }
    if (!allowedFrequencies.has(frequency)) {
      return res.status(400).json({ error: 'Invalid donation frequency.' });
    }

    const amountCents = Math.round(amount * 100);
    const recurringIntervals = {
      weekly: 'week',
      monthly: 'month',
      yearly: 'year'
    };

    const metadata = {
      fund: 'parroise_st_marie_madleine_lagonave',
      campaign: 'La Gonave Children Fund',
      frequency
    };

    const priceData = {
      currency: 'usd',
      unit_amount: amountCents,
      product_data: {
        name: 'La Gonâve Children Fund Donation',
        description: 'Support for the children of Sainte Madeleine Parish in La Gonâve, Haiti.',
        metadata: {
          fund: 'parroise_st_marie_madleine_lagonave'
        }
      }
    };

    const sessionParams = {
      ui_mode: 'elements',
      mode: frequency === 'one_time' ? 'payment' : 'subscription',
      line_items: [{ price_data: priceData, quantity: 1 }],
      payment_method_types: ['card'],
      billing_address_collection: 'auto',
      return_url: buildReturnUrl(),
      metadata
    };

    if (frequency === 'one_time') {
      sessionParams.customer_creation = 'always';
      sessionParams.payment_intent_data = { metadata };
    } else {
      priceData.recurring = {
        interval: recurringIntervals[frequency],
        interval_count: 1
      };
      sessionParams.subscription_data = { metadata };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);
    res.json({ clientSecret: session.client_secret });
  } catch (error) {
    console.error('Stripe session error:', error);
    res.status(500).json({ error: 'Unable to create the secure Stripe donation session.' });
  }
});

app.get('/donation-session-status', async (req, res) => {
  if (!originAllowed(req)) return res.status(403).json({ error: 'Origin not allowed.' });

  try {
    const sessionId = String(req.query.session_id || '');
    if (!sessionId.startsWith('cs_')) return res.status(400).json({ error: 'Invalid session ID.' });

    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['payment_intent', 'subscription']
    });

    res.json({
      status: session.status,
      paymentStatus: session.payment_status,
      mode: session.mode,
      subscriptionStatus: session.subscription && typeof session.subscription !== 'string'
        ? session.subscription.status
        : null
    });
  } catch (error) {
    console.error('Stripe status error:', error);
    res.status(500).json({ error: 'Unable to verify the donation session.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

const port = process.env.PORT || 4242;
app.listen(port, () => console.log(`Stripe donation backend listening on port ${port}`));
