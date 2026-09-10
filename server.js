/**
 * St. Mary / JNCC Stripe backend
 * - Existing La Gonâve donation endpoints are preserved.
 * - Event-space reservation workflow adds:
 *   $50 deposit, saved off-session payment method, staff availability approval,
 *   dynamic reservation-fee charge ($300 first day + $100/additional day), cancellation, and approved $50 refund.
 */
const express = require('express');
const Stripe = require('stripe');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { Pool } = require('pg');
const { DateTime } = require('luxon');

const app = express();
app.disable('x-powered-by');

const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const stripePublishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
const donationReturnUrl = process.env.DONATION_RETURN_URL;
const reservationReturnUrl = process.env.RESERVATION_RETURN_URL || 'https://www.jnccfaith.org/event-space-reservation';
const databaseUrl = process.env.DATABASE_URL || process.env.DATABASE_POSTGRES_URL;
const actionSecret = process.env.ACTION_SECRET;
const cronSecret = process.env.CRON_SECRET;
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
const staffEmail = process.env.STAFF_EMAIL || 'jnccfaithnorwichct@gmail.com';
const mailFrom = process.env.MAIL_FROM || 'Joint Norwich Catholic Cluster <jnccfaithnorwichct@gmail.com>';
const publicBackendUrl = (process.env.PUBLIC_BACKEND_URL || 'https://st-mary-stripe-donations.vercel.app').replace(/\/$/, '');
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://www.jnccfaith.org,https://jnccfaith.org')
  .split(',').map(v => v.trim()).filter(Boolean);

if (!stripeSecretKey || !stripePublishableKey || !databaseUrl || !actionSecret) {
  console.error('Missing required STRIPE keys, DATABASE_URL, or ACTION_SECRET.');
  process.exit(1);
}

const stripe = new Stripe(stripeSecretKey);
const pool = new Pool({
  connectionString: databaseUrl,
  max: 4,
  ssl: /localhost|127\.0\.0\.1/.test(databaseUrl) ? false : { rejectUnauthorized: false }
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true',
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
});

let schemaPromise;
function ensureSchema() {
  if (!schemaPromise) {
    schemaPromise = pool.query(`
      CREATE TABLE IF NOT EXISTS reservations (
        id UUID PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        location TEXT NOT NULL,
        event_type TEXT NOT NULL,
        guest_count INTEGER NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        reservation_occurrences JSONB NOT NULL DEFAULT '[]'::jsonb,
        reserved_day_count INTEGER NOT NULL DEFAULT 1,
        reservation_fee_cents INTEGER NOT NULL DEFAULT 30000,
        event_start_at TIMESTAMPTZ NOT NULL,
        event_end_at TIMESTAMPTZ NOT NULL,
        additional_info TEXT,
        authorization_accepted BOOLEAN NOT NULL DEFAULT FALSE,
        status TEXT NOT NULL DEFAULT 'pending_deposit',
        stripe_checkout_session_id TEXT UNIQUE,
        stripe_customer_id TEXT,
        stripe_payment_method_id TEXT,
        deposit_payment_intent_id TEXT,
        deposit_paid_at TIMESTAMPTZ,
        availability_confirmed_at TIMESTAMPTZ,
        balance_charge_at TIMESTAMPTZ,
        balance_payment_intent_id TEXT,
        balance_paid_at TIMESTAMPTZ,
        canceled_at TIMESTAMPTZ,
        cancellation_reason TEXT,
        charge_failure_at TIMESTAMPTZ,
        charge_failure_message TEXT,
        deposit_refund_id TEXT,
        deposit_refunded_at TIMESTAMPTZ,
        request_emails_sent_at TIMESTAMPTZ,
        refund_approval_sent_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      ALTER TABLE reservations ADD COLUMN IF NOT EXISTS reservation_occurrences JSONB NOT NULL DEFAULT '[]'::jsonb;
      ALTER TABLE reservations ADD COLUMN IF NOT EXISTS reserved_day_count INTEGER NOT NULL DEFAULT 1;
      ALTER TABLE reservations ADD COLUMN IF NOT EXISTS reservation_fee_cents INTEGER NOT NULL DEFAULT 30000;
      CREATE INDEX IF NOT EXISTS reservations_due_balance_idx ON reservations(status, balance_charge_at);
      CREATE INDEX IF NOT EXISTS reservations_refund_review_idx ON reservations(event_end_at, deposit_refunded_at);
    `);
  }
  return schemaPromise;
}

// Stripe webhook MUST receive the untouched raw request body.
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripeWebhookSecret) return res.status(500).send('Webhook secret is not configured.');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], stripeWebhookSecret);
  } catch (err) {
    console.error('Stripe webhook signature error:', err.message);
    return res.status(400).send('Invalid webhook signature.');
  }

  try {
    await ensureSchema();
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      if (session.metadata && session.metadata.workflow === 'event_space_reservation') {
        await finalizeDepositSession(session.id);
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Stripe webhook processing error:', err);
    res.status(500).json({ error: 'Webhook processing failed.' });
  }
});

app.use(express.json({ limit: '35kb' }));

// CORS for browser calls from the parish website.
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
  return !origin || allowedOrigins.includes(origin);
}
function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
function clean(value, max = 500) { return String(value == null ? '' : value).trim().slice(0, max); }
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function money(cents) { return '$' + (Number(cents || 0) / 100).toFixed(2); }
function reservationFeeCents(dayCount) {
  const days = Math.max(1, Number(dayCount || 1));
  return 30000 + Math.max(0, days - 1) * 10000;
}
function parseReservationOccurrences(value) {
  if (!Array.isArray(value) || !value.length) throw new Error('Please select at least one reservation date.');
  if (value.length > 366) throw new Error('A reservation can include up to 366 selected dates.');
  const today = DateTime.now().setZone('America/New_York').startOf('day');
  const seenDates = new Set();
  const occurrences = [];
  for (const raw of value) {
    const date = clean(raw && raw.date, 10);
    const startTime = clean(raw && raw.startTime, 5);
    const endTime = clean(raw && raw.endTime, 5);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{2}:\d{2}$/.test(startTime) || !/^\d{2}:\d{2}$/.test(endTime)) {
      throw new Error('Each selected date must include a valid date, start time, and end time.');
    }
    if (seenDates.has(date)) throw new Error(`The date ${date} was selected more than once. Please use one time range per reserved day.`);
    const start = DateTime.fromISO(`${date}T${startTime}`, { zone: 'America/New_York' });
    const end = DateTime.fromISO(`${date}T${endTime}`, { zone: 'America/New_York' });
    if (!start.isValid || !end.isValid || end <= start) throw new Error(`Please enter a valid start and end time for ${date}.`);
    if (start.startOf('day') < today) throw new Error('All reservation dates must be today or later.');
    seenDates.add(date);
    occurrences.push({ date, startTime, endTime, startAt: start, endAt: end });
  }
  occurrences.sort((a, b) => a.startAt.toMillis() - b.startAt.toMillis());
  return occurrences;
}
function getReservationOccurrences(r) {
  let items = r && r.reservation_occurrences;
  if (typeof items === 'string') { try { items = JSON.parse(items); } catch (_) { items = []; } }
  if (Array.isArray(items) && items.length) {
    return items.map(o => ({ date: String(o.date || ''), startTime: String(o.startTime || ''), endTime: String(o.endTime || '') }))
      .filter(o => o.date && o.startTime && o.endTime);
  }
  if (r && r.start_date && r.start_time) {
    return [{ date: String(r.start_date).slice(0, 10), startTime: String(r.start_time).slice(0, 5), endTime: String(r.end_time || '').slice(0, 5) }];
  }
  return [];
}
function scheduleHtml(r) {
  const items = getReservationOccurrences(r);
  if (!items.length) return 'No schedule available';
  return '<ol style="margin:0;padding-left:20px">' + items.map(o => `<li style="margin:0 0 5px">${escapeHtml(formatDate(o.date))} &mdash; ${escapeHtml(formatTime(o.startTime))} to ${escapeHtml(formatTime(o.endTime))}</li>`).join('') + '</ol>';
}
function feeForReservation(r) { return Number(r && r.reservation_fee_cents) || reservationFeeCents(r && r.reserved_day_count); }
function base64urlJson(obj) { return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
function signToken(payload) {
  const body = base64urlJson(payload);
  const sig = crypto.createHmac('sha256', actionSecret).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function createActionToken(reservationId, scope, days = 180) {
  return signToken({ reservationId, scope, exp: Date.now() + days * 86400000 });
}
function verifyActionToken(token, expectedScope) {
  if (!token || !token.includes('.')) throw new Error('Invalid token.');
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', actionSecret).update(body).digest('base64url');
  const a = Buffer.from(sig); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) throw new Error('Invalid token.');
  const payload = JSON.parse(Buffer.from(body,'base64url').toString('utf8'));
  if (payload.scope !== expectedScope || Number(payload.exp) < Date.now()) throw new Error('Expired or invalid token.');
  return payload;
}
function htmlButton(url, label, color = '#173f5f') {
  return `<a href="${escapeHtml(url)}" style="display:inline-block;background:${color};color:#fff;text-decoration:none;padding:12px 18px;border-radius:7px;font-weight:700;margin:6px 6px 6px 0">${escapeHtml(label)}</a>`;
}
function reservationRows(r) {
  const days = Number(r.reserved_day_count || getReservationOccurrences(r).length || 1);
  return `
    <table style="border-collapse:collapse;width:100%;max-width:680px">
      ${row('Reservation ID', r.id)}
      ${row('Name', `${r.first_name} ${r.last_name}`)}
      ${row('Email', r.email)}
      ${row('Phone', r.phone)}
      ${row('Parish Hall', r.location)}
      ${row('Event Type', r.event_type)}
      ${row('Estimated Guests', r.guest_count)}
      ${row('Reserved Days', days)}
      ${rowHtml('Reservation Schedule', scheduleHtml(r))}
      ${row('Reservation Fee', `${money(feeForReservation(r))} ($300 first day + $100 each additional day)`)}
      ${row('Additional Information', r.additional_info || 'None')}
    </table>`;
}
function rowHtml(label, html) {
  return `<tr><td style="padding:8px;border:1px solid #ddd;font-weight:700;background:#f6f8fa;vertical-align:top">${escapeHtml(label)}</td><td style="padding:8px;border:1px solid #ddd">${html}</td></tr>`;
}
function row(label, value) {
  return `<tr><td style="padding:8px;border:1px solid #ddd;font-weight:700;background:#f6f8fa;vertical-align:top">${escapeHtml(label)}</td><td style="padding:8px;border:1px solid #ddd">${escapeHtml(value)}</td></tr>`;
}
function formatDate(value) {
  if (!value) return '';
  const raw = String(value);
  // PostgreSQL DATE values are calendar dates, not UTC timestamps. Parse them in
  // the parish timezone so a YYYY-MM-DD date never renders as the previous day.
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const localDate = DateTime.fromISO(raw, { zone: 'America/New_York' });
    return localDate.isValid ? localDate.toFormat('LLLL d, yyyy') : raw;
  }
  const d = value instanceof Date
    ? DateTime.fromJSDate(value, { zone: 'America/New_York' })
    : DateTime.fromISO(raw, { zone: 'America/New_York' });
  return d.isValid ? d.toFormat('LLLL d, yyyy') : raw.slice(0, 10);
}
function formatTime(value) {
  const s = String(value || '').slice(0,5);
  const d = DateTime.fromFormat(s,'HH:mm');
  return d.isValid ? d.toFormat('h:mm a') : s;
}
async function sendMail({to, subject, html, replyTo}) {
  if (!process.env.SMTP_HOST) throw new Error('SMTP_HOST is not configured.');
  const recipients = (Array.isArray(to) ? to : [to])
    .map(value => String(value || '').toLowerCase());
  const bccStaff = recipients.includes(String(staffEmail).toLowerCase()) ? undefined : staffEmail;
  return transporter.sendMail({ from: mailFrom, to, bcc: bccStaff, replyTo, subject, html });
}
function buildDonationReturnUrl() {
  if (!donationReturnUrl) return null;
  const separator = donationReturnUrl.includes('?') ? '&' : '?';
  return `${donationReturnUrl}${separator}donation=success&session_id={CHECKOUT_SESSION_ID}`;
}
function buildReservationReturnUrl() {
  const separator = reservationReturnUrl.includes('?') ? '&' : '?';
  return `${reservationReturnUrl}${separator}reservation=success&session_id={CHECKOUT_SESSION_ID}`;
}

app.get('/stripe-config', (req,res) => {
  if (!originAllowed(req)) return res.status(403).json({error:'Origin not allowed.'});
  res.json({ publishableKey: stripePublishableKey });
});

// ----------------------------
// EXISTING DONATION ENDPOINTS
// ----------------------------
app.post('/create-donation-session', async (req, res) => {
  if (!originAllowed(req)) return res.status(403).json({ error: 'Origin not allowed.' });
  if (!donationReturnUrl) return res.status(500).json({ error: 'Donation return URL is not configured.' });
  try {
    const amount = Number(req.body && req.body.amount);
    const frequency = String((req.body && req.body.frequency) || 'one_time');
    const allowedFrequencies = new Set(['one_time','weekly','monthly','yearly']);
    if (!Number.isFinite(amount) || amount < 1 || amount > 100000) return res.status(400).json({ error:'Donation amount must be between $1 and $100,000.' });
    if (!allowedFrequencies.has(frequency)) return res.status(400).json({ error:'Invalid donation frequency.' });
    const amountCents = Math.round(amount * 100);
    const recurringIntervals = { weekly:'week', monthly:'month', yearly:'year' };
    const metadata = { fund:'parroise_st_marie_madleine_lagonave', campaign:'La Gonave Children Fund', frequency };
    const priceData = { currency:'usd', unit_amount:amountCents, product_data:{ name:'La Gonâve Children Fund Donation', description:'Support for the children of Sainte Madeleine Parish in La Gonâve, Haiti.', metadata:{ fund:'parroise_st_marie_madleine_lagonave' } } };
    const sessionParams = { ui_mode:'embedded', mode:frequency === 'one_time' ? 'payment' : 'subscription', line_items:[{price_data:priceData,quantity:1}], payment_method_types:['card'], billing_address_collection:'auto', return_url:buildDonationReturnUrl(), redirect_on_completion:'always', metadata };
    if (frequency === 'one_time') { sessionParams.customer_creation='always'; sessionParams.payment_intent_data={metadata}; }
    else { priceData.recurring={interval:recurringIntervals[frequency],interval_count:1}; sessionParams.subscription_data={metadata}; }
    const session = await stripe.checkout.sessions.create(sessionParams);
    res.json({ clientSecret:session.client_secret });
  } catch (error) { console.error('Stripe donation session error:',error); res.status(500).json({error:'Unable to create the secure Stripe donation session.'}); }
});

app.get('/donation-session-status', async (req,res) => {
  if (!originAllowed(req)) return res.status(403).json({error:'Origin not allowed.'});
  try {
    const sessionId=String(req.query.session_id||'');
    if (!sessionId.startsWith('cs_')) return res.status(400).json({error:'Invalid session ID.'});
    const session=await stripe.checkout.sessions.retrieve(sessionId,{expand:['payment_intent','subscription']});
    res.json({status:session.status,paymentStatus:session.payment_status,mode:session.mode,subscriptionStatus:session.subscription && typeof session.subscription !== 'string' ? session.subscription.status : null});
  } catch(error){console.error('Stripe donation status error:',error);res.status(500).json({error:'Unable to verify the donation session.'});}
});

// ----------------------------
// RESERVATION / $50 DEPOSIT
// ----------------------------
app.post('/create-reservation-session', async (req,res) => {
  if (!originAllowed(req)) return res.status(403).json({error:'Origin not allowed.'});
  try {
    await ensureSchema();
    const data = {
      firstName: clean(req.body.firstName,100), lastName: clean(req.body.lastName,100), email: clean(req.body.email,250).toLowerCase(), phone: clean(req.body.phone,80),
      location: clean(req.body.location,150), eventType: clean(req.body.eventType,120), guestCount: Number(req.body.guestCount),
      additionalInfo: clean(req.body.additionalInfo,3000), authorization: req.body.authorization === true
    };
    if (!data.firstName || !data.lastName || !validEmail(data.email) || !data.phone || !data.location || !data.eventType || !Number.isInteger(data.guestCount) || data.guestCount < 1 || !data.authorization) {
      return res.status(400).json({error:'Please complete all required reservation fields and accept the payment authorization.'});
    }
    let occurrences;
    try { occurrences = parseReservationOccurrences(req.body.occurrences); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const firstOccurrence = occurrences[0];
    const lastOccurrence = occurrences[occurrences.length - 1];
    const dayCount = occurrences.length;
    const feeCents = reservationFeeCents(dayCount);
    const storedOccurrences = occurrences.map(o => ({ date:o.date, startTime:o.startTime, endTime:o.endTime }));

    const id = crypto.randomUUID();
    await pool.query(`INSERT INTO reservations
      (id,first_name,last_name,email,phone,location,event_type,guest_count,start_date,end_date,start_time,end_time,reservation_occurrences,reserved_day_count,reservation_fee_cents,event_start_at,event_end_at,additional_info,authorization_accepted)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18,TRUE)`,
      [id,data.firstName,data.lastName,data.email,data.phone,data.location,data.eventType,data.guestCount,
       firstOccurrence.date,lastOccurrence.date,firstOccurrence.startTime,lastOccurrence.endTime,JSON.stringify(storedOccurrences),dayCount,feeCents,
       firstOccurrence.startAt.toUTC().toJSDate(),lastOccurrence.endAt.toUTC().toJSDate(),data.additionalInfo]);

    const session = await stripe.checkout.sessions.create({
      ui_mode:'embedded', mode:'payment', customer_creation:'always', customer_email:data.email,
      payment_method_types:['card'], billing_address_collection:'auto',
      line_items:[{quantity:1,price_data:{currency:'usd',unit_amount:5000,product_data:{name:'Event Space Refundable Security Deposit',description:'$50 refundable security deposit for a parish event-space reservation request.'}}}],
      payment_intent_data:{ setup_future_usage:'off_session', metadata:{workflow:'event_space_reservation',reservation_id:id,payment_type:'deposit',reserved_day_count:String(dayCount),reservation_fee_cents:String(feeCents)} },
      metadata:{workflow:'event_space_reservation',reservation_id:id,reserved_day_count:String(dayCount),reservation_fee_cents:String(feeCents)},
      return_url:buildReservationReturnUrl(), redirect_on_completion:'always'
    });
    await pool.query('UPDATE reservations SET stripe_checkout_session_id=$1, updated_at=NOW() WHERE id=$2',[session.id,id]);
    res.json({clientSecret:session.client_secret,reservationId:id});
  } catch(error){
    console.error('Create reservation session error:',error);
    res.status(500).json({error:'Unable to start the secure $50 reservation deposit.'});
  }
});

async function finalizeDepositSession(sessionId) {
  await ensureSchema();
  const session = await stripe.checkout.sessions.retrieve(sessionId,{expand:['payment_intent']});
  if (session.payment_status !== 'paid' || !session.metadata || session.metadata.workflow !== 'event_space_reservation') return null;
  const reservationId = session.metadata.reservation_id;
  const pi = session.payment_intent;
  const customerId = typeof session.customer === 'string' ? session.customer : session.customer && session.customer.id;
  const paymentMethodId = pi && typeof pi !== 'string' ? (typeof pi.payment_method === 'string' ? pi.payment_method : pi.payment_method && pi.payment_method.id) : null;
  const paymentIntentId = pi && typeof pi !== 'string' ? pi.id : (typeof pi === 'string' ? pi : null);
  const update = await pool.query(`UPDATE reservations SET
    status=CASE WHEN status='pending_deposit' THEN 'pending_availability' ELSE status END,
    stripe_customer_id=COALESCE($1,stripe_customer_id), stripe_payment_method_id=COALESCE($2,stripe_payment_method_id), deposit_payment_intent_id=COALESCE($3,deposit_payment_intent_id),
    deposit_paid_at=COALESCE(deposit_paid_at,NOW()), updated_at=NOW()
    WHERE id=$4 RETURNING *`,[customerId,paymentMethodId,paymentIntentId,reservationId]);
  if (!update.rows.length) return null;
  const r = update.rows[0];
  if (!r.request_emails_sent_at) {
    await sendInitialReservationEmails(r);
    await pool.query('UPDATE reservations SET request_emails_sent_at=NOW(),updated_at=NOW() WHERE id=$1',[r.id]);
  }
  return r;
}

app.get('/reservation-session-status', async (req,res) => {
  if (!originAllowed(req)) return res.status(403).json({error:'Origin not allowed.'});
  try {
    const sessionId=String(req.query.session_id||'');
    if(!sessionId.startsWith('cs_')) return res.status(400).json({error:'Invalid session ID.'});
    const r=await finalizeDepositSession(sessionId);
    const session=await stripe.checkout.sessions.retrieve(sessionId);
    res.json({status:session.status,paymentStatus:session.payment_status,reservationId:r && r.id});
  } catch(error){console.error('Reservation status error:',error);res.status(500).json({error:'Unable to verify the reservation deposit.'});}
});

async function sendInitialReservationEmails(r) {
  const availabilityToken = createActionToken(r.id,'availability');
  const reviewUrl = `${publicBackendUrl}/admin/reservation-review?token=${encodeURIComponent(availabilityToken)}`;
  const cancelToken = createActionToken(r.id,'cancel');
  const cancelUrl = `${publicBackendUrl}/reservation/cancel?token=${encodeURIComponent(cancelToken)}`;

  await sendMail({
    to:r.email, replyTo:staffEmail,
    subject:'Event Space Reservation Request Received',
    html:`<h2>We received your event-space reservation request</h2><p>Thank you, ${escapeHtml(r.first_name)}. Your <strong>$50 refundable security deposit</strong> was received. The hall is not yet confirmed; parish staff will review availability and send you another email.</p>${reservationRows(r)}<p>${htmlButton(cancelUrl,'Review / Cancel Request','#8a2e2e')}</p><p>If you cancel before the scheduled reservation-fee charge, that automatic charge will not be processed.</p>`
  });
  await sendMail({
    to:staffEmail, replyTo:r.email,
    subject:`New Event Space Reservation Request — ${r.first_name} ${r.last_name}`,
    html:`<h2>New event-space reservation request</h2><p>The renter has paid the $50 deposit. Please review the requested hall and dates.</p>${reservationRows(r)}<p>${htmlButton(reviewUrl,'Review & Confirm Availability')}</p>`
  });
}

// ----------------------------
// ADMIN AVAILABILITY REVIEW
// ----------------------------
app.get('/admin/reservation-review', async (req,res) => {
  try {
    await ensureSchema();
    const payload=verifyActionToken(String(req.query.token||''),'availability');
    const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[payload.reservationId]);
    if(!result.rows.length) return res.status(404).send('Reservation not found.');
    const r=result.rows[0];
    res.send(adminReviewPage(r,String(req.query.token||'')));
  } catch(error){res.status(400).send(simplePage('Invalid or expired review link',error.message));}
});

app.post('/admin/reservation-review', express.urlencoded({extended:false}), async (req,res) => {
  try {
    await ensureSchema();
    const token=String(req.body.token||''); const action=String(req.body.action||'');
    const payload=verifyActionToken(token,'availability');
    const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[payload.reservationId]);
    if(!result.rows.length) return res.status(404).send('Reservation not found.');
    let r=result.rows[0];
    if(action==='confirm'){
      if(['canceled','declined'].includes(r.status)) return res.send(simplePage('Reservation cannot be confirmed',`Current status: ${r.status}`));
      const startLocal=DateTime.fromJSDate(new Date(r.event_start_at),{zone:'America/New_York'});
      let chargeAt=startLocal.minus({days:14}).set({hour:9,minute:0,second:0,millisecond:0});
      if(chargeAt < DateTime.now()) chargeAt=DateTime.now();
      const upd=await pool.query(`UPDATE reservations SET status=CASE WHEN balance_paid_at IS NULL THEN 'confirmed' ELSE 'balance_paid' END,availability_confirmed_at=COALESCE(availability_confirmed_at,NOW()),balance_charge_at=$1,updated_at=NOW() WHERE id=$2 RETURNING *`,[chargeAt.toUTC().toJSDate(),r.id]);
      r=upd.rows[0];
      await sendAvailabilityConfirmedEmail(r);
      if(chargeAt <= DateTime.now().plus({minutes:1})) await chargeReservationBalance(r.id);
      return res.send(simplePage('Availability confirmed','The renter was emailed and the reservation is confirmed.'));
    }
    if(action==='decline'){
      if(r.balance_paid_at) return res.send(simplePage('Cannot decline automatically','The reservation fee has already been charged. Please handle this reservation manually.'));
      const upd=await pool.query(`UPDATE reservations SET status='declined',updated_at=NOW() WHERE id=$1 RETURNING *`,[r.id]);
      r=upd.rows[0];
      if(r.deposit_payment_intent_id && !r.deposit_refunded_at){
        const refund=await stripe.refunds.create({payment_intent:r.deposit_payment_intent_id,amount:5000},{idempotencyKey:`reservation-${r.id}-decline-deposit-refund`});
        await pool.query('UPDATE reservations SET deposit_refund_id=$1,deposit_refunded_at=NOW(),updated_at=NOW() WHERE id=$2',[refund.id,r.id]);
      }
      await sendMail({to:r.email,replyTo:staffEmail,subject:'Event Space Request — Space Not Available',html:`<h2>We are unable to confirm the requested space</h2><p>We are sorry, ${escapeHtml(r.first_name)}. The parish was unable to confirm availability for the requested reservation.</p>${reservationRows(r)}<p>Your $50 deposit has been submitted for refund to the original payment method.</p>`});
      return res.send(simplePage('Request declined','The renter was emailed and the $50 deposit was refunded.'));
    }
    res.status(400).send('Invalid action.');
  } catch(error){console.error('Admin review action error:',error);res.status(400).send(simplePage('Unable to complete action',error.message));}
});

function adminReviewPage(r,token){
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reservation Review</title>${pageCss()}</head><body><main><h1>Reservation Availability Review</h1>${reservationRows(r)}<p><strong>Current status:</strong> ${escapeHtml(r.status)}</p><form method="post" action="/admin/reservation-review"><input type="hidden" name="token" value="${escapeHtml(token)}"><button name="action" value="confirm">Confirm Availability</button><button class="danger" name="action" value="decline">Space Not Available / Refund $50</button></form></main></body></html>`;
}

async function sendAvailabilityConfirmedEmail(r){
  const cancelToken=createActionToken(r.id,'cancel');
  const cancelUrl=`${publicBackendUrl}/reservation/cancel?token=${encodeURIComponent(cancelToken)}`;
  const chargeDate=DateTime.fromJSDate(new Date(r.balance_charge_at),{zone:'America/New_York'}).toFormat('LLLL d, yyyy');
  await sendMail({to:r.email,replyTo:staffEmail,subject:'Your Event Space Reservation Is Confirmed',html:`<h2>Your event space is confirmed</h2><p>Good news, ${escapeHtml(r.first_name)}. Parish staff confirmed availability for your requested space.</p>${reservationRows(r)}<p>The <strong>${escapeHtml(money(feeForReservation(r)))} reservation fee</strong> is scheduled to be charged to the payment method used for your deposit on <strong>${escapeHtml(chargeDate)}</strong>.</p><p>The fee is $300 for the first reserved day plus $100 for each additional reserved day.</p><p>${htmlButton(cancelUrl,'Review / Cancel Reservation','#8a2e2e')}</p><p>If you cancel before the scheduled reservation-fee charge is processed, that automatic charge will not be made.</p>`});
}

// ----------------------------
// RENTER CANCELLATION
// ----------------------------
app.get('/reservation/cancel', async (req,res) => {
  try{
    await ensureSchema();
    const token=String(req.query.token||''); const payload=verifyActionToken(token,'cancel');
    const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[payload.reservationId]); if(!result.rows.length)return res.status(404).send('Reservation not found.');
    const r=result.rows[0];
    res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cancel Reservation</title>${pageCss()}</head><body><main><h1>Cancel Reservation</h1>${reservationRows(r)}<p><strong>Status:</strong> ${escapeHtml(r.status)}</p>${r.balance_paid_at?`<p class="warning">The ${escapeHtml(money(feeForReservation(r)))} reservation fee has already been charged. Online cancellation will notify the parish, but any refund requires parish review.</p>`:'<p>If you confirm cancellation before the scheduled reservation-fee charge, that automatic charge will be stopped.</p>'}<form method="post" action="/reservation/cancel"><input type="hidden" name="token" value="${escapeHtml(token)}"><button class="danger" name="action" value="cancel">Confirm Cancellation</button></form></main></body></html>`);
  }catch(error){res.status(400).send(simplePage('Invalid or expired cancellation link',error.message));}
});

app.post('/reservation/cancel', express.urlencoded({extended:false}), async (req,res) => {
  try{
    await ensureSchema(); const token=String(req.body.token||''); const payload=verifyActionToken(token,'cancel');
    const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[payload.reservationId]); if(!result.rows.length)return res.status(404).send('Reservation not found.');
    let r=result.rows[0];
    if(r.canceled_at) return res.send(simplePage('Reservation already canceled','No additional charge will be scheduled.'));
    const update=await pool.query(`UPDATE reservations SET status='canceled',canceled_at=NOW(),cancellation_reason='Canceled by renter',updated_at=NOW() WHERE id=$1 RETURNING *`,[r.id]); r=update.rows[0];
    // Existing policy: if cancellation is more than 14 days before the event, refund the $50 deposit automatically.
    const now=DateTime.now().setZone('America/New_York');
    const start=DateTime.fromJSDate(new Date(r.event_start_at),{zone:'America/New_York'});
    const moreThan14Days=start.diff(now,'days').days > 14;
    let depositRefunded=false;
    if(moreThan14Days && r.deposit_payment_intent_id && !r.deposit_refunded_at){
      const refund=await stripe.refunds.create({payment_intent:r.deposit_payment_intent_id,amount:5000},{idempotencyKey:`reservation-${r.id}-early-cancel-deposit-refund`});
      await pool.query('UPDATE reservations SET deposit_refund_id=$1,deposit_refunded_at=NOW(),updated_at=NOW() WHERE id=$2',[refund.id,r.id]); depositRefunded=true;
    }
    await sendMail({to:staffEmail,replyTo:r.email,subject:`Reservation Canceled — ${r.first_name} ${r.last_name}`,html:`<h2>Reservation canceled by renter</h2>${reservationRows(r)}<p>The reservation has been marked canceled. ${r.balance_paid_at?'The reservation fee had already been charged and requires parish review.':'The future reservation-fee automatic charge has been stopped.'}</p><p>${depositRefunded?'The $50 deposit was automatically refunded because the cancellation was more than 14 days before the event.':'The $50 deposit was not automatically refunded under the more-than-14-days rule.'}</p>`});
    await sendMail({to:r.email,replyTo:staffEmail,subject:'Your Event Space Reservation Was Canceled',html:`<h2>Your reservation has been canceled</h2><p>${r.balance_paid_at?'The reservation fee had already been processed. The parish office will review any applicable refund.':'The scheduled reservation-fee automatic charge has been stopped.'}</p><p>${depositRefunded?'Your $50 deposit has been submitted for refund to the original payment method.':'Any refund of the $50 deposit is subject to the parish cancellation policy.'}</p>`});
    res.send(simplePage('Reservation canceled',r.balance_paid_at?'The parish office has been notified.':'The scheduled reservation-fee charge has been stopped.'));
  }catch(error){console.error('Cancellation error:',error);res.status(400).send(simplePage('Unable to cancel reservation',error.message));}
});

// ----------------------------
// DAILY CRON: BALANCE + REFUND REVIEW
// ----------------------------
app.get('/cron/reservations', async (req,res) => {
  if(!cronSecret || req.headers.authorization !== `Bearer ${cronSecret}`) return res.status(401).json({error:'Unauthorized'});
  try{
    await ensureSchema();
    const due=await pool.query(`SELECT id FROM reservations WHERE status='confirmed' AND canceled_at IS NULL AND balance_paid_at IS NULL AND balance_charge_at IS NOT NULL AND balance_charge_at <= NOW() ORDER BY balance_charge_at LIMIT 100`);
    const charged=[]; const failed=[];
    for(const item of due.rows){try{await chargeReservationBalance(item.id);charged.push(item.id);}catch(err){failed.push({id:item.id,error:err.message});}}
    const refunds=await sendDueRefundReviewEmails();
    res.json({ok:true,charged,failed,refundReviewEmails:refunds});
  }catch(error){console.error('Reservation cron error:',error);res.status(500).json({error:'Reservation cron failed.'});}
});

async function chargeReservationBalance(id){
  const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[id]); if(!result.rows.length)throw new Error('Reservation not found.');
  let r=result.rows[0];
  if(r.canceled_at || r.status==='canceled' || r.status==='declined') return r;
  if(r.balance_paid_at) return r;
  if(!r.stripe_customer_id || !r.stripe_payment_method_id) throw new Error('Saved Stripe payment method is missing.');
  try{
    const feeCents=feeForReservation(r);
    const pi=await stripe.paymentIntents.create({amount:feeCents,currency:'usd',customer:r.stripe_customer_id,payment_method:r.stripe_payment_method_id,off_session:true,confirm:true,description:`Parish event-space reservation fee - ${r.reserved_day_count || 1} reserved day(s)`,metadata:{workflow:'event_space_reservation',reservation_id:r.id,payment_type:'reservation_fee',reserved_day_count:String(r.reserved_day_count || 1),reservation_fee_cents:String(feeCents)}},{idempotencyKey:`reservation-${r.id}-balance-${feeCents}`});
    const upd=await pool.query(`UPDATE reservations SET balance_payment_intent_id=$1,balance_paid_at=NOW(),status='balance_paid',charge_failure_at=NULL,charge_failure_message=NULL,updated_at=NOW() WHERE id=$2 RETURNING *`,[pi.id,r.id]); r=upd.rows[0];
    await sendMail({to:r.email,replyTo:staffEmail,subject:`${money(feeCents)} Event Space Reservation Fee Charged`,html:`<h2>Your ${escapeHtml(money(feeCents))} reservation fee was processed</h2><p>The scheduled reservation fee for your confirmed event was successfully charged to the saved payment method.</p>${reservationRows(r)}<p>Your $50 security deposit remains refundable according to the rental agreement. After the final reserved date, parish staff will review the space and can approve the deposit refund.</p>`});
    await sendMail({to:staffEmail,replyTo:r.email,subject:`${money(feeCents)} Reservation Fee Charged — ${r.first_name} ${r.last_name}`,html:`<h2>${escapeHtml(money(feeCents))} reservation fee successfully charged</h2>${reservationRows(r)}<p>The $50 security deposit remains held until the post-event refund review after the final reserved date.</p>`});
    return r;
  }catch(error){
    await pool.query(`UPDATE reservations SET charge_failure_at=NOW(),charge_failure_message=$1,updated_at=NOW() WHERE id=$2`,[String(error.message||error).slice(0,1000),r.id]);
    await sendMail({to:staffEmail,replyTo:r.email,subject:`ACTION REQUIRED: ${money(feeForReservation(r))} Reservation Charge Failed — ${r.first_name} ${r.last_name}`,html:`<h2>The scheduled ${escapeHtml(money(feeForReservation(r)))} reservation-fee charge failed</h2>${reservationRows(r)}<p><strong>Error:</strong> ${escapeHtml(error.message||'Unknown Stripe error')}</p><p>Please contact the renter to resolve payment before the event.</p>`});
    await sendMail({to:r.email,replyTo:staffEmail,subject:'Action Needed for Your Event Space Reservation Payment',html:`<h2>We could not process the scheduled ${escapeHtml(money(feeForReservation(r)))} reservation fee</h2><p>Please contact the parish office at ${escapeHtml(staffEmail)} so the payment can be resolved and your reservation remains in good standing.</p>`});
    throw error;
  }
}

async function sendDueRefundReviewEmails(){
  const result=await pool.query(`SELECT * FROM reservations WHERE balance_paid_at IS NOT NULL AND canceled_at IS NULL AND deposit_payment_intent_id IS NOT NULL AND deposit_refunded_at IS NULL AND refund_approval_sent_at IS NULL AND event_end_at < NOW() ORDER BY event_end_at LIMIT 100`);
  const sent=[];
  for(const r of result.rows){
    const token=createActionToken(r.id,'refund');
    const url=`${publicBackendUrl}/admin/refund-review?token=${encodeURIComponent(token)}`;
    await sendMail({to:staffEmail,replyTo:r.email,subject:`Deposit Refund Review — ${r.first_name} ${r.last_name}`,html:`<h2>Post-event $50 deposit review</h2><p>The event has ended. Please review the facility condition and decide whether to refund the $50 security deposit.</p>${reservationRows(r)}<p>${htmlButton(url,'Review $50 Deposit Refund')}</p>`});
    await pool.query('UPDATE reservations SET refund_approval_sent_at=NOW(),updated_at=NOW() WHERE id=$1',[r.id]); sent.push(r.id);
  }
  return sent;
}

// ----------------------------
// ADMIN REFUND REVIEW
// ----------------------------
app.get('/admin/refund-review', async (req,res) => {
  try{
    await ensureSchema(); const token=String(req.query.token||''); const payload=verifyActionToken(token,'refund');
    const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[payload.reservationId]); if(!result.rows.length)return res.status(404).send('Reservation not found.');
    const r=result.rows[0];
    res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Deposit Refund Review</title>${pageCss()}</head><body><main><h1>$50 Deposit Refund Review</h1>${reservationRows(r)}<p><strong>Status:</strong> ${escapeHtml(r.status)}</p><p>Approve the refund only after confirming the facility was returned in the required condition and there are no damages or agreement violations.</p><form method="post" action="/admin/refund-review"><input type="hidden" name="token" value="${escapeHtml(token)}"><button name="action" value="refund">Approve $50 Refund</button><button class="danger" name="action" value="hold">Hold Deposit / Do Not Refund</button></form></main></body></html>`);
  }catch(error){res.status(400).send(simplePage('Invalid or expired refund link',error.message));}
});

app.post('/admin/refund-review', express.urlencoded({extended:false}), async (req,res) => {
  try{
    await ensureSchema(); const token=String(req.body.token||''); const action=String(req.body.action||''); const payload=verifyActionToken(token,'refund');
    const result=await pool.query('SELECT * FROM reservations WHERE id=$1',[payload.reservationId]); if(!result.rows.length)return res.status(404).send('Reservation not found.');
    let r=result.rows[0];
    if(action==='refund'){
      if(r.deposit_refunded_at) return res.send(simplePage('Deposit already refunded','No additional refund was issued.'));
      const refund=await stripe.refunds.create({payment_intent:r.deposit_payment_intent_id,amount:5000},{idempotencyKey:`reservation-${r.id}-approved-deposit-refund`});
      const upd=await pool.query(`UPDATE reservations SET deposit_refund_id=$1,deposit_refunded_at=NOW(),updated_at=NOW() WHERE id=$2 RETURNING *`,[refund.id,r.id]); r=upd.rows[0];
      await sendMail({to:r.email,replyTo:staffEmail,subject:'Your $50 Event Space Deposit Was Refunded',html:`<h2>Your $50 security deposit was approved for refund</h2><p>The parish approved the refund and Stripe has submitted $50 back to the original payment method.</p>${reservationRows(r)}`});
      return res.send(simplePage('$50 refund approved','Stripe has submitted the refund to the original payment method.'));
    }
    if(action==='hold'){
      await sendMail({to:staffEmail,subject:`Deposit Held — ${r.first_name} ${r.last_name}`,html:`<h2>The $50 deposit was not refunded</h2>${reservationRows(r)}<p>No Stripe refund was issued. Document the reason in the parish records and contact the renter as appropriate.</p>`});
      return res.send(simplePage('Deposit held','No refund was issued.'));
    }
    res.status(400).send('Invalid action.');
  }catch(error){console.error('Refund review error:',error);res.status(400).send(simplePage('Unable to process refund action',error.message));}
});

function pageCss(){return `<style>body{font-family:Arial,sans-serif;background:#f5f7f9;color:#26323b;margin:0;padding:24px}main{max-width:760px;margin:auto;background:#fff;padding:28px;border-radius:14px;box-shadow:0 8px 28px rgba(0,0,0,.08)}h1{color:#173f5f}button{background:#173f5f;color:#fff;border:0;border-radius:7px;padding:12px 18px;font-weight:700;margin:8px 8px 8px 0;cursor:pointer}.danger{background:#8a2e2e}.warning{background:#fff3cd;padding:12px;border-radius:7px}</style>`;}
function simplePage(title,message){return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>${pageCss()}</head><body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message||'')}</p></main></body></html>`;}

app.get('/health', async (_req,res) => {
  try{await ensureSchema();res.json({ok:true,reservations:true});}catch(e){res.status(500).json({ok:false,error:'Database unavailable'});}
});

const port=process.env.PORT||4242;
app.listen(port,()=>console.log(`St. Mary Stripe backend listening on port ${port}`));
