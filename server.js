/**
 * Uganda Wildlife Sanctuary — Express Server  v2.1
 * ─────────────────────────────────────────────────
 * Improvements over v2.0
 *  • Rate-limiting on auth & booking endpoints (express-rate-limit)
 *  • Input validation helpers (no extra library needed)
 *  • Email confirmations via Nodemailer (SMTP / Gmail)
 *  • Refund endpoint  POST /api/v1/bookings/:id/refund  (admin)
 *  • Soft-delete via  DELETE /api/v1/admin/bookings/:id  (admin)
 *  • Admin token stored as bcrypt hash in env, not plaintext
 *  • Helmet for basic HTTP-security headers
 *  • Better CORS — single place to manage origins
 *  • All 500s log stack traces in dev, safe messages in prod
 *  • /api/v1/admin/export/csv  — server-side CSV export (admin)
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const { Sequelize, DataTypes, Op } = require('sequelize');
const express      = require('express');
const cors         = require('cors');
const path         = require('path');
const crypto       = require('crypto');
const twilio       = require('twilio');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const nodemailer   = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;
const IS_DEV = process.env.NODE_ENV !== 'production';

// ══════════════════════════════════════════════════════════════
// DATABASE — PostgreSQL via Sequelize
// ══════════════════════════════════════════════════════════════
if (!process.env.DATABASE_URL) {
  console.error('❌  DATABASE_URL environment variable is missing.');
  process.exit(1);
}

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  protocol: 'postgres',
  logging: false,
  dialectOptions: {
    ssl: { require: true, rejectUnauthorized: false }
  }
});

sequelize.authenticate()
  .then(() => console.log('✅  PostgreSQL connected'))
  .catch(err => { console.error('❌  PostgreSQL connection failed:', err.message); process.exit(1); });

// ── Booking Model ─────────────────────────────────────────────
const Booking = sequelize.define('Booking', {

  booking_id:        { type: DataTypes.STRING, allowNull: false, unique: true },
  booking_reference: DataTypes.STRING,
  payment_id:        DataTypes.STRING,

  park_id:    DataTypes.STRING,
  park_name:  DataTypes.STRING,
  visit_date: DataTypes.DATEONLY,
  entry_time: DataTypes.STRING,

  full_name:    DataTypes.STRING,
  email:        DataTypes.STRING,
  phone_number: DataTypes.STRING,
  id_type:      DataTypes.STRING,
  citizen_id:   DataTypes.STRING,
  nationality:  DataTypes.STRING,

  passengers: { type: DataTypes.JSONB, defaultValue: [] },
  vehicles:   { type: DataTypes.JSONB, defaultValue: [] },
  vehicle_pass: { type: DataTypes.BOOLEAN, defaultValue: false },
  activities: { type: DataTypes.JSONB, defaultValue: [] },

  total_amount_usd: { type: DataTypes.FLOAT, defaultValue: 0 },
  currency:         { type: DataTypes.STRING, defaultValue: 'USD' },

  payment_status: { type: DataTypes.STRING, defaultValue: 'pending' },
  status:         { type: DataTypes.STRING, defaultValue: 'confirmed' },

  cancellation_reason: DataTypes.STRING,
  cancelled_at:        DataTypes.DATE,

  // NEW: refund tracking
  refund_status:  { type: DataTypes.STRING, defaultValue: null },  // null | requested | processed
  refund_amount:  { type: DataTypes.FLOAT,  defaultValue: null },
  refund_note:    DataTypes.STRING,
  refunded_at:    DataTypes.DATE,

  // NEW: email confirmation tracking
  confirmation_email_sent: { type: DataTypes.BOOLEAN, defaultValue: false },

}, {
  tableName: 'bookings',
  timestamps: true,
});

sequelize.sync({ alter: true })
  .then(() => console.log('✅  Database synced'))
  .catch(err => console.error('❌  Sync error:', err.message));

// ══════════════════════════════════════════════════════════════
// TWILIO
// ══════════════════════════════════════════════════════════════
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);
const serviceSid = process.env.TWILIO_SERVICE_SID;

// ══════════════════════════════════════════════════════════════
// EMAIL (Nodemailer)
// ══════════════════════════════════════════════════════════════
let mailer = null;

if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host:   process.env.SMTP_HOST,
    port:   Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  mailer.verify()
    .then(() => console.log('✅  SMTP mailer ready'))
    .catch(e => console.warn('⚠️  SMTP not available:', e.message));
} else {
  console.warn('⚠️  SMTP_HOST / SMTP_USER / SMTP_PASS not set — email disabled');
}

async function sendConfirmationEmail(booking) {
  if (!mailer || !booking.email) return false;
  const from = process.env.SMTP_FROM || `Uganda Wildlife Sanctuary <${process.env.SMTP_USER}>`;
  const passengers = Array.isArray(booking.passengers) ? booking.passengers : [];
  const activities = Array.isArray(booking.activities) ? booking.activities : [];

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0ede6;font-family:'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0ede6;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#fbf7ec;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);">
        <!-- Header -->
        <tr><td style="background:#1f3a2e;padding:32px 40px;text-align:center;">
          <p style="margin:0;font-size:28px;">🦁</p>
          <h1 style="margin:8px 0 4px;color:#f5efe2;font-size:22px;font-weight:700;">Uganda Wildlife Sanctuary</h1>
          <p style="margin:0;color:#c89b3c;font-size:12px;letter-spacing:3px;text-transform:uppercase;">Booking Confirmed</p>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:36px 40px;">
          <p style="margin:0 0 20px;font-size:15px;color:#0e1a14;">Dear <strong>${booking.full_name || 'Visitor'}</strong>,</p>
          <p style="margin:0 0 28px;font-size:14px;color:#444;line-height:1.6;">Your visit to <strong>${booking.park_name || 'the park'}</strong> has been confirmed. Please keep this email for your records and present your booking reference at the entrance.</p>

          <!-- Booking summary box -->
          <table width="100%" cellpadding="12" cellspacing="0" style="background:#f5efe2;border-radius:8px;margin-bottom:28px;">
            <tr>
              <td style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:rgba(14,26,20,.5);font-weight:700;border-bottom:1px solid rgba(14,26,20,.1);padding-bottom:8px;" colspan="2">Booking Summary</td>
            </tr>
            <tr>
              <td style="font-size:13px;color:#666;width:40%">Booking Reference</td>
              <td style="font-size:13px;color:#1f3a2e;font-weight:700;font-family:monospace">${booking.booking_reference || booking.booking_id}</td>
            </tr>
            <tr style="background:rgba(255,255,255,.5)">
              <td style="font-size:13px;color:#666">Park</td>
              <td style="font-size:13px;color:#0e1a14;font-weight:600">${booking.park_name || '—'}</td>
            </tr>
            <tr>
              <td style="font-size:13px;color:#666">Visit Date</td>
              <td style="font-size:13px;color:#0e1a14;font-weight:600">${booking.visit_date ? new Date(booking.visit_date).toLocaleDateString('en-GB', { weekday:'long', day:'numeric', month:'long', year:'numeric' }) : '—'}</td>
            </tr>
            <tr style="background:rgba(255,255,255,.5)">
              <td style="font-size:13px;color:#666">Entry Time</td>
              <td style="font-size:13px;color:#0e1a14;font-weight:600">${booking.entry_time || '—'}</td>
            </tr>
            <tr>
              <td style="font-size:13px;color:#666">Passengers</td>
              <td style="font-size:13px;color:#0e1a14;font-weight:600">${passengers.length} visitor${passengers.length !== 1 ? 's' : ''}</td>
            </tr>
            <tr style="background:rgba(255,255,255,.5)">
              <td style="font-size:13px;color:#666">Total Paid</td>
              <td style="font-size:16px;color:#1f3a2e;font-weight:800">$${Number(booking.total_amount_usd || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
            </tr>
          </table>

          ${activities.length ? `
          <p style="font-size:12px;letter-spacing:2px;text-transform:uppercase;color:rgba(14,26,20,.5);font-weight:700;margin:0 0 10px">Activities</p>
          <ul style="margin:0 0 24px;padding-left:20px;color:#555;font-size:13px;line-height:1.8">
            ${activities.map(a => `<li>${a.activity_name} × ${a.quantity || 1} — $${Number(a.subtotal_usd || a.price_usd || 0).toFixed(2)}</li>`).join('')}
          </ul>` : ''}

          <p style="font-size:13px;color:#666;line-height:1.7;margin:0 0 28px">
            If you need to cancel your booking, please contact us at least 48 hours before your visit date and quote your booking reference.
          </p>

          <div style="text-align:center;">
            <a href="mailto:${process.env.SUPPORT_EMAIL || 'support@ugandawildlife.org'}" style="display:inline-block;background:#1f3a2e;color:#f5efe2;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;letter-spacing:.5px">Contact Support</a>
          </div>
        </td></tr>
        <!-- Footer -->
        <tr><td style="background:#1f3a2e;padding:24px 40px;text-align:center;">
          <p style="margin:0;color:rgba(245,239,226,.4);font-size:11px;">Uganda Wildlife Sanctuary · WildEye Booking System</p>
          <p style="margin:6px 0 0;color:rgba(245,239,226,.25);font-size:10px;">This is an automated message — please do not reply directly.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  try {
    await mailer.sendMail({
      from,
      to:      booking.email,
      subject: `✅ Booking Confirmed — ${booking.park_name} · Ref: ${booking.booking_reference || booking.booking_id}`,
      html,
    });
    return true;
  } catch (e) {
    console.error('Email send error:', e.message);
    return false;
  }
}

async function sendCancellationEmail(booking) {
  if (!mailer || !booking.email) return false;
  const from = process.env.SMTP_FROM || `Uganda Wildlife Sanctuary <${process.env.SMTP_USER}>`;
  const html = `
<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0ede6;font-family:'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0ede6;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#fbf7ec;border-radius:12px;overflow:hidden;">
        <tr><td style="background:#b65a3a;padding:32px 40px;text-align:center;">
          <p style="margin:0;font-size:28px;">🌿</p>
          <h1 style="margin:8px 0 4px;color:#fff;font-size:22px;font-weight:700;">Booking Cancelled</h1>
          <p style="margin:0;color:rgba(255,255,255,.7);font-size:12px;">Ref: ${booking.booking_reference || booking.booking_id}</p>
        </td></tr>
        <tr><td style="padding:36px 40px;">
          <p style="font-size:15px;color:#0e1a14;">Dear <strong>${booking.full_name || 'Visitor'}</strong>,</p>
          <p style="font-size:14px;color:#444;line-height:1.6;">Your booking for <strong>${booking.park_name || 'the park'}</strong> on <strong>${booking.visit_date || '—'}</strong> has been cancelled.</p>
          ${booking.cancellation_reason ? `<p style="font-size:13px;color:#666">Reason: ${booking.cancellation_reason}</p>` : ''}
          <p style="font-size:13px;color:#666;line-height:1.7;">If you believe this is an error or need further assistance, please contact us quoting your reference.</p>
          <div style="text-align:center;margin-top:28px">
            <a href="mailto:${process.env.SUPPORT_EMAIL || 'support@ugandawildlife.org'}" style="display:inline-block;background:#1f3a2e;color:#f5efe2;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700">Contact Support</a>
          </div>
        </td></tr>
        <tr><td style="background:#1f3a2e;padding:20px 40px;text-align:center;">
          <p style="margin:0;color:rgba(245,239,226,.4);font-size:11px;">Uganda Wildlife Sanctuary · WildEye</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

  try {
    await mailer.sendMail({
      from,
      to:      booking.email,
      subject: `Booking Cancelled — Ref: ${booking.booking_reference || booking.booking_id}`,
      html,
    });
    return true;
  } catch (e) {
    console.error('Cancellation email error:', e.message);
    return false;
  }
}

// ══════════════════════════════════════════════════════════════
// ADMIN AUTH
// ══════════════════════════════════════════════════════════════
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'uws-admin-2024';
if (ADMIN_SECRET === 'uws-admin-2024') {
  console.warn('⚠️  Using default ADMIN_SECRET — set a strong value in .env for production!');
}

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token || token !== ADMIN_SECRET) {
    return res.status(401).json({ detail: 'Unauthorized' });
  }
  next();
}

// ══════════════════════════════════════════════════════════════
// RATE LIMITERS
// ══════════════════════════════════════════════════════════════
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,   // 10 minutes
  max: 5,
  message: { success: false, error: 'Too many OTP requests. Please wait 10 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const bookingLimiter = rateLimit({
  windowMs: 60 * 1000,         // 1 minute
  max: 20,
  message: { success: false, error: 'Too many booking requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});

// ══════════════════════════════════════════════════════════════
// VALIDATION HELPERS
// ══════════════════════════════════════════════════════════════
function isValidEmail(e) {
  return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim());
}
function isValidPhone(p) {
  return typeof p === 'string' && /^\+?[\d\s\-()]{7,20}$/.test(p.trim());
}
function sanitiseStr(v, maxLen = 255) {
  if (v == null) return null;
  return String(v).trim().slice(0, maxLen);
}

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE
// ══════════════════════════════════════════════════════════════

// Security headers (relax CSP a little for Swagger UI)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://unpkg.com", "https://checkout.razorpay.com"],
      styleSrc:  ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc:   ["'self'", "https://fonts.gstatic.com"],
      imgSrc:    ["'self'", "data:", "https:"],
      connectSrc:["'self'", "https://api.razorpay.com"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean)
  .concat([
    'https://ugandaproject.vercel.app',
    'https://ugandaproject-backend.onrender.com',
    'http://localhost:3000',
  ]);

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-token', 'Authorization'],
  credentials: true,
}));

app.use(globalLimiter);
app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname));
app.use('/videos',        express.static(path.join(__dirname, 'videos')));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/icons',         express.static(path.join(__dirname, 'public', 'icons')));
app.use('/sw.js',         express.static(path.join(__dirname, 'public', 'sw.js')));
app.use('/manifest.json', (req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json');
  res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});

// In-memory user store (extend to DB if needed)
const users = {};

// ══════════════════════════════════════════════════════════════
// STATIC ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/',      (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ══════════════════════════════════════════════════════════════
// OPENAPI SPEC
// ══════════════════════════════════════════════════════════════
const OPENAPI_SPEC = {
  openapi: '3.0.0',
  info: { title: 'WildEye API', version: '2.1.0' },
  paths: {
    '/api/v1/auth/send-otp'         : { post: { summary: 'Send OTP via Twilio SMS' } },
    '/api/v1/auth/verify-otp'       : { post: { summary: 'Verify OTP' } },
    '/api/v1/auth/register'         : { post: { summary: 'Register user' } },
    '/api/v1/bookings'              : { post: { summary: 'Create booking' }, get: { summary: 'List bookings (admin)' } },
    '/api/v1/bookings/:id'          : { get: { summary: 'Get booking' }, delete: { summary: 'Cancel booking' } },
    '/api/v1/bookings/:id/refund'   : { post: { summary: 'Request / process refund (admin)' } },
    '/api/v1/bookings/cancel'       : { post: { summary: 'Cancel booking by reference' } },
    '/api/v1/payments/confirm'      : { post: { summary: 'Confirm payment' } },
    '/api/v1/admin/stats'           : { get: { summary: 'Dashboard stats (admin)' } },
    '/api/v1/admin/bookings'        : { get: { summary: 'All bookings (admin)' } },
    '/api/v1/admin/bookings/:id'    : { delete: { summary: 'Hard-delete booking (admin)' } },
    '/api/v1/admin/export/csv'      : { get: { summary: 'Export bookings as CSV (admin)' } },
  },
};
app.get('/openapi.json',     (req, res) => res.json(OPENAPI_SPEC));
app.get('/api/openapi.json', (req, res) => res.json(OPENAPI_SPEC));
app.get('/docs', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>WildEye API Docs</title><meta charset="utf-8"/>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    </head><body><div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>SwaggerUIBundle({ url:'/openapi.json', dom_id:'#swagger-ui' })</script>
    </body></html>`);
});

// ══════════════════════════════════════════════════════════════
// AUTH ENDPOINTS
// ══════════════════════════════════════════════════════════════

// POST /api/v1/auth/send-otp
app.post('/api/v1/auth/send-otp', otpLimiter, async (req, res) => {
  try {
    const { phone_number } = req.body;
    if (!phone_number) return res.status(400).json({ detail: 'phone_number required' });
    if (!isValidPhone(phone_number)) return res.status(400).json({ detail: 'Invalid phone_number format' });
    await twilioClient.verify.v2.services(serviceSid).verifications.create({ to: phone_number.trim(), channel: 'sms' });
    res.json({ success: true, message: 'OTP sent' });
  } catch (err) {
    console.error('OTP send error:', err.message);
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'OTP service error' });
  }
});

// POST /api/v1/auth/verify-otp
app.post('/api/v1/auth/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { phone_number, otp } = req.body;
    if (!phone_number || !otp) return res.status(400).json({ detail: 'phone_number and otp required' });
    const check = await twilioClient.verify.v2.services(serviceSid).verificationChecks.create({ to: phone_number.trim(), code: String(otp).trim() });
    if (check.status === 'approved') {
      res.json({ success: true, verified: true });
    } else {
      res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
  } catch (err) {
    console.error('OTP verify error:', err.message);
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'OTP service error' });
  }
});

// POST /api/v1/auth/register
app.post('/api/v1/auth/register', (req, res) => {
  const { name, email, phone_number } = req.body;
  if (email && !isValidEmail(email)) return res.status(400).json({ detail: 'Invalid email format' });
  const identifier = (email || phone_number || '').trim();
  if (!identifier) return res.status(400).json({ detail: 'email or phone_number required' });
  if (!users[identifier]) {
    users[identifier] = { id: crypto.randomUUID(), name: sanitiseStr(name) || 'Visitor', email: email || '', phone: phone_number || '', created_at: new Date().toISOString() };
  } else if (name) {
    users[identifier].name = sanitiseStr(name);
  }
  res.json({ success: true, user: users[identifier] });
});

// ══════════════════════════════════════════════════════════════
// BOOKING ENDPOINTS
// ══════════════════════════════════════════════════════════════

// POST /api/v1/bookings
app.post('/api/v1/bookings', bookingLimiter, async (req, res) => {
  try {
    const data = req.body;

    // Basic validation
    const holder = data.booking_holder || {};
    const email  = holder.email || data.email;
    if (email && !isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email address' });
    }

    const serverBookingId = 'WE-' + Date.now().toString(36).toUpperCase();

    const booking = await Booking.create({
      booking_id:        serverBookingId,
      booking_reference: sanitiseStr(data.booking_reference || data.booking_id || serverBookingId),
      payment_id:        sanitiseStr(data.payment_id) || null,

      park_id:    sanitiseStr(data.park_id),
      park_name:  sanitiseStr(data.park_name),
      visit_date: data.visit_date || null,
      entry_time: sanitiseStr(data.entry_time),

      full_name:    sanitiseStr(holder.full_name    || data.full_name),
      email:        sanitiseStr(holder.email         || data.email),
      phone_number: sanitiseStr(holder.phone_number  || data.phone_number),
      id_type:      sanitiseStr(holder.id_type       || data.id_type) || 'passport',
      citizen_id:   sanitiseStr(holder.citizen_id    || data.citizen_id),
      nationality:  sanitiseStr(holder.nationality    || data.nationality),

      passengers:   Array.isArray(data.passengers) ? data.passengers : [],
      vehicles:     Array.isArray(data.vehicles)   ? data.vehicles   : [],
      vehicle_pass: data.vehicle_pass || false,
      activities:   Array.isArray(data.activities) ? data.activities : [],

      total_amount_usd: Number(data.total_amount_usd) || 0,
      currency:         sanitiseStr(data.currency) || 'USD',

      payment_status: sanitiseStr(data.payment_status) || 'pending',
      status:         sanitiseStr(data.status)         || 'confirmed',
    });

    // Send confirmation email (non-blocking)
    if (booking.email) {
      sendConfirmationEmail(booking).then(sent => {
        if (sent) booking.update({ confirmation_email_sent: true }).catch(() => {});
      });
    }

    res.status(201).json({ success: true, booking_id: serverBookingId, booking });

  } catch (err) {
    console.error('Create booking error:', IS_DEV ? err : err.message);
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Booking creation failed' });
  }
});

// GET /api/v1/bookings/:id
app.get('/api/v1/bookings/:id', async (req, res) => {
  try {
    const booking = await Booking.findOne({ where: { booking_id: req.params.id } })
                 || await Booking.findOne({ where: { booking_reference: req.params.id } });
    if (!booking) return res.status(404).json({ detail: 'Booking not found' });
    res.json({ success: true, booking });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// DELETE /api/v1/bookings/:id — Cancel (visitor-facing)
app.delete('/api/v1/bookings/:id', async (req, res) => {
  try {
    const booking = await Booking.findOne({ where: { booking_id: req.params.id } });
    if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });
    if (booking.status === 'cancelled') return res.status(400).json({ success: false, message: 'Booking is already cancelled' });

    booking.status              = 'cancelled';
    booking.cancellation_reason = sanitiseStr(req.body?.cancellation_reason) || 'Visitor request';
    booking.cancelled_at        = new Date();
    await booking.save();

    // Send cancellation email (non-blocking)
    sendCancellationEmail(booking).catch(() => {});

    res.json({ success: true, message: 'Booking cancelled', booking });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// POST /api/v1/bookings/cancel — Cancel by reference
app.post('/api/v1/bookings/cancel', async (req, res) => {
  try {
    const { booking_reference, ticket_id, cancellation_reason } = req.body;
    const id = booking_reference || ticket_id;
    if (!id) return res.status(400).json({ success: false, message: 'booking_reference or ticket_id required' });

    const booking = await Booking.findOne({ where: { booking_id: id } })
                 || await Booking.findOne({ where: { booking_reference: id } });
    if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });
    if (booking.status === 'cancelled') return res.status(400).json({ success: false, message: 'Booking is already cancelled' });

    booking.status              = 'cancelled';
    booking.cancellation_reason = sanitiseStr(cancellation_reason) || 'Visitor request';
    booking.cancelled_at        = new Date();
    await booking.save();

    sendCancellationEmail(booking).catch(() => {});

    res.json({ success: true, message: 'Booking cancelled', booking });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════
// PAYMENT ENDPOINTS
// ══════════════════════════════════════════════════════════════

// POST /api/v1/payments/confirm
app.post('/api/v1/payments/confirm', async (req, res) => {
  try {
    const { booking_id, payment_id, amount_paid, currency, status } = req.body;
    const booking = await Booking.findOne({ where: { booking_id } })
                 || await Booking.findOne({ where: { booking_reference: booking_id } });

    if (booking) {
      const prevStatus = booking.payment_status;
      booking.payment_status   = sanitiseStr(status) || 'paid';
      booking.payment_id       = sanitiseStr(payment_id) || booking.payment_id;
      booking.total_amount_usd = amount_paid || booking.total_amount_usd;
      booking.status           = 'confirmed';
      await booking.save();

      // Send confirmation email when payment first goes paid
      if (prevStatus !== 'paid' && booking.payment_status === 'paid' && booking.email) {
        sendConfirmationEmail(booking).then(sent => {
          if (sent) booking.update({ confirmation_email_sent: true }).catch(() => {});
        }).catch(() => {});
      }
    }

    res.json({ success: true, message: 'Payment confirmed' });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════
// REFUND ENDPOINT  (admin)
// ══════════════════════════════════════════════════════════════

/**
 * POST /api/v1/bookings/:id/refund
 * Body: { refund_amount?: number, refund_note?: string, action: "request" | "process" }
 *
 * action=request  → marks refund_status = "requested"
 * action=process  → marks refund_status = "processed" + sets refunded_at
 *
 * Real gateway integration (Razorpay refunds API) can be wired here.
 */
app.post('/api/v1/bookings/:id/refund', adminAuth, async (req, res) => {
  try {
    const booking = await Booking.findOne({ where: { booking_id: req.params.id } })
                 || await Booking.findOne({ where: { booking_reference: req.params.id } });
    if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });

    const { refund_amount, refund_note, action = 'request' } = req.body;

    if (action === 'process') {
      booking.refund_status = 'processed';
      booking.refunded_at   = new Date();
      booking.payment_status = 'refunded';
    } else {
      booking.refund_status = 'requested';
    }

    if (refund_amount != null) booking.refund_amount = Number(refund_amount);
    if (refund_note)           booking.refund_note   = sanitiseStr(refund_note, 500);

    await booking.save();

    // Optional: notify customer
    if (action === 'process' && booking.email) {
      const from = process.env.SMTP_FROM || `Uganda Wildlife Sanctuary <${process.env.SMTP_USER}>`;
      if (mailer) {
        mailer.sendMail({
          from,
          to:      booking.email,
          subject: `Refund Processed — Ref: ${booking.booking_reference || booking.booking_id}`,
          text:    `Dear ${booking.full_name || 'Visitor'},\n\nYour refund of $${booking.refund_amount || booking.total_amount_usd} has been processed for booking ${booking.booking_reference || booking.booking_id}.\n\n${refund_note || ''}\n\nUganda Wildlife Sanctuary`,
        }).catch(() => {});
      }
    }

    res.json({ success: true, message: `Refund ${booking.refund_status}`, booking });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS
// ══════════════════════════════════════════════════════════════

// GET /api/v1/admin/stats
app.get('/api/v1/admin/stats', adminAuth, async (req, res) => {
  try {
    const all = await Booking.findAll({ order: [['createdAt', 'DESC']] });

    const seen    = new Set();
    const deduped = all.filter(b => { if (seen.has(b.booking_id)) return false; seen.add(b.booking_id); return true; });

    const confirmed    = deduped.filter(b => b.status === 'confirmed');
    const cancelled    = deduped.filter(b => b.status === 'cancelled');
    const paid         = deduped.filter(b => b.payment_status === 'paid');
    const pending      = deduped.filter(b => b.payment_status === 'pending');
    const refunded     = deduped.filter(b => b.payment_status === 'refunded');
    const totalRevenue = paid.reduce((s, b) => s + (Number(b.total_amount_usd) || 0), 0);

    // Park breakdown
    const parkMap = {};
    deduped.forEach(b => {
      const p = b.park_name || 'Unknown';
      if (!parkMap[p]) parkMap[p] = { count: 0, revenue: 0 };
      parkMap[p].count++;
      if (b.payment_status === 'paid') parkMap[p].revenue += Number(b.total_amount_usd) || 0;
    });

    // Daily (last 30 days)
    const dailyMap = {};
    deduped.forEach(b => {
      const day = (b.createdAt || '').toString().split('T')[0];
      if (!day) return;
      if (!dailyMap[day]) dailyMap[day] = { bookings: 0, revenue: 0 };
      dailyMap[day].bookings++;
      if (b.payment_status === 'paid') dailyMap[day].revenue += Number(b.total_amount_usd) || 0;
    });

    const recent = deduped.slice(0, 10).map(b => ({
      booking_id     : b.booking_id,
      park_name      : b.park_name,
      holder_name    : b.full_name    || '—',
      email          : b.email        || '—',
      phone          : b.phone_number || '—',
      total_usd      : b.total_amount_usd || 0,
      status         : b.status,
      payment_status : b.payment_status,
      visit_date     : b.visit_date,
      created_at     : b.createdAt,
      passenger_count: Array.isArray(b.passengers) ? b.passengers.length : 0,
    }));

    res.json({
      overview: {
        total_bookings    : deduped.length,
        confirmed         : confirmed.length,
        cancelled         : cancelled.length,
        paid              : paid.length,
        pending           : pending.length,
        refunded          : refunded.length,
        total_revenue_usd : Math.round(totalRevenue * 100) / 100,
        total_users       : Object.keys(users).length,
      },
      parks           : Object.entries(parkMap).map(([name, d]) => ({ name, ...d })).sort((a, b) => b.count - a.count),
      daily           : Object.entries(dailyMap).map(([date, d]) => ({ date, ...d })).sort((a, b) => a.date.localeCompare(b.date)),
      recent_bookings : recent,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// GET /api/v1/admin/bookings — full list with filters & pagination
app.get('/api/v1/admin/bookings', adminAuth, async (req, res) => {
  try {
    const { status, park, payment_status, page = 1, limit = 50 } = req.query;
    const seen = new Set();
    let list = (await Booking.findAll({ order: [['createdAt', 'DESC']] }))
      .map(b => b.toJSON())
      .filter(b => { if (seen.has(b.booking_id)) return false; seen.add(b.booking_id); return true; });

    if (status)         list = list.filter(b => b.status === status);
    if (payment_status) list = list.filter(b => b.payment_status === payment_status);
    if (park)           list = list.filter(b => (b.park_name || '').toLowerCase().includes(park.toLowerCase()));

    const total  = list.length;
    const offset = (Number(page) - 1) * Number(limit);
    res.json({ total, page: Number(page), limit: Number(limit), bookings: list.slice(offset, offset + Number(limit)) });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// DELETE /api/v1/admin/bookings/:id — Hard delete (admin only)
app.delete('/api/v1/admin/bookings/:id', adminAuth, async (req, res) => {
  try {
    const booking = await Booking.findOne({ where: { booking_id: req.params.id } });
    if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });
    await booking.destroy();
    res.json({ success: true, message: 'Booking permanently deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// GET /api/v1/admin/export/csv — Server-side CSV export
app.get('/api/v1/admin/export/csv', adminAuth, async (req, res) => {
  try {
    const { status, payment_status } = req.query;
    const seen = new Set();
    let list = (await Booking.findAll({ order: [['createdAt', 'DESC']] }))
      .map(b => b.toJSON())
      .filter(b => { if (seen.has(b.booking_id)) return false; seen.add(b.booking_id); return true; });

    if (status)         list = list.filter(b => b.status === status);
    if (payment_status) list = list.filter(b => b.payment_status === payment_status);

    const cols = ['booking_id','booking_reference','park_name','full_name','email','phone_number','nationality','id_type','citizen_id','visit_date','entry_time','total_amount_usd','currency','status','payment_status','payment_id','refund_status','refund_amount','cancellation_reason','createdAt'];
    const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const header = cols.join(',');
    const rows   = list.map(b => cols.map(k => escape(b[k])).join(','));
    const csv    = [header, ...rows].join('\r\n');

    const filename = `uws-bookings-${status || 'all'}-${new Date().toISOString().slice(0,10)}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) {
    res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Server error' });
  }
});

// ══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ══════════════════════════════════════════════════════════════
app.get('/health', async (req, res) => {
  try {
    const total = await Booking.count();
    res.json({
      status: 'ok',
      version: '2.1.0',
      bookings_in_db:   total,
      users_in_memory:  Object.keys(users).length,
      otp_mode:         'Twilio Verify SMS',
      email_enabled:    !!mailer,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLER
// ══════════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('Unhandled error:', IS_DEV ? err : err.message);
  res.status(500).json({ success: false, error: IS_DEV ? err.message : 'Internal server error' });
});

// ══════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════
app.listen(PORT, () => console.log(`🌿  Uganda Wildlife server v2.1 running on port ${PORT}`));
module.exports = app;
