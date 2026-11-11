'use strict';

require('dotenv').config();

const express   = require('express');
const path      = require('path');
const helmet    = require('helmet');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');

const { router: authRouter, passport } = require('./auth');
const { requireAuth }                  = require('./middleware');
const { users }                        = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY HEADERS ──────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", 'https://cdnjs.cloudflare.com', "'sha256-l+rJfO1vJtJWuTBzfP6sgTVJfN8otD/rhNIE6WgPm6E='"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:', 'blob:', 'https://lh3.googleusercontent.com'],
      connectSrc: ["'self'"],
    },
  },
}));

// ── BODY PARSING ──────────────────────────────────────────
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// ── SESSION ───────────────────────────────────────────────
// Using in-memory store for local development.
// For production, swap this for a persistent store (e.g. connect-sqlite3).
app.use(session({
  secret:            process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge:   7 * 24 * 60 * 60 * 1000,
  },
}));

// ── PASSPORT ──────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ── RATE LIMITING ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      20,
  message:  { error: 'Too many attempts. Wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders:   false,
});
app.use('/auth/login',    authLimiter);
app.use('/auth/register', authLimiter);

// ── AUTH ROUTES ───────────────────────────────────────────
app.use('/auth', authRouter);

// ── PAGE ROUTES ───────────────────────────────────────────
app.get('/login',    (req, res) => res.redirect('/app'));
app.get('/register', (req, res) => res.redirect('/app'));
app.get('/about',                    (req, res) => res.sendFile(path.join(__dirname, 'about.html')));
app.get('/app',                       (req, res) => res.sendFile(path.join(__dirname, 'qr-checker.html')));
app.get('/',                          (req, res) => res.redirect('/app'));

// ── STATIC ASSETS ─────────────────────────────────────────
// Serve everything except raw .html files (those go through page routes)
app.use(express.static(__dirname, {
  index: false,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.status(404).end();
  },
}));

// ── ADMIN API ─────────────────────────────────────────────
const { requireAdmin } = require('./middleware');
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json(users.list());
});

// ── 404 ───────────────────────────────────────────────────
app.use((req, res) => res.status(404).send('Not found'));

// ── ERROR HANDLER ─────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ── START ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\nCyberForge QR Checker running at http://localhost:${PORT}`);
  console.log(`  Checker:   http://localhost:${PORT}/app`);
  console.log(`  About:     http://localhost:${PORT}/about\n`);
});
