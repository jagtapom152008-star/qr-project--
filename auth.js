'use strict';

const express  = require('express');
const bcrypt   = require('bcryptjs');
const passport = require('passport');
const { Strategy: LocalStrategy }  = require('passport-local');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { users, loginLog } = require('./db');

const router = express.Router();
const SALT_ROUNDS = 10;

// ── PASSPORT SERIALISATION ────────────────────────────────

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
  try {
    const user = users.findById(id);
    done(null, user || false);
  } catch (err) {
    done(err);
  }
});

// ── LOCAL STRATEGY ────────────────────────────────────────

passport.use(new LocalStrategy(
  { usernameField: 'username', passwordField: 'password' },
  (username, password, done) => {
    try {
      const user = users.findByUsername(username) || users.findByEmail(username);
      if (!user || !user.passwordHash) {
        return done(null, false, { message: 'Incorrect username or password.' });
      }
      const match = bcrypt.compareSync(password, user.passwordHash);
      if (!match) {
        return done(null, false, { message: 'Incorrect username or password.' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// ── GOOGLE STRATEGY ───────────────────────────────────────

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy(
    {
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      try {
        const email       = profile.emails?.[0]?.value || '';
        const displayName = profile.displayName || email;
        const avatarUrl   = profile.photos?.[0]?.value || '';

        // 1. Already linked by Google ID
        let user = users.findByGoogleId(profile.id);
        if (user) { users.updateLastLogin(user.id); return done(null, user); }

        // 2. Existing account with same email — link it
        user = users.findByEmail(email);
        if (user) {
          users.linkGoogle(user.id, profile.id, avatarUrl);
          users.updateLastLogin(user.id);
          return done(null, users.findById(user.id));
        }

        // 3. New user
        user = users.createFromGoogle({ email, googleId: profile.id, displayName, avatarUrl });
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));
}

// ── ROUTES ────────────────────────────────────────────────

/* POST /auth/register */
router.post('/register', async (req, res) => {
  const { username, email, password, confirm } = req.body;
  const errors = [];

  if (!username || username.trim().length < 3)
    errors.push('Username must be at least 3 characters.');
  if (!email || !email.includes('@'))
    errors.push('Enter a valid email address.');
  if (!password || password.length < 8)
    errors.push('Password must be at least 8 characters.');
  if (password !== confirm)
    errors.push('Passwords do not match.');

  if (errors.length) return res.status(400).json({ errors });

  try {
    if (users.findByUsername(username.trim()))
      return res.status(409).json({ errors: ['That username is already taken.'] });
    if (users.findByEmail(email))
      return res.status(409).json({ errors: ['An account with that email already exists.'] });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = users.create({
      username:     username.trim(),
      email:        email.toLowerCase().trim(),
      passwordHash: hash,
      displayName:  username.trim(),
    });

    req.login(user, err => {
      if (err) return res.status(500).json({ errors: ['Sign-in after registration failed. Please sign in manually.'] });
      loginLog.add({ userId: user.id, method: 'local', ip: req.ip, success: true });
      res.json({ ok: true, redirect: '/app' });
    });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ errors: ['Something went wrong. Try again.'] });
  }
});

/* POST /auth/login */
router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      loginLog.add({ userId: null, method: 'local', ip: req.ip, success: false, reason: info?.message });
      return res.status(401).json({ error: info?.message || 'Incorrect username or password.' });
    }
    req.login(user, err => {
      if (err) return next(err);
      users.updateLastLogin(user.id);
      loginLog.add({ userId: user.id, method: 'local', ip: req.ip, success: true });
      const returnTo = req.session.returnTo || '/app';
      delete req.session.returnTo;
      res.json({ ok: true, redirect: returnTo });
    });
  })(req, res, next);
});

/* POST /auth/logout */
router.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

/* GET /auth/google */
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

/* GET /auth/google/callback */
router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login?error=google' }),
  (req, res) => {
    users.updateLastLogin(req.user.id);
    loginLog.add({ userId: req.user.id, method: 'google', ip: req.ip, success: true });
    const returnTo = req.session.returnTo || '/app';
    delete req.session.returnTo;
    res.redirect(returnTo);
  }
);

/* GET /auth/me */
router.get('/me', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not signed in' });
  const { id, username, email, displayName, avatarUrl, role, createdAt, lastLogin } = req.user;
  res.json({ id, username, email, displayName, avatarUrl, role, createdAt, lastLogin });
});

module.exports = { router, passport };
