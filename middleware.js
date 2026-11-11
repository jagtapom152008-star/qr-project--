'use strict';

/**
 * requireAuth — redirect to /login if the user is not signed in.
 * Attach this to any route that needs a logged-in user.
 */
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  // Remember where they were trying to go
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

/**
 * requireAdmin — only allow users with role === 'admin'.
 */
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') return next();
  res.status(403).json({ error: 'Forbidden' });
}

module.exports = { requireAuth, requireAdmin };
