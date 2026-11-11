'use strict';

/**
 * db.js — lightweight JSON file store using lowdb v1 (pure JS, no native modules).
 * Data is stored in data/db.json. All reads/writes are synchronous via lowdb's
 * LodashSync adapter.
 */

const path = require('path');
const fs   = require('fs');
const low  = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const adapter = new FileSync(path.join(dataDir, 'db.json'));
const db      = low(adapter);

// ── DEFAULTS ──────────────────────────────────────────────
db.defaults({
  users:     [],
  loginLogs: [],
}).write();

// ── HELPERS ───────────────────────────────────────────────
const { v4: uuidv4 } = require('uuid');

function now() { return Date.now(); }

const users = {
  findById(id) {
    return db.get('users').find({ id }).value() || null;
  },
  findByEmail(email) {
    return db.get('users').find(u => u.email === email.toLowerCase().trim()).value() || null;
  },
  findByUsername(username) {
    return db.get('users').find(u => u.username === username.trim()).value() || null;
  },
  findByGoogleId(googleId) {
    return db.get('users').find({ googleId }).value() || null;
  },

  create({ username, email, passwordHash, displayName }) {
    const user = {
      id:           uuidv4(),
      username:     username ? username.trim() : null,
      email:        email.toLowerCase().trim(),
      passwordHash: passwordHash || null,
      googleId:     null,
      displayName:  displayName || username || email,
      avatarUrl:    null,
      role:         'user',
      createdAt:    now(),
      lastLogin:    null,
    };
    db.get('users').push(user).write();
    return user;
  },

  createFromGoogle({ email, googleId, displayName, avatarUrl }) {
    const user = {
      id:           uuidv4(),
      username:     null,
      email:        email.toLowerCase().trim(),
      passwordHash: null,
      googleId,
      displayName:  displayName || email,
      avatarUrl:    avatarUrl || null,
      role:         'user',
      createdAt:    now(),
      lastLogin:    null,
    };
    db.get('users').push(user).write();
    return user;
  },

  linkGoogle(id, googleId, avatarUrl) {
    db.get('users').find({ id }).assign({ googleId, avatarUrl }).write();
  },

  updateLastLogin(id) {
    db.get('users').find({ id }).assign({ lastLogin: now() }).write();
  },

  list() {
    return db.get('users').map(u => ({
      id:          u.id,
      username:    u.username,
      email:       u.email,
      displayName: u.displayName,
      hasGoogle:   !!u.googleId,
      role:        u.role,
      createdAt:   u.createdAt,
      lastLogin:   u.lastLogin,
    })).value();
  },
};

const loginLog = {
  add({ userId, method, ip, success, reason }) {
    db.get('loginLogs').push({
      id:        uuidv4(),
      userId:    userId || null,
      method,
      ip:        ip || null,
      success:   !!success,
      reason:    reason || null,
      createdAt: now(),
    }).write();
  },
};

module.exports = { users, loginLog };
