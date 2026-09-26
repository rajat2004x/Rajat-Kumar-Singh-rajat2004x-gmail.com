import { randomUUID } from 'node:crypto';

import {
  hashRefreshToken,
  issueAccessToken,
  newRefreshToken,
  verifyPassword,
} from '../auth.js';
import { newId } from '../db.js';
import { badRequest, notFound, send, unauthenticated } from '../http.js';
import { resolve } from '../permissions.js';

const REFRESH_COOKIE = 'rt';
const REFRESH_MAX_AGE = 30 * 24 * 60 * 60;

function requireText(value, field) {
  if (typeof value !== 'string' || value.trim() === '') throw badRequest(`${field} is required`);
  return value.trim();
}

function organizationFromRow(row) {
  return {
    id: row.org_id,
    name: row.org_name,
    theme: row.theme,
    max_session_minutes: row.max_session_minutes,
  };
}

function membershipsForUser(db, userId) {
  return db.prepare(
    `SELECT m.org_id, m.role, o.name AS org_name, o.theme, o.max_session_minutes
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY o.id`
  ).all(userId);
}

function selectMembership(db, userId, orgId) {
  const query = orgId
    ? `SELECT m.org_id, m.user_id, m.role, m.perm_version,
              o.name AS org_name, o.theme, o.max_session_minutes
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    : `SELECT m.org_id, m.user_id, m.role, m.perm_version,
              o.name AS org_name, o.theme, o.max_session_minutes
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.id
        LIMIT 1`;
  return orgId ? db.prepare(query).get(userId, orgId) : db.prepare(query).get(userId);
}

function publicOrganizations(db, userId) {
  return membershipsForUser(db, userId).map((row) => ({
    ...organizationFromRow(row),
    role: row.role,
  }));
}

function issueRefresh(db, userId, membership, secret, res, familyId = randomUUID()) {
  const raw = newRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_MAX_AGE * 1000).toISOString();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(newId('rt'), userId, hashRefreshToken(raw), familyId, expiresAt);
  res.setHeader(
    'set-cookie',
    `${REFRESH_COOKIE}=${raw}; Max-Age=${REFRESH_MAX_AGE}; Path=/; HttpOnly; SameSite=Strict; Secure`
  );
  return issueAccessToken({
    userId,
    orgId: membership.org_id,
    role: membership.role,
    permVersion: membership.perm_version,
  }, secret);
}

function parseRefreshCookie(req) {
  const cookie = req.headers?.cookie;
  if (typeof cookie !== 'string') return null;
  for (const part of cookie.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    const name = part.slice(0, separator).trim();
    if (name === REFRESH_COOKIE) return part.slice(separator + 1).trim() || null;
  }
  return null;
}

function loginResponse(db, user, membership, token) {
  return {
    token,
    user: { id: user.id, email: user.email, name: user.name },
    org: organizationFromRow(membership),
    role: membership.role,
    orgs: publicOrganizations(db, user.id),
  };
}

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const email = requireText(ctx.body.email, 'email').toLowerCase();
    const password = typeof ctx.body.password === 'string' ? ctx.body.password : '';
    const user = db.prepare(
      'SELECT id, email, name, password_hash FROM users WHERE email = ? COLLATE NOCASE'
    ).get(email);
    const validPassword = user ? verifyPassword(password, user.password_hash) : false;
    if (!user || !validPassword) throw unauthenticated('invalid email or password');

    const orgId = ctx.body.orgId === undefined ? undefined : requireText(ctx.body.orgId, 'orgId');
    const membership = selectMembership(db, user.id, orgId);
    if (!membership) throw unauthenticated('invalid email or password');

    const token = issueRefresh(db, user.id, membership, secret, res);
    send(res, 200, loginResponse(db, user, membership, token));
  });

  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = parseRefreshCookie(ctx.req);
    if (!raw) throw unauthenticated('invalid refresh token');

    const hash = hashRefreshToken(raw);
    const stored = db.prepare(
      'SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?'
    ).get(hash);
    if (!stored) throw unauthenticated('invalid refresh token');

    const now = new Date().toISOString();
    if (stored.revoked_at) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?')
        .run(now, stored.family_id);
      throw unauthenticated('invalid refresh token');
    }
    if (stored.expires_at <= now) throw unauthenticated('invalid refresh token');

    const membership = selectMembership(db, stored.user_id);
    if (!membership) throw unauthenticated('invalid refresh token');

    const rotate = db.transaction(() => {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(now, stored.id);
      const token = issueRefresh(db, stored.user_id, membership, secret, res, stored.family_id);
      return token;
    });
    send(res, 200, { token: rotate() });
  });

  router.post('/v1/auth/token', (ctx, _params, res) => {
    const orgId = requireText(ctx.body.orgId, 'orgId');
    const membership = selectMembership(db, ctx.userId, orgId);
    if (!membership) throw notFound();
    const token = issueAccessToken({
      userId: ctx.userId,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);
    send(res, 200, {
      token,
      org: organizationFromRow(membership),
      role: membership.role,
      orgs: publicOrganizations(db, ctx.userId),
    });
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const permissions = resolve(db, { userId: ctx.userId, orgId: ctx.orgId });
    send(res, 200, {
      user: ctx.user,
      org: ctx.organization,
      role: ctx.role,
      orgs: publicOrganizations(db, ctx.userId),
      permissions: permissions.permissions,
    });
  });
}
