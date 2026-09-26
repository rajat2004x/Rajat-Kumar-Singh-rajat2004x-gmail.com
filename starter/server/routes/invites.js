import { randomUUID } from 'node:crypto';

import {
  hashInviteToken,
  hashRefreshToken,
  hashPassword,
  issueAccessToken,
  newInviteToken,
  newRefreshToken,
} from '../auth.js';
import { newId, nowIso } from '../db.js';
import { assertCan } from '../permissions.js';
import {
  badRequest,
  conflict,
  forbidden,
  gone,
  notFound,
  send,
} from '../http.js';

const INVITE_TTL_DAYS = 7;
const REFRESH_TTL_DAYS = 30;

function text(value, field) {
  if (typeof value !== 'string' || value.trim() === '') throw badRequest(`${field} is required`);
  return value.trim();
}

function role(db, key) {
  const row = db.prepare('SELECT key, rank FROM roles WHERE key = ?').get(key);
  if (!row) throw badRequest('role is invalid');
  return row;
}

function topRole(db) {
  return db.prepare('SELECT key, rank FROM roles ORDER BY rank DESC LIMIT 1').get();
}

function inviteRow(db, tokenHash) {
  return db.prepare(
    `SELECT i.id, i.org_id, i.email, i.role, i.token_hash, i.invited_by,
            i.expires_at, i.accepted_at, i.accepted_by, i.revoked_at,
            o.name AS org_name
       FROM invites i
       JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ? AND o.deleted_at IS NULL`
  ).get(tokenHash);
}

function publicInvite(row) {
  return {
    orgName: row.org_name,
    role: row.role,
    email: row.email,
    expiresAt: row.expires_at,
  };
}

function ensureLiveInvite(row) {
  if (!row) throw notFound();
  if (row.accepted_at) throw conflict('invite has already been accepted');
  if (row.revoked_at || row.expires_at <= nowIso()) throw gone();
}

function storeRefreshToken(db, userId, res) {
  const raw = newRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 86_400_000).toISOString();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(newId('rt'), userId, hashRefreshToken(raw), randomUUID(), expiresAt);
  res.setHeader(
    'set-cookie',
    `rt=${raw}; Max-Age=${REFRESH_TTL_DAYS * 24 * 60 * 60}; Path=/; HttpOnly; SameSite=Strict; Secure`
  );
}

export function registerInviteRoutes(router, { db, secret }) {
  router.post('/v1/orgs/:org/invites', (ctx, _params, res) => {
    assertCan(db, ctx, 'user:invite');
    const email = text(ctx.body.email, 'email').toLowerCase();
    const invitedRole = role(db, text(ctx.body.role, 'role'));
    const callerRole = role(db, ctx.role);
    const owner = topRole(db);
    if (invitedRole.rank >= callerRole.rank || (invitedRole.key === owner.key && callerRole.key !== owner.key)) {
      throw forbidden('you cannot assign this role', 'scope_mismatch');
    }

    const existingUser = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email);
    if (existingUser && db.prepare(
      `SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, existingUser.id)) {
      throw conflict('user is already a member');
    }

    const rawToken = newInviteToken();
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 86_400_000).toISOString();
    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(newId('inv'), ctx.orgId, email, invitedRole.key, hashInviteToken(rawToken), ctx.userId, expiresAt);
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('a live invite already exists');
      throw error;
    }
    send(res, 201, { inviteToken: rawToken, email, role: invitedRole.key, expiresAt });
  });

  router.get('/v1/orgs/:org/invites', (ctx, _params, res) => {
    assertCan(db, ctx, 'user:invite');
    const invites = db.prepare(
      `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
         FROM invites
        WHERE org_id = ?
        ORDER BY created_at DESC, id DESC`
    ).all(ctx.orgId).map((row) => ({
      id: row.id,
      email: row.email,
      role: row.role,
      expiresAt: row.expires_at,
      acceptedAt: row.accepted_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
    }));
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const invite = db.prepare(
      'SELECT id FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL'
    ).get(params.id, ctx.orgId);
    if (!invite) throw notFound();
    db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ? AND org_id = ?').run(nowIso(), invite.id, ctx.orgId);
    send(res, 200, { ok: true });
  });

  router.get('/v1/invites/:token', (ctx, params, res) => {
    const invite = inviteRow(db, hashInviteToken(params.token));
    ensureLiveInvite(invite);
    send(res, 200, publicInvite(invite));
  });

  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const invite = inviteRow(db, hashInviteToken(params.token));
    ensureLiveInvite(invite);
    const name = text(ctx.body.name, 'name');
    const password = text(ctx.body.password, 'password');
    const acceptedAt = nowIso();
    let userId;
    let membership;
    const complete = db.transaction(() => {
      const existing = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(invite.email);
      userId = existing?.id ?? newId('usr');
      if (!existing) {
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(userId, invite.email, name, hashPassword(password));
      }

      const current = db.prepare(
        'SELECT org_id, user_id, role, status, perm_version FROM memberships WHERE org_id = ? AND user_id = ?'
      ).get(invite.org_id, userId);
      if (current?.status === 'active') throw conflict('user is already a member');
      if (current) {
        db.prepare(
          `UPDATE memberships
              SET role = ?, status = 'active', invited_by = ?, joined_at = ?, perm_version = perm_version + 1
            WHERE org_id = ? AND user_id = ?`
        ).run(invite.role, invite.invited_by, acceptedAt, invite.org_id, userId);
      } else {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?)`
          ).run(newId('mem'), invite.org_id, userId, invite.role, invite.invited_by, acceptedAt);
      }
      membership = db.prepare(
        'SELECT org_id, user_id, role, perm_version FROM memberships WHERE org_id = ? AND user_id = ?'
      ).get(invite.org_id, userId);
      db.prepare(
        'UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL'
      ).run(acceptedAt, userId, invite.id);
      storeRefreshToken(db, userId, res);
    });
    complete();
    const token = issueAccessToken({
      userId,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);
    send(res, 200, { token, role: membership.role });
  });
}
