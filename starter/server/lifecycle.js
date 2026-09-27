// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { nowIso } from './db.js';
import { badRequest, forbidden, lastOwner } from './http.js';

const END_REASONS = new Set([
  'user_stopped',
  'user_suspended',
  'membership_removed',
  'device_transferred',
  'admin_terminated',
  'session_expired',
  'superseded',
]);

export function roleRanks(db) {
  return Object.fromEntries(
    db.prepare('SELECT key, rank FROM roles ORDER BY rank DESC, key').all()
      .map((row) => [row.key, row.rank])
  );
}

export function assertRoleExists(db, role) {
  const row = db.prepare('SELECT key, rank FROM roles WHERE key = ?').get(role);
  if (!row) throw badRequest('role is invalid');
  return row;
}

export function assertCanModify(db, callerRole, targetRole) {
  const caller = assertRoleExists(db, callerRole);
  const target = assertRoleExists(db, targetRole);
  if (caller.rank <= target.rank) throw forbidden('you cannot modify this member', 'scope_mismatch');
  return true;
}

export function assertNotLastOwner(db, orgId, userId) {
  const target = db.prepare(
    `SELECT role
       FROM memberships
      WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).get(orgId, userId);
  if (!target) return true;

  const highest = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
  if (!highest || target.role !== highest.key) return true;

  const count = db.prepare(
    `SELECT count(*) AS count
       FROM memberships
      WHERE org_id = ? AND role = ? AND status = 'active'`
  ).get(orgId, highest.key).count;
  if (count <= 1) throw lastOwner();
  return true;
}

export function endActiveSessions(db, {
  orgId,
  userId,
  deviceId,
  reason,
  exceptSessionId,
  sessionId,
}) {
  if (!END_REASONS.has(reason)) throw badRequest('session end reason is invalid');
  const conditions = ['org_id = ?', "state = 'active'"];
  const values = [orgId];
  if (userId !== undefined) {
    conditions.push('user_id = ?');
    values.push(userId);
  }
  if (deviceId !== undefined) {
    conditions.push('device_id = ?');
    values.push(deviceId);
  }
  if (exceptSessionId !== undefined) {
    conditions.push('id != ?');
    values.push(exceptSessionId);
  }
  if (sessionId !== undefined) {
    conditions.push('id = ?');
    values.push(sessionId);
  }
  if (values.length === 1) throw badRequest('session termination scope is required');

  const at = nowIso();
  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE ${conditions.join(' AND ')}`
  ).run(reason, at, ...values).changes;
}

export function endExpiredSessions(db, orgId, at = nowIso()) {
  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = 'session_expired', ended_at = ?
      WHERE org_id = ? AND state = 'active' AND expires_at <= ?`
  ).run(at, orgId, at).changes;
}

export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db.prepare(
    `SELECT role
       FROM memberships
      WHERE user_id = ? AND org_id = ? AND status = 'active'`
  ).get(userId, orgId);
  if (!membership) throw badRequest('active membership is required');

  const at = nowIso();
  const grantIds = db.prepare(
    `SELECT DISTINCT g.id
       FROM grants g
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.device_id IS NULL OR g.device_id = ?)
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR ? < g.expires_at)
      ORDER BY g.id`
  ).all(userId, orgId, deviceId, at, at).map((row) => row.id);

  return { role: membership.role, grantIds, snapshotAt: at };
}

export function sessionExpiry(db, orgId, startedAt = nowIso()) {
  const organization = db.prepare(
    'SELECT max_session_minutes FROM organizations WHERE id = ? AND deleted_at IS NULL'
  ).get(orgId);
  if (!organization) throw badRequest('organization is invalid');
  return new Date(
    Date.parse(startedAt) + Number(organization.max_session_minutes) * 60_000
  ).toISOString();
}
