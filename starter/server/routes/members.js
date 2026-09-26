import { bumpPermVersion, nowIso } from '../db.js';
import { assertCan } from '../permissions.js';
import {
  badRequest,
  forbidden,
  lastOwner,
  notFound,
  selfRoleChange,
  send,
} from '../http.js';

function memberRow(db, orgId, userId) {
  return db.prepare(
    `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version,
            m.invited_by, m.joined_at, u.email, u.name
       FROM memberships m
       JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.user_id = ?`
  ).get(orgId, userId);
}

function membershipResponse(row) {
  return {
    id: row.id,
    orgId: row.org_id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role: row.role,
    status: row.status,
    permVersion: row.perm_version,
    joinedAt: row.joined_at,
  };
}

function roleRank(db, role) {
  const row = db.prepare('SELECT rank FROM roles WHERE key = ?').get(role);
  if (!row) throw badRequest('role is invalid');
  return row.rank;
}

function ownerRole(db) {
  const row = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
  return row?.key;
}

function assertCanModifyTarget(db, ctx, target) {
  const callerRank = roleRank(db, ctx.role);
  const targetRank = roleRank(db, target.role);
  if (callerRank <= targetRank) throw forbidden('you cannot modify this member', 'scope_mismatch');
}

function assertNotLastOwner(db, orgId, targetRole) {
  if (targetRole !== ownerRole(db)) return;
  const count = db.prepare(
    `SELECT count(*) AS count
       FROM memberships
      WHERE org_id = ? AND role = ? AND status = 'active'`
  ).get(orgId, targetRole).count;
  if (count <= 1) throw lastOwner();
}

function endMemberSessions(db, orgId, userId, reason) {
  db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE org_id = ? AND user_id = ? AND state = 'active'`
  ).run(reason, nowIso(), orgId, userId);
}

function updateMembership(db, orgId, userId, changes, endReason = null) {
  const write = db.transaction(() => {
    const fields = Object.keys(changes);
    const values = Object.values(changes);
    db.prepare(
      `UPDATE memberships SET ${fields.map((field) => `${field} = ?`).join(', ')},
              perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?`
    ).run(...values, orgId, userId);
    if (endReason) endMemberSessions(db, orgId, userId, endReason);
  });
  write();
}

export function registerMemberRoutes(router, { db }) {
  router.get('/v1/orgs/:org/members', (ctx, _params, res) => {
    assertCan(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version,
              m.joined_at, u.email, u.name
         FROM memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status != 'removed'
        ORDER BY u.name, u.id`
    ).all(ctx.orgId).map(membershipResponse);
    send(res, 200, { members });
  });

  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    assertCan(db, ctx, 'user:role:update');
    if (params.userId === ctx.userId) throw selfRoleChange();
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    const role = typeof ctx.body.role === 'string' ? ctx.body.role.trim() : '';
    if (!role) throw badRequest('role is required');
    roleRank(db, role);
    const owner = ownerRole(db);
    const ownerDemotion = ctx.role === owner && target.role === owner && role !== owner;
    if (!ownerDemotion) assertCanModifyTarget(db, ctx, target);
    if (role === owner && ctx.role !== owner) {
      throw forbidden('only an owner may assign owner', 'scope_mismatch');
    }
    if (target.role === owner && role !== target.role) {
      assertNotLastOwner(db, ctx.orgId, target.role);
    }
    updateMembership(db, ctx.orgId, params.userId, { role });
    send(res, 200, { membership: membershipResponse(memberRow(db, ctx.orgId, params.userId)) });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    if (params.userId === ctx.userId) throw forbidden('you cannot suspend yourself', 'scope_mismatch');
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    assertCanModifyTarget(db, ctx, target);
    assertNotLastOwner(db, ctx.orgId, target.role);
    updateMembership(db, ctx.orgId, params.userId, { status: 'suspended' }, 'user_suspended');
    send(res, 200, { membership: membershipResponse(memberRow(db, ctx.orgId, params.userId)) });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    if (params.userId === ctx.userId) throw forbidden('you cannot reinstate yourself', 'scope_mismatch');
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status !== 'suspended') throw notFound();
    assertCanModifyTarget(db, ctx, target);
    updateMembership(db, ctx.orgId, params.userId, { status: 'active' });
    send(res, 200, { membership: membershipResponse(memberRow(db, ctx.orgId, params.userId)) });
  });

  router.delete('/v1/orgs/:org/members/me', (ctx, _params, res) => {
    const target = memberRow(db, ctx.orgId, ctx.userId);
    if (!target || target.status !== 'active') throw notFound();
    assertNotLastOwner(db, ctx.orgId, target.role);
    updateMembership(db, ctx.orgId, ctx.userId, { status: 'removed' }, 'membership_removed');
    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    if (params.userId === ctx.userId) throw forbidden('use the self-leave route', 'scope_mismatch');
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    assertCanModifyTarget(db, ctx, target);
    assertNotLastOwner(db, ctx.orgId, target.role);
    updateMembership(db, ctx.orgId, params.userId, { status: 'removed' }, 'membership_removed');
    send(res, 200, { ok: true });
  });
}
