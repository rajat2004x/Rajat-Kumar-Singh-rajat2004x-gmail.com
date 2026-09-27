import { nowIso } from '../db.js';
import { assertCan } from '../permissions.js';
import { resolve } from '../permissions.js';
import { assertCanModify, assertNotLastOwner, assertRoleExists, endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
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

function updateMembership(db, orgId, userId, changes, endReason = null, auditMeta = null) {
  const write = db.transaction(() => {
    const fields = Object.keys(changes);
    const values = Object.values(changes);
    db.prepare(
      `UPDATE memberships SET ${fields.map((field) => `${field} = ?`).join(', ')},
              perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?`
    ).run(...values, orgId, userId);
    if (endReason) endActiveSessions(db, { orgId, userId, reason: endReason });
    if (auditMeta) audit(db, auditMeta);
  });
  write();
}

export function registerMemberRoutes(router, { db }) {
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    const target = db.prepare(
      `SELECT user_id
         FROM memberships
        WHERE org_id = ? AND user_id = ? AND status IN ('active', 'suspended')`
    ).get(ctx.orgId, params.userId);
    if (!target) throw notFound();

    if (params.userId !== ctx.userId) {
      auditDenials(db, ctx, {
        action: 'member.effective', targetType: 'membership', targetId: params.userId,
      }, () => assertCan(db, ctx, 'user:read'));
    }

    const effective = resolve(db, {
      userId: params.userId,
      orgId: ctx.orgId,
    });
    send(res, 200, {
      role: effective.role,
      permissions: effective.permissions,
    });
  });

  router.get('/v1/orgs/:org/members', (ctx, _params, res) => {
    auditDenials(db, ctx, {
      action: 'member.list', targetType: 'organization', targetId: ctx.orgId,
    }, () => assertCan(db, ctx, 'user:read'));
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
    auditDenials(db, ctx, {
      action: 'member.role_update', targetType: 'membership', targetId: params.userId,
    }, () => assertCan(db, ctx, 'user:role:update'));
    if (params.userId === ctx.userId) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.role_update',
        targetType: 'membership', targetId: params.userId, result: 'deny',
        reasonCode: 'scope_mismatch', requestId: ctx.requestId,
      });
      throw selfRoleChange();
    }
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    const role = typeof ctx.body.role === 'string' ? ctx.body.role.trim() : '';
    if (!role) throw badRequest('role is required');
    assertRoleExists(db, role);
    const owner = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get()?.key;
    const ownerDemotion = ctx.role === owner && target.role === owner && role !== owner;
    if (!ownerDemotion) auditDenials(db, ctx, {
      action: 'member.role_update', targetType: 'membership', targetId: params.userId,
    }, () => assertCanModify(db, ctx.role, target.role));
    if (role === owner && ctx.role !== owner) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.role_update',
        targetType: 'membership', targetId: params.userId, result: 'deny',
        reasonCode: 'scope_mismatch', requestId: ctx.requestId,
      });
      throw forbidden('only an owner may assign owner', 'scope_mismatch');
    }
    if (target.role === owner && role !== target.role) {
      auditDenials(db, ctx, {
        action: 'member.role_update', targetType: 'membership', targetId: params.userId,
      }, () => assertNotLastOwner(db, ctx.orgId, params.userId));
    }
    updateMembership(db, ctx.orgId, params.userId, { role }, null, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'member.role_update',
      targetType: 'membership', targetId: params.userId, result: 'allow', requestId: ctx.requestId,
    });
    send(res, 200, { membership: membershipResponse(memberRow(db, ctx.orgId, params.userId)) });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    auditDenials(db, ctx, {
      action: 'member.suspend', targetType: 'membership', targetId: params.userId,
    }, () => assertCan(db, ctx, 'user:remove'));
    if (params.userId === ctx.userId) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.suspend',
        targetType: 'membership', targetId: params.userId, result: 'deny',
        reasonCode: 'scope_mismatch', requestId: ctx.requestId,
      });
      throw forbidden('you cannot suspend yourself', 'scope_mismatch');
    }
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    auditDenials(db, ctx, {
      action: 'member.suspend', targetType: 'membership', targetId: params.userId,
    }, () => assertCanModify(db, ctx.role, target.role));
    auditDenials(db, ctx, {
      action: 'member.suspend', targetType: 'membership', targetId: params.userId,
    }, () => assertNotLastOwner(db, ctx.orgId, params.userId));
    updateMembership(db, ctx.orgId, params.userId, { status: 'suspended' }, 'user_suspended', {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'member.suspend',
      targetType: 'membership', targetId: params.userId, result: 'allow', requestId: ctx.requestId,
    });
    send(res, 200, { membership: membershipResponse(memberRow(db, ctx.orgId, params.userId)) });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    auditDenials(db, ctx, {
      action: 'member.reinstate', targetType: 'membership', targetId: params.userId,
    }, () => assertCan(db, ctx, 'user:remove'));
    if (params.userId === ctx.userId) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.reinstate',
        targetType: 'membership', targetId: params.userId, result: 'deny',
        reasonCode: 'scope_mismatch', requestId: ctx.requestId,
      });
      throw forbidden('you cannot reinstate yourself', 'scope_mismatch');
    }
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status !== 'suspended') throw notFound();
    auditDenials(db, ctx, {
      action: 'member.reinstate', targetType: 'membership', targetId: params.userId,
    }, () => assertCanModify(db, ctx.role, target.role));
    updateMembership(db, ctx.orgId, params.userId, { status: 'active' }, null, {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'member.reinstate',
      targetType: 'membership', targetId: params.userId, result: 'allow', requestId: ctx.requestId,
    });
    send(res, 200, { membership: membershipResponse(memberRow(db, ctx.orgId, params.userId)) });
  });

  router.delete('/v1/orgs/:org/members/me', (ctx, _params, res) => {
    const target = memberRow(db, ctx.orgId, ctx.userId);
    if (!target || target.status !== 'active') throw notFound();
    auditDenials(db, ctx, {
      action: 'member.leave', targetType: 'membership', targetId: ctx.userId,
    }, () => assertNotLastOwner(db, ctx.orgId, ctx.userId));
    updateMembership(db, ctx.orgId, ctx.userId, { status: 'removed' }, 'membership_removed', {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'member.leave',
      targetType: 'membership', targetId: ctx.userId, result: 'allow', requestId: ctx.requestId,
    });
    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    auditDenials(db, ctx, {
      action: 'member.remove', targetType: 'membership', targetId: params.userId,
    }, () => assertCan(db, ctx, 'user:remove'));
    if (params.userId === ctx.userId) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'member.remove',
        targetType: 'membership', targetId: params.userId, result: 'deny',
        reasonCode: 'scope_mismatch', requestId: ctx.requestId,
      });
      throw forbidden('use the self-leave route', 'scope_mismatch');
    }
    const target = memberRow(db, ctx.orgId, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    auditDenials(db, ctx, {
      action: 'member.remove', targetType: 'membership', targetId: params.userId,
    }, () => assertCanModify(db, ctx.role, target.role));
    auditDenials(db, ctx, {
      action: 'member.remove', targetType: 'membership', targetId: params.userId,
    }, () => assertNotLastOwner(db, ctx.orgId, params.userId));
    updateMembership(db, ctx.orgId, params.userId, { status: 'removed' }, 'membership_removed', {
      orgId: ctx.orgId, actorId: ctx.userId, action: 'member.remove',
      targetType: 'membership', targetId: params.userId, result: 'allow', requestId: ctx.requestId,
    });
    send(res, 200, { ok: true });
  });
}
