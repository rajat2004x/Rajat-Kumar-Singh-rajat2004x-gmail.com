import { can, assertCan, assertMayGrant, resolveDevices } from '../permissions.js';
import { bumpPermVersion, newId, nowIso } from '../db.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';
import { badRequest, conflict, forbidden, notFound, normalizeTs, send } from '../http.js';

const DEVICE_KINDS = new Set(['macos', 'windows', 'linux', 'android', 'ios']);

function text(value, field) {
  if (typeof value !== 'string' || value.trim() === '') throw badRequest(`${field} is required`);
  return value.trim();
}

function deviceFromRow(row, permissions) {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    online: Boolean(row.online),
    permissions,
  };
}

function findDevice(db, orgId, deviceId) {
  return db.prepare(
    `SELECT id, org_id, name, kind, online
       FROM devices
      WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
  ).get(deviceId, orgId);
}

function validateKind(kind) {
  if (typeof kind !== 'string' || !DEVICE_KINDS.has(kind)) throw badRequest('kind is invalid');
  return kind;
}

function validateOnline(online) {
  if (typeof online !== 'boolean') throw badRequest('online must be a boolean');
  return online ? 1 : 0;
}

function grantFromRow(row) {
  return {
    id: row.id,
    userId: row.user_id,
    deviceId: row.device_id,
    effect: row.effect,
    permissions: row.permissions,
    startsAt: row.starts_at,
    expiresAt: row.expires_at,
    createdBy: row.created_by,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

function grantRow(db, id, orgId) {
  return db.prepare(
    `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at,
            g.created_by, g.revoked_at, g.created_at,
            GROUP_CONCAT(gp.permission) AS permission_list
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.id = ? AND g.org_id = ?
      GROUP BY g.id`
  ).get(id, orgId);
}

function grantResponseRow(row) {
  return grantFromRow({
    ...row,
    permissions: row.permission_list ? row.permission_list.split(',') : [],
  });
}

function validateGrantPermissions(db, permissions) {
  if (!Array.isArray(permissions) || permissions.length === 0 || permissions.some((item) => typeof item !== 'string')) {
    throw badRequest('permissions must be a non-empty array', 'unknown_permission');
  }
  const known = new Set(
    db.prepare('SELECT pattern FROM permission_patterns').all().map((row) => row.pattern)
  );
  if (permissions.some((permission) => !known.has(permission))) {
    throw badRequest('unknown permission', 'unknown_permission');
  }
  return [...new Set(permissions)];
}

function activeMember(db, orgId, userId) {
  return db.prepare(
    `SELECT user_id
       FROM memberships
      WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).get(orgId, userId);
}

export function registerDeviceRoutes(router, { db }) {
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    auditDenials(db, ctx, {
      action: 'device.list', targetType: 'organization', targetId: ctx.orgId,
    }, () => assertCan(db, ctx, 'device:list'));
    const rows = db.prepare(
      `SELECT id, org_id, name, kind, online
         FROM devices
        WHERE org_id = ? AND deleted_at IS NULL
        ORDER BY id`
    ).all(ctx.orgId);
    const resolved = resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds: rows.map((row) => row.id),
    });
    const devices = rows
      .filter((row) => resolved.byDevice[row.id]['device:view'].effect === 'allow')
      .map((row) => deviceFromRow(row, resolved.byDevice[row.id]));
    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const row = findDevice(db, ctx.orgId, params.id);
    if (!row || !can(db, ctx, 'device:view', row.id)) throw notFound();
    const permissions = resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds: [row.id],
    }).byDevice[row.id];
    send(res, 200, { device: deviceFromRow(row, permissions) });
  });

  router.post('/v1/orgs/:org/devices', (ctx, _params, res) => {
    auditDenials(db, ctx, {
      action: 'device.create', targetType: 'organization', targetId: ctx.orgId,
    }, () => assertCan(db, ctx, 'device:provision'));
    const name = text(ctx.body.name, 'name');
    const kind = validateKind(ctx.body.kind);
    const online = ctx.body.online === undefined ? 0 : validateOnline(ctx.body.online);
    const id = newId('dev');
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO devices (id, org_id, name, kind, online)
           VALUES (?, ?, ?, ?, ?)`
        ).run(id, ctx.orgId, name, kind, online);
        audit(db, {
          orgId: ctx.orgId, actorId: ctx.userId, action: 'device.create',
          targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId,
        });
      })();
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('device already exists');
      throw error;
    }
    const row = findDevice(db, ctx.orgId, id);
    send(res, 201, { device: deviceFromRow(row, resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds: [id],
    }).byDevice[id]) });
  });

  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const row = findDevice(db, ctx.orgId, params.id);
    if (!row) throw notFound();
    auditDenials(db, ctx, {
      action: 'device.update', targetType: 'device', targetId: row.id,
    }, () => assertCan(db, ctx, 'device:update', row.id));
    const updates = [];
    const values = [];
    if (ctx.body.name !== undefined) {
      updates.push('name = ?');
      values.push(text(ctx.body.name, 'name'));
    }
    if (ctx.body.kind !== undefined) {
      updates.push('kind = ?');
      values.push(validateKind(ctx.body.kind));
    }
    if (ctx.body.online !== undefined) {
      updates.push('online = ?');
      values.push(validateOnline(ctx.body.online));
    }
    if (!updates.length) throw badRequest('no device fields to update');
    values.push(row.id, ctx.orgId);
    db.transaction(() => {
      db.prepare(`UPDATE devices SET ${updates.join(', ')} WHERE id = ? AND org_id = ?`).run(...values);
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'device.update',
        targetType: 'device', targetId: row.id, result: 'allow', requestId: ctx.requestId,
      });
    })();
    send(res, 200, { device: deviceFromRow(findDevice(db, ctx.orgId, row.id), resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds: [row.id],
    }).byDevice[row.id]) });
  });

  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const row = findDevice(db, ctx.orgId, params.id);
    if (!row) throw notFound();
    auditDenials(db, ctx, {
      action: 'device.decommission', targetType: 'device', targetId: row.id,
    }, () => assertCan(db, ctx, 'device:provision', row.id));
    const decommission = db.transaction(() => {
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: row.id, reason: 'device_transferred' });
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ? AND org_id = ?').run(nowIso(), row.id, ctx.orgId);
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'device.decommission',
        targetType: 'device', targetId: row.id, result: 'allow', requestId: ctx.requestId,
      });
    });
    decommission();
    send(res, 200, { ok: true });
  });

  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const row = findDevice(db, ctx.orgId, params.id);
    if (!row) throw notFound();
    auditDenials(db, ctx, {
      action: 'device.transfer', targetType: 'device', targetId: row.id,
    }, () => assertCan(db, ctx, 'device:provision', row.id));
    const targetOrgId = text(ctx.body.orgId, 'orgId');
    const targetOrg = db.prepare(
      'SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL'
    ).get(targetOrgId);
    if (!targetOrg || !activeMember(db, targetOrgId, ctx.userId)) throw notFound();
    if (!can(db, { userId: ctx.userId, orgId: targetOrgId }, 'device:provision')) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer',
        targetType: 'device', targetId: row.id, result: 'deny',
        reasonCode: 'missing_permission', requestId: ctx.requestId,
      });
      throw forbidden('missing permission: device:provision', 'missing_permission');
    }
    const transfer = db.transaction(() => {
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: row.id, reason: 'device_transferred' });
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ? AND org_id = ?')
        .run(targetOrgId, row.id, ctx.orgId);
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer',
        targetType: 'device', targetId: row.id, result: 'allow', requestId: ctx.requestId,
      });
    });
    transfer();
    send(res, 200, { device: { ...row, org_id: targetOrgId } });
  });

  router.get('/v1/orgs/:org/grants', (ctx, _params, res) => {
    auditDenials(db, ctx, {
      action: 'grant.list', targetType: 'organization', targetId: ctx.orgId,
    }, () => assertCan(db, ctx, 'user:read'));
    const rows = db.prepare(
      `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at,
              g.created_by, g.revoked_at, g.created_at,
              GROUP_CONCAT(gp.permission) AS permission_list
         FROM grants g
         JOIN grant_permissions gp ON gp.grant_id = g.id
        WHERE g.org_id = ? AND g.revoked_at IS NULL
        GROUP BY g.id
        ORDER BY g.id`
    ).all(ctx.orgId);
    send(res, 200, { grants: rows.map(grantResponseRow) });
  });

  router.post('/v1/orgs/:org/grants', (ctx, _params, res) => {
    auditDenials(db, ctx, {
      action: 'grant.create', targetType: 'membership', targetId: ctx.body.userId ?? null,
    }, () => assertCan(db, ctx, 'grant:create'));
    const userId = text(ctx.body.userId, 'userId');
    if (userId === ctx.userId) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create',
        targetType: 'membership', targetId: userId, result: 'deny',
        reasonCode: 'scope_mismatch', requestId: ctx.requestId,
      });
      throw forbidden('self-grant is forbidden', 'scope_mismatch');
    }
    if (!activeMember(db, ctx.orgId, userId)) throw notFound();
    const permissions = validateGrantPermissions(db, ctx.body.permissions);
    if (ctx.body.effect !== 'allow' && ctx.body.effect !== 'deny') throw badRequest('effect must be allow or deny');
    const deviceId = ctx.body.deviceId === undefined || ctx.body.deviceId === null
      ? null
      : text(ctx.body.deviceId, 'deviceId');
    if (deviceId && !findDevice(db, ctx.orgId, deviceId)) throw notFound();
    const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
    const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
    if (expiresAt && expiresAt <= nowIso()) throw badRequest('grant has already expired', 'expired_grant');
    if (startsAt && expiresAt && expiresAt <= startsAt) throw badRequest('expiresAt must be after startsAt');
    auditDenials(db, ctx, {
      action: 'grant.create', targetType: 'membership', targetId: userId,
    }, () => assertMayGrant(db, ctx, permissions, deviceId));

    const grantId = newId('grt');
    const write = db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(grantId, ctx.orgId, userId, deviceId, ctx.body.effect, startsAt, expiresAt, ctx.userId);
      const insertPermission = db.prepare(
        'INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)'
      );
      for (const permission of permissions) insertPermission.run(grantId, permission);
      bumpPermVersion(db, { orgId: ctx.orgId, userId });
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create',
        targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId,
      });
    });
    write();
    send(res, 201, { grant: grantResponseRow(grantRow(db, grantId, ctx.orgId)) });
  });

  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    const grant = grantRow(db, params.id, ctx.orgId);
    if (!grant || grant.revoked_at) throw notFound();
    auditDenials(db, ctx, {
      action: 'grant.revoke', targetType: 'grant', targetId: grant.id,
    }, () => assertCan(db, ctx, 'grant:revoke'));
    const revokedAt = nowIso();
    const revoke = db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ? AND org_id = ? AND revoked_at IS NULL')
        .run(revokedAt, grant.id, ctx.orgId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke',
        targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId,
      });
    });
    revoke();
    send(res, 200, { ok: true });
  });
}
