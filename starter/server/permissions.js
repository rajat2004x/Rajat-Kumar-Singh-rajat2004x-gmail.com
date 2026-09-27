// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { badRequest, forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

function catalogue(db) {
  return db.prepare('SELECT key FROM permissions ORDER BY key').all().map((row) => row.key);
}

function matchesPattern(pattern, permission) {
  return pattern === '*' || pattern === permission ||
    (pattern.endsWith(':*') && permission.startsWith(pattern.slice(0, -1)));
}

function loadState(db, { userId, orgId, now }) {
  const permissions = catalogue(db);
  const membership = db.prepare(
    `SELECT role, status
       FROM memberships
      WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);

  if (!membership) return { permissions, role: null, status: 'missing', baseline: new Set(), grants: [] };
  if (membership.status === 'suspended') {
    return { permissions, role: membership.role, status: 'suspended', baseline: new Set(), grants: [] };
  }
  if (membership.status !== 'active') {
    return { permissions, role: membership.role, status: membership.status, baseline: new Set(), grants: [] };
  }

  const baseline = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(membership.role)
      .map((row) => row.permission)
  );
  const at = now.toISOString();
  const grants = db.prepare(
    `SELECT g.id, g.device_id, g.effect, gp.permission
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR ? < g.expires_at)
      ORDER BY g.id, gp.permission`
  ).all(userId, orgId, at, at);

  return { permissions, role: membership.role, status: 'active', baseline, grants };
}

function resolved(effect, source = null, reason = null) {
  return { effect, source, reason };
}

function resolveDevice(state, deviceId) {
  const permissions = {};
  for (const permission of state.permissions) {
    if (state.status === 'missing') {
      permissions[permission] = resolved('deny', null, 'not_a_member');
      continue;
    }
    if (state.status === 'suspended') {
      permissions[permission] = resolved('deny', null, 'suspended');
      continue;
    }
    if (state.status !== 'active') {
      permissions[permission] = resolved('deny', null, 'not_a_member');
      continue;
    }

    const applicable = state.grants.filter((grant) =>
      grant.device_id === null || grant.device_id === deviceId
    );
    const denies = applicable.filter((grant) =>
      grant.effect === 'deny' && matchesPattern(grant.permission, permission)
    );
    if (denies.length) {
      permissions[permission] = resolved('deny', `grant:${denies[0].id}`, 'explicit_deny');
      continue;
    }

    const allows = applicable.filter((grant) =>
      grant.effect === 'allow' && matchesPattern(grant.permission, permission)
    );
    if (state.baseline.has(permission)) {
      permissions[permission] = resolved('allow', `role:${state.role}`);
    } else if (allows.length) {
      permissions[permission] = resolved('allow', `grant:${allows[0].id}`);
    } else {
      permissions[permission] = resolved('deny', null, 'implicit');
    }
  }
  return permissions;
}

function unionPermissions(state, devicePermissions) {
  if (!devicePermissions.length) return resolveDevice(state, null);

  const permissions = {};
  for (const permission of state.permissions) {
    const explicitDeny = devicePermissions.find((device) => device[permission].reason === 'explicit_deny');
    if (explicitDeny) {
      permissions[permission] = explicitDeny[permission];
      continue;
    }
    const allowedDevice = devicePermissions.find((device) => device[permission].effect === 'allow');
    permissions[permission] = allowedDevice
      ? allowedDevice[permission]
      : devicePermissions[0][permission];
  }
  return permissions;
}

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const state = loadState(db, { userId, orgId, now });
  if (deviceId !== null) {
    return { role: state.role, permissions: resolveDevice(state, deviceId) };
  }

  const deviceIds = db.prepare(
    'SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY id'
  ).all(orgId).map((row) => row.id);
  const devicePermissions = deviceIds.map((id) => resolveDevice(state, id));
  return { role: state.role, permissions: unionPermissions(state, devicePermissions) };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const state = loadState(db, { userId, orgId, now });
  const byDevice = {};
  for (const deviceId of deviceIds) byDevice[deviceId] = resolveDevice(state, deviceId);
  return { role: state.role, byDevice };
}

export function can(db, ctx, permission, deviceId) {
  return resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  }).permissions[permission]?.effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const answer = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  }).permissions[permission];
  if (answer?.effect === 'allow') return answer;
  throw forbidden(`missing permission: ${permission}`, answer?.reason ?? 'missing_permission');
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const permissions = catalogue(db);
  const concrete = [...new Set(
    patterns.flatMap((pattern) => permissions.filter((permission) => matchesPattern(pattern, permission)))
  )];
  if (!concrete.length || concrete.some((permission) => !can(db, ctx, permission, deviceId))) {
    throw forbidden('you cannot grant a permission you do not hold', 'scope_mismatch');
  }
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest('invalid session mode');
  if (!can(db, ctx, 'session:start', deviceId)) {
    throw forbidden('missing permission: session:start', 'missing_permission');
  }
  if (!can(db, ctx, modePermission, deviceId)) {
    throw forbidden(`missing permission: ${modePermission}`, 'missing_device_permission');
  }
}
