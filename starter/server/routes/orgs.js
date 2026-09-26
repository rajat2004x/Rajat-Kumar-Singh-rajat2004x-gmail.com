import { newId, nowIso } from '../db.js';
import { assertCan } from '../permissions.js';
import { badRequest, conflict, notFound, send } from '../http.js';

function text(value, field) {
  if (typeof value !== 'string' || value.trim() === '') throw badRequest(`${field} is required`);
  return value.trim();
}

function ownerRole(db) {
  const row = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
  if (!row) throw badRequest('no owner role is configured');
  return row.key;
}

function organization(db, id) {
  return db.prepare(
    `SELECT id, name, theme, max_session_minutes, created_at
       FROM organizations
      WHERE id = ? AND deleted_at IS NULL`
  ).get(id);
}

function organizationResponse(row) {
  return {
    id: row.id,
    name: row.name,
    theme: row.theme,
    maxSessionMinutes: row.max_session_minutes,
    createdAt: row.created_at,
  };
}

export function registerOrgRoutes(router, { db }) {
  router.get('/v1/orgs', (ctx, _params, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, o.max_session_minutes, o.created_at, m.role
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.id`
    ).all(ctx.userId).map((row) => ({
      ...organizationResponse(row),
      role: row.role,
    }));
    send(res, 200, { orgs });
  });

  router.post('/v1/orgs', (ctx, _params, res) => {
    const name = text(ctx.body.name, 'name');
    const theme = ctx.body.theme === undefined ? 'teal' : text(ctx.body.theme, 'theme');
    const maxSessionMinutes = ctx.body.maxSessionMinutes === undefined
      ? 60
      : Number(ctx.body.maxSessionMinutes);
    if (!Number.isInteger(maxSessionMinutes) || maxSessionMinutes <= 0) {
      throw badRequest('maxSessionMinutes must be a positive integer');
    }

    const orgId = newId('org');
    const membershipId = newId('mem');
    const role = ownerRole(db);
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO organizations (id, name, theme, max_session_minutes)
           VALUES (?, ?, ?, ?)`
        ).run(orgId, name, theme, maxSessionMinutes);
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at)
           VALUES (?, ?, ?, ?, 'active', ?)`
        ).run(membershipId, orgId, ctx.userId, role, nowIso());
      })();
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('organization already exists');
      throw error;
    }

    const row = organization(db, orgId);
    send(res, 201, {
      ...organizationResponse(row),
      org: organizationResponse(row),
      role,
    });
  });

  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:update');
    const row = organization(db, ctx.orgId);
    if (!row) throw notFound();
    const updates = [];
    const values = [];
    if (ctx.body.name !== undefined) {
      updates.push('name = ?');
      values.push(text(ctx.body.name, 'name'));
    }
    if (ctx.body.theme !== undefined) {
      updates.push('theme = ?');
      values.push(text(ctx.body.theme, 'theme'));
    }
    if (ctx.body.maxSessionMinutes !== undefined) {
      const value = Number(ctx.body.maxSessionMinutes);
      if (!Number.isInteger(value) || value <= 0) throw badRequest('maxSessionMinutes must be a positive integer');
      updates.push('max_session_minutes = ?');
      values.push(value);
    }
    if (!updates.length) throw badRequest('no organization fields to update');
    values.push(ctx.orgId);
    db.prepare(`UPDATE organizations SET ${updates.join(', ')} WHERE id = ? AND deleted_at IS NULL`).run(...values);
    const updated = organization(db, params.org);
    send(res, 200, { org: organizationResponse(updated) });
  });

  router.delete('/v1/orgs/:org', (ctx, _params, res) => {
    assertCan(db, ctx, 'org:delete');
    if (!organization(db, ctx.orgId)) throw notFound();
    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL')
      .run(nowIso(), ctx.orgId);
    send(res, 200, { ok: true });
  });
}
