import { newId, nowIso } from '../db.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { badRequest, deviceBusy, notFound, send } from '../http.js';

const MODES = new Set(['view', 'control', 'terminal']);

function activeDevice(db, orgId, deviceId) {
  return db.prepare(
    `SELECT id
       FROM devices
      WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
  ).get(deviceId, orgId);
}

function expireSessions(db, orgId, at) {
  db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = 'session_expired', ended_at = ?
      WHERE org_id = ? AND state = 'active' AND expires_at <= ?`
  ).run(at, orgId, at);
}

function sessionRow(db, id, orgId) {
  return db.prepare(
    `SELECT id, org_id, user_id, device_id, mode, state, end_reason,
            authorized_by, started_at, expires_at, ended_at
       FROM sessions
      WHERE id = ? AND org_id = ?`
  ).get(id, orgId);
}

function activeGrantIds(db, { userId, orgId, deviceId, at }) {
  return db.prepare(
    `SELECT DISTINCT g.id
       FROM grants g
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.device_id IS NULL OR g.device_id = ?)
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR ? < g.expires_at)
      ORDER BY g.id`
  ).all(userId, orgId, deviceId, at, at).map((row) => row.id);
}

function parseMode(value) {
  if (typeof value !== 'string' || !MODES.has(value)) throw badRequest('mode is invalid');
  return value;
}

function sessionBusyMessage(db, deviceId) {
  const holder = db.prepare(
    `SELECT id
       FROM sessions
      WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')
      ORDER BY id
      LIMIT 1`
  ).get(deviceId);
  return holder ? `device already has an exclusive session (${holder.id})` : undefined;
}

export function registerSessionRoutes(router, { db }) {
  router.post('/v1/orgs/:org/sessions', (ctx, _params, res) => {
    const deviceId = typeof ctx.body.deviceId === 'string' ? ctx.body.deviceId.trim() : '';
    if (!deviceId) throw badRequest('deviceId is required');
    const mode = parseMode(ctx.body.mode);
    if (!activeDevice(db, ctx.orgId, deviceId)) throw notFound();

    assertCanStartSession(db, ctx, mode, deviceId);

    const startedAt = nowIso();
    const expiresAt = new Date(
      Date.parse(startedAt) + Number(ctx.organization.max_session_minutes) * 60_000
    ).toISOString();
    const authorizedBy = {
      role: ctx.role,
      grantIds: activeGrantIds(db, {
        userId: ctx.userId,
        orgId: ctx.orgId,
        deviceId,
        at: startedAt,
      }),
      snapshotAt: startedAt,
    };
    const id = newId('ses');

    try {
      db.prepare(
        `INSERT INTO sessions
           (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
      ).run(
        id,
        ctx.orgId,
        ctx.userId,
        deviceId,
        mode,
        JSON.stringify(authorizedBy),
        startedAt,
        expiresAt
      );
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw deviceBusy(sessionBusyMessage(db, deviceId));
      }
      throw error;
    }

    send(res, 201, { session: sessionRow(db, id, ctx.orgId) });
  });

  router.get('/v1/orgs/:org/sessions', (ctx, _params, res) => {
    assertCan(db, ctx, 'session:view');
    const at = nowIso();
    expireSessions(db, ctx.orgId, at);
    const sessions = db.prepare(
      `SELECT id, org_id, user_id, device_id, mode, state, end_reason,
              authorized_by, started_at, expires_at, ended_at
         FROM sessions
        WHERE org_id = ?
        ORDER BY started_at DESC, id DESC`
    ).all(ctx.orgId);
    send(res, 200, { sessions });
  });

  router.get('/v1/sessions/:id', (ctx, params, res) => {
    const at = nowIso();
    expireSessions(db, ctx.orgId, at);
    const session = sessionRow(db, params.id, ctx.orgId);
    if (!session) throw notFound();
    if (session.user_id !== ctx.userId) assertCan(db, ctx, 'session:view');
    send(res, 200, session);
  });

  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    const session = sessionRow(db, params.id, ctx.orgId);
    if (!session) throw notFound();
    const own = session.user_id === ctx.userId;
    if (!own) assertCan(db, ctx, 'session:terminate');
    if (session.state === 'active') {
      db.prepare(
        `UPDATE sessions
            SET state = 'ended', end_reason = ?, ended_at = ?
          WHERE id = ? AND org_id = ? AND state = 'active'`
      ).run(own ? 'user_stopped' : 'admin_terminated', nowIso(), session.id, ctx.orgId);
    }
    send(res, 200, { session: sessionRow(db, session.id, ctx.orgId) });
  });
}
