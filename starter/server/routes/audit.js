import { assertCan } from '../permissions.js';
import { auditDenials } from '../audit.js';
import { badRequest, send } from '../http.js';

function pageValue(value, field, defaultValue, maximum = Number.MAX_SAFE_INTEGER, minimum = 0) {
  if (value === null || value === '') return defaultValue;
  if (!/^\d+$/.test(value)) throw badRequest(`${field} must be a non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw badRequest(`${field} is out of range`);
  }
  return parsed;
}

export function registerAuditRoutes(router, { db }) {
  router.get('/v1/orgs/:org/audit', (ctx, _params, res) => {
    auditDenials(db, ctx, {
      action: 'audit.list', targetType: 'organization', targetId: ctx.orgId,
    }, () => assertCan(db, ctx, 'audit:read'));
    const limit = pageValue(ctx.query.get('limit'), 'limit', 100, 1000, 1);
    const offset = pageValue(ctx.query.get('offset'), 'offset', 0);
    const events = db.prepare(
      `SELECT id, org_id, actor_id, action, target_type, target_id,
              result, reason_code, request_id, at
         FROM audit_events
        WHERE org_id = ?
        ORDER BY at DESC, id DESC
        LIMIT ? OFFSET ?`
    ).all(ctx.orgId, limit, offset);
    send(res, 200, { events });
  });
}
