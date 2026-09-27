// Append-only audit writes.

import { newId } from './db.js';
import { HttpError } from './http.js';

const RESULTS = new Set(['allow', 'deny']);

export function audit(db, {
  orgId,
  actorId = null,
  action,
  targetType = null,
  targetId = null,
  result,
  reasonCode = null,
  requestId = null,
}) {
  if (typeof orgId !== 'string' || orgId.length === 0) throw new TypeError('audit orgId is required');
  if (typeof action !== 'string' || action.length === 0) throw new TypeError('audit action is required');
  if (!RESULTS.has(result)) throw new TypeError('audit result is invalid');

  db.prepare(
    `INSERT INTO audit_events
       (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId('aud'),
    orgId,
    actorId,
    action,
    targetType,
    targetId,
    result,
    reasonCode,
    requestId
  );
}

// Run fn(); if it refuses with a permission error, record the denial before rethrowing.
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (error) {
    if (error instanceof HttpError && (error.status === 403 || error.code === 'LAST_OWNER')) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        ...meta,
        result: 'deny',
        reasonCode: error.reason ?? error.code,
        requestId: ctx.requestId,
      });
    }
    throw error;
  }
}
