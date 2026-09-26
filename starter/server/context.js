// Per-request context: turn a bearer token into an authenticated caller.
//
// YOURS TO WRITE. This file ships as a stub so the server boots and every
// authenticated request fails loudly instead of appearing to work.
//
// What it has to do (BRIEF.md §3, PERMISSIONS.md §6):
//   - read the bearer token, verify it with verifyAccessToken() from ./auth.js
//   - look the membership up and refuse a token whose org or membership is gone
//   - THE TOKEN'S org CLAIM IS THE ONLY ORG THE CALLER MAY ADDRESS. A request that
//     names a different org is INVISIBLE — 404, never 403. Isolation is structural:
//     the caller cannot name another org, rather than being filtered afterwards.
//   - check freshness against memberships.perm_version (AUTH-DATA-MODEL.md §3), so a
//     role or grant change takes effect on the NEXT request, not at token expiry
//   - throw through the one error path in ./http.js
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries at
// least { userId, orgId, role, membership, claims }.

import { assertFresh, verifyAccessToken } from './auth.js';
import { notFound, unauthenticated } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const authorization = req.headers?.authorization;
    if (typeof authorization !== 'string') {
      throw unauthenticated('missing bearer token');
    }

    const match = authorization.trim().match(/^Bearer\s+(\S+)$/i);
    if (!match) throw unauthenticated('invalid authorization header');

    const claims = verifyAccessToken(match[1], secret);
    const requestedOrgId = params?.org ?? params?.orgId;
    if (requestedOrgId && requestedOrgId !== claims.org) throw notFound();

    const record = db.prepare(
      `SELECT
         m.id AS membership_id,
         m.org_id,
         m.user_id,
         m.role,
         m.status,
         m.perm_version,
         m.invited_by,
         m.joined_at,
         m.created_at AS membership_created_at,
         u.id AS user_id_value,
         u.email,
         u.name,
         o.id AS organization_id,
         o.name AS organization_name,
         o.theme,
         o.max_session_minutes
       FROM memberships m
       JOIN users u ON u.id = m.user_id
       JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.org_id = ? AND o.deleted_at IS NULL`
    ).get(claims.sub, claims.org);

    if (!record || record.status === 'invited' || record.status === 'removed') {
      throw unauthenticated('not a member of this org');
    }

    const membership = {
      id: record.membership_id,
      org_id: record.org_id,
      user_id: record.user_id,
      role: record.role,
      status: record.status,
      perm_version: record.perm_version,
      invited_by: record.invited_by,
      joined_at: record.joined_at,
      created_at: record.membership_created_at,
    };
    const user = {
      id: record.user_id_value,
      email: record.email,
      name: record.name,
    };
    const organization = {
      id: record.organization_id,
      name: record.organization_name,
      theme: record.theme,
      max_session_minutes: record.max_session_minutes,
    };

    assertFresh(claims, membership);

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      user,
      organization,
      org: organization,
      membership,
      claims,
    };
  };
}
