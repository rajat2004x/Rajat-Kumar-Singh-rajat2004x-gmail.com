BUILD-LOG

Phase 0 — orientation

2026-09-27 · Phase 0 — orientation

Read the root requirements and the starter implementation before making changes. The starting implementation was incomplete rather than a single missing feature: authentication and parts of authorization existed, while lifecycle, audit, the effective-permissions endpoint, refresh-token organization scoping, and the SPA still had gaps.

The existing validation scripts were important because several requirements were encoded in the database and check scripts rather than being fully represented by the visible route stubs. I therefore split the work into authentication, authorization/lifecycle, routes, audit, refresh-token scope, and frontend instead of changing the whole application at once.

Phase 1 — token verification

2026-09-27 · access-token verifier

I initially treated verifyAccessToken as the boundary for token validity only. I inspected server/auth.js, server/http.js, server/db.js, server/index.js, scripts/check-jwt.js, and the authentication requirements before changing it.

Implemented strict three-segment JWT parsing, base64url/JSON validation, HS256 and JWT type pinning, HMAC-SHA256 verification with constant-time comparison, issuer/audience checks, expiry validation including exp == now, and non-empty jti validation. I deliberately kept membership freshness and permission resolution outside the cryptographic verifier.

node scripts/check-jwt.js finished at 43 passed, 0 failed.

Phase 2 — caller context and the resolution engine

2026-09-27 · authorization model changed after validation

My first model was that role permissions were the main authorization source. Reading the database-backed permission catalogue and exercising the personalization/permission checks showed that this was incomplete: roles, grants, device scope, explicit denies, time windows, and organization boundaries all contribute to the final result.

I moved to database-backed resolution and preserved the distinction between allow, explicit_deny, and implicit.

A later validation exposed a concrete mistake in my aggregation logic: an organization-level deny could be masked by a device-scoped allow. The first fix also introduced a local variable error where the allowed value was the permission entry rather than its containing device scope. check-permissions.js caught that regression immediately. I corrected the aggregation and reran the failed check before continuing.

Final permission validation: 35/35 passed. Personalization validation: 18/18 passed.

Phase 3 — orgs, members, invites

2026-09-27 · membership and invitation boundaries

Membership mutation logic had to preserve organization isolation, last-owner protection, self-action restrictions, and permission-version freshness. I centralized lifecycle concerns rather than leaving role ranks, owner checks, session expiry, and termination logic duplicated across routes.

Invite handling keeps raw invite credentials out of storage. The API checks confirmed single-use behavior, hashed credentials, successful acceptance, rejection of reuse, and that the invited user receives the invited role.

The API contract reached 66/66 passed after these changes.

Phase 4 — devices and grants

2026-09-27 · scope and deny precedence

The important boundary was the disagreement between organization-wide and device-scoped permission results. The observed failing aggregation case showed that a more-specific device allow could not be allowed to defeat an explicit organization-level deny.

I therefore made explicit denial authoritative during aggregation. Device transfer and decommission also became lifecycle operations: active sessions are terminated with the schema-valid device_transferred reason before the device ownership/state mutation.

The corrected permission engine continued to pass 35/35 permission checks and the complete API contract remained 66/66.

Phase 5 — sessions

2026-09-27 · lifecycle centralization

The routes originally duplicated role-rank checks, last-owner protection, session snapshots, expiry calculations, and active-session termination. I moved these responsibilities into server/lifecycle.js and changed the relevant member, session, and device routes to use the shared helpers.

The lifecycle model preserves session grandfathering for permission changes while terminating sessions for suspension/removal and device transfer/decommission. Session authority snapshots and expiry are derived through the shared lifecycle helpers.

After the refactor:

check-permissions.js: 35/35

check-jwt.js: 43/43

check-api.js: 66/66

Phase 6 — audit

2026-09-27 · audit boundary

The audit writer was initially a stub. I implemented append-only audit insertion and connected successful organization, membership, device, grant, invite, and session mutations to audit records inside their existing mutation transactions.

Authorization denials were connected at the route boundary rather than making permissions.js persist every resolve() result. This keeps permission resolution separate from the side effect of recording an actual authorization attempt.

The API contract explicitly verified that denied attempts appear in the audit stream and carry a reason code. Final API result: 66/66 passed.

Phase 7 — the console

2026-09-27 · RemoteOps SPA

The original frontend entry point was a placeholder, so the console was implemented in web/main.jsx with web/styles.css.

Implemented:

login and visible login errors

refresh-cookie session restoration

in-memory access-token handling

logout

organization switching and active organization identity

permission-driven navigation

device, people, grants, sessions, audit, and admin views

organization creation

invite preview and redemption

organization-specific rendering and per-tab isolation

Browser testing found a production-serving issue on Windows: / returned the server's NOT_FOUND response instead of the built SPA. The static-file path handling in server/index.js was corrected.

The invite flow also exposed two different issues during testing. First, the post-acceptance state did not match the Playwright contract, so the SPA was changed to return to the normal login form after successful redemption. Second, a reused e2e.db caused an already-consumed invite to be reused by the full suite. Removing the generated database artifacts and rerunning the suite produced the clean result.

Final UI validation: npx playwright test tests/ui.spec.js — 25 passed, 0 failed.

Phase 8 — hardening

2026-09-27 · final validation

The final validation was run after the subsystem changes rather than relying on a single end-of-project run.

node scripts/check-permissions.js — 35/35

node scripts/check-jwt.js — 43/43

node scripts/check-api.js — 66/66

node scripts/check-personalisation.js — 18/18

npm run build — passed

npx playwright test tests/ui.spec.js — 25/25

A refresh-token scope issue was also corrected. The schema has no dedicated org_id column on refresh_tokens, so the existing family_id field was used to preserve the issuing organization together with rotation lineage while retaining random opaque refresh credentials and hashed storage.

The implementation was committed as 85de22f (Implement RemoteOps authorization backend and SPA) and pushed to origin/main. The final Git state was clean and synchronized.

Open threads

The supplied validation contracts are passing, but several areas have less focused coverage than the main suites:

dedicated refresh-token replay/rotation tests

focused exact session-expiry tests

concurrent session/device exclusivity tests

additional effective-permissions endpoint edge cases

deeper audit completeness tests

concurrency around unique invite/grant constraints

broader malformed-input/fuzz coverage for permission inputs

These are follow-up hardening opportunities, not known failures in the supplied validation suites.

The application also intentionally models device/session authorization state rather than implementing a real remote-device transport.