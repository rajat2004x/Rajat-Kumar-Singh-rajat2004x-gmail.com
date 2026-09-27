# BUILD-LOG

## Phase 0 — orientation

### 2026-09-27 · Phase 0 — orientation

Read the root requirements and the starter implementation before making changes. The starting
implementation was incomplete rather than a single missing feature: authentication and parts of
authorization existed, while lifecycle, audit, the effective-permissions endpoint, refresh-token
organization scoping, and the SPA still had gaps.

The existing validation scripts were important because several requirements were encoded in the
database and check scripts rather than being fully represented by the visible route stubs.

The first useful baseline was to identify the implementation boundaries instead of changing
everything at once. The work was therefore split into authentication, authorization/lifecycle,
routes, audit, refresh-token scope, and finally the frontend.

---

## Phase 1 — token verification

### 2026-09-27 · access-token verifier

Investigated `server/auth.js`, `server/http.js`, `server/db.js`, `server/index.js`,
`scripts/check-jwt.js`, `AUTH-DATA-MODEL.md`, and `README.md` before coding. The initial
hypothesis was straightforward: `verifyAccessToken` was still a stub, so neither valid tokens
nor invalid tokens could be verified through the required authentication error path.

Implemented strict three-segment JWT parsing, base64url and JSON-object validation, fixed HS256
and JWT-type pinning, HMAC-SHA256 verification with constant-time signature comparison, issuer
and audience checks, expiry validation with `exp == now` treated as expired, and non-empty `jti`
validation. The verifier preserves the signed claims and does not perform membership freshness or
permission resolution; those belong to the request context and authorization layers.

Ran `node scripts/check-jwt.js`: **43 passed, 0 failed**.

---

## Phase 2 — caller context and the resolution engine

### 2026-09-27 · authorization model

The initial implementation model treated role permissions as the main source of authorization.
The requirement tables showed that this was incomplete: the database permission catalogue,
membership role, grants, device scope, explicit denies, time windows, and organization
boundaries all participate in the final answer.

Implemented database-backed permission resolution rather than hardcoding the documented
permission matrix. The resolver distinguishes `allow`, `explicit_deny`, and `implicit` results,
uses the membership belonging to the requested organization, and respects device-scoped grants
and organization-wide denies.

A later validation exposed an aggregation mistake where an allow from one device could mask an
organization-wide deny. That was corrected so explicit organization-level denial is applied before
device-scoped allows.

The permission and personalization checks then passed:

- `check-permissions.js`: **35 passed, 0 failed**
- `check-personalisation.js`: **18 passed, 0 failed**

The personalization check was particularly useful because it confirmed that the database, rather
than the documentation, remains the permission catalogue and that undocumented database roles and
permissions are resolved dynamically.

---

## Phase 3 — orgs, members, invites

### 2026-09-27 · organization and membership lifecycle

Implemented organization, membership, and invitation behavior while preserving organization
isolation and database constraints.

Membership changes use database-derived role information and protect the last owner. Self-role
changes and privilege laundering are rejected. Suspended memberships resolve to no usable
permissions.

Invites use generated random tokens that are hashed at rest. The raw token is returned only when
the invite is created. Public preview intentionally exposes only the information required for
redemption and does not expose organization IDs or device information.

Invite acceptance is transactional: an existing user is reused or a new user is created,
membership is activated with the invited role, the invite is marked accepted, and the normal
token flow is used.

The API contract verified the important invite properties:

- creation succeeds
- raw token is returned once
- public preview works
- no device or organization-ID leakage occurs
- unknown tokens return `404`
- acceptance succeeds
- the invited role is preserved
- reuse returns `409`
- the new user can log in
- the seed password cannot be used for the newly created user

---

## Phase 4 — devices and grants

### 2026-09-27 · device and grant authorization

Implemented device and grant operations using the same permission-resolution model instead of
creating a separate authorization system for management routes.

Grant validation uses the database permission catalogue and rejects unknown permissions.
Self-grants and privilege-laundering attempts are rejected.

A significant boundary case was the interaction between organization-wide and device-scoped
grants. An organization-wide explicit deny must not be bypassed by adding a device-scoped allow.
The resolver was corrected after this behavior was exposed during validation.

Device transfer and decommission operations were also connected to the lifecycle subsystem so
active sessions are terminated with the documented `device_transferred` lifecycle reason where
required.

The existing permission and API suites remained green after these changes.

---

## Phase 5 — sessions

### 2026-09-27 · session authority and lifecycle

The session model required more than checking whether the user currently possessed a permission.
Sessions retain an authority snapshot and have their own expiry/lifecycle state.

Implemented shared lifecycle helpers for:

- database-derived role ranks
- modification authority
- last-owner protection
- authority snapshots
- database-derived session expiry
- active-session termination
- suspension/removal cascades
- device transfer/decommission cascades
- centralized expiry handling

Permission changes preserve the documented session-grandfathering behavior rather than
automatically invalidating every existing session.

The important distinction is between the permission required to start a session and the permission
required to perform an operation through an existing session. The implementation keeps those
failure reasons distinguishable.

Validation after the lifecycle refactor:

- `check-permissions.js`: **35 passed, 0 failed**
- `check-jwt.js`: **43 passed, 0 failed**
- `check-api.js`: **66 passed, 0 failed**

---

## Phase 6 — audit

### 2026-09-27 · append-only audit trail

Implemented the audit subsystem around the existing `audit_events` schema.

The audit writer creates organization-scoped append-only records and stores request IDs,
actions, targets, and reason codes without logging secrets such as access tokens or invite
secrets.

Success events are written within the existing mutation transactions so the audit record follows
the mutation. Authorization failures are also recorded, because the requirements explicitly
treat denied attempts as auditable events.

The audit coverage was connected to organization, membership, device, grant, invite, session,
and relevant authorization paths. Audit-read authorization failures are also recorded.

The API checks confirmed that denied attempts appear in the audit stream and carry reason codes.
Pagination validation was also tightened so invalid limits such as `0`, negative values, and
values above the allowed maximum return `400`, while a valid `offset=0` remains valid.

Final API validation remained **66 passed, 0 failed**.

---

## Phase 7 — the console

### 2026-09-27 · RemoteOps SPA

The original frontend entry point was only a placeholder, so the console was implemented in
`web/main.jsx` with the required styling in `web/styles.css`.

The SPA uses the server as the authority for permissions rather than duplicating the permission
matrix in the browser. Navigation and controls are therefore rendered from the permissions and
device-specific results returned by the API.

Implemented:

- login
- refresh-cookie based session restoration
- in-memory access-token handling
- logout
- organization switching
- active organization identity
- permission-driven navigation
- device views
- member/people views
- grants view
- sessions view
- audit view
- admin controls
- organization creation
- invite preview and redemption
- visible login/request failure messages
- organization-specific rendering
- per-tab organization isolation

A production-serving issue also appeared during browser testing: `/` returned the server's
`NOT_FOUND` response instead of the built SPA on Windows. The static-file path handling in
`server/index.js` was corrected to convert the file URL correctly.

The production frontend then built successfully with:

`npm run build`

Playwright initially exposed an invite-flow state mismatch. The isolated invite test showed
that the backend preview and acceptance were working; the remaining issue was post-acceptance
state. The SPA was changed to return to the normal login form after successful redemption.

A stale Playwright database then caused the full-suite invite test to reuse an already-consumed
invite. Removing the generated `e2e.db` artifacts and rerunning the test produced the clean
invite result.

Final UI validation:

`npx playwright test tests/ui.spec.js`

**25 passed, 0 failed.**

---

## Phase 8 — hardening

### 2026-09-27 · final validation and hardening

The implementation was validated repeatedly after each subsystem rather than waiting until the
end.

Final backend checks:

- `node scripts/check-permissions.js` — **35 passed, 0 failed**
- `node scripts/check-jwt.js` — **43 passed, 0 failed**
- `node scripts/check-api.js` — **66 passed, 0 failed**
- `node scripts/check-personalisation.js` — **18 passed, 0 failed**
- `npm run build` — **passed**
- `npx playwright test tests/ui.spec.js` — **25 passed, 0 failed**

The refresh-token implementation was also corrected so a refresh family remains associated with
the organization in which it was issued. The schema does not provide an `org_id` column on
`refresh_tokens`, so the existing `family_id` field was used to retain the organization scope
while keeping the raw refresh token random and hashed.

The final implementation deliberately left the existing test files unchanged. Validation was
performed against the supplied contracts rather than weakening or rewriting the assertions.

The completed implementation was committed and pushed to the repository. The final Git state was:

`nothing to commit, working tree clean`

and the local `main` branch was synchronized with `origin/main`.

---

## Open threads

The documented and shipped validation suites are passing, but some areas have less focused
automated coverage than the main contracts.

Known areas for future hardening include:

- dedicated refresh-token replay/rotation tests
- focused session-expiry tests
- concurrent session/device exclusivity tests
- additional effective-permissions endpoint coverage
- deeper audit completeness tests
- additional concurrency testing around unique invite/grant constraints
- broader malformed-input/fuzz coverage for permission inputs

These are follow-up hardening opportunities rather than known failures in the current supplied
test suites.

The final validated state is the implementation committed to `main` and pushed to `origin/main`.