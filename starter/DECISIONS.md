DECISIONS

The access-token verifier performs cryptographic validation only

What I chose:
verifyAccessToken validates JWT structure, pins HS256/JWT, verifies the HMAC signature with constant-time comparison, checks issuer, audience, expiry, and non-empty jti, and returns the signed claims without performing database authorization.

Why:
node scripts/check-jwt.js passed 43/43 cases, including malformed tokens, algorithm substitution, signature tampering, expiry equality, issuer/audience failures, and missing/empty jti. The authentication requirements also separate cryptographic validation from perm_version freshness.

What I rejected:
Putting membership lookup, permission-version freshness, or permission resolution inside verifyAccessToken. That would make a cryptographic verifier depend on database state and duplicate work that belongs to request context and authorization.

What would change my mind:
A tested contract requiring the verifier itself to perform database-backed authorization, or evidence that a valid signed token can bypass freshness or authorization without that coupling.

The permission catalogue comes from the database rather than a hardcoded matrix

What I chose:
Permission resolution reads roles and permissions from the database at runtime.

Why:
node scripts/check-personalisation.js passed 18/18, including undocumented role/permission cases. The observed behavior showed that the database, not a copied list in application code, is the useful source of truth for runtime permission resolution.

What I rejected:
Hardcoding the documented role and permission matrix. That would only represent the examples known while reading the documents and would not handle additional database-defined roles or permissions.

What would change my mind:
A database/schema contract explicitly rejecting additional roles and permissions and making the documented list authoritative.

An organization-wide explicit deny cannot be bypassed by a device-scoped allow

What I chose:
During permission aggregation, an explicit organization-level deny remains effective even when a device-scoped allow exists.

Why:
The first aggregation implementation allowed a device-level allow to mask an organization-level denial. check-permissions.js exposed the mistake. After changing the aggregation order, the permission suite passed 35/35.

What I rejected:
Resolving the narrowest scope last and allowing a device grant to carve an exception out of an organization-wide explicit denial. The failing case demonstrated that this interpretation produced the wrong authorization result.

What would change my mind:
A tested rule explicitly stating that device scope may override an organization-wide explicit deny.

Lifecycle rules belong in shared helpers rather than duplicated route logic

What I chose:
Role-rank checks, last-owner protection, session authority snapshots, session expiry, and scoped session termination are centralized in server/lifecycle.js.

Why:
Before the refactor, the same lifecycle decisions existed in multiple routes. The implementation work identified duplicated rank, expiry, snapshot, and termination behavior, and the final check-api.js result remained 66/66 after routes were switched to the shared helpers.

What I rejected:
Keeping route-local copies because they were already passing the API checks. That leaves multiple implementations of the same security rule and makes a future fix easy to apply to one path but miss another.

What would change my mind:
A requirement showing that the lifecycle semantics genuinely differ by route and cannot be expressed through a common contract.

Successful mutations and their audit records commit together

What I chose:
Successful organization, membership, device, grant, invite, and session mutations write their audit records inside the same transaction as the mutation.

Why:
The audit stream is intended to describe committed mutations. The API suite also verifies that denied attempts are present and carry a reason code; keeping the success write in the same transaction avoids a committed state change without its corresponding required audit record.

What I rejected:
Writing audit events asynchronously after the mutation commits. That introduces a consistency window in which the mutation exists but its audit event does not.

What would change my mind:
A deliberately asynchronous/event-sourced architecture with an independently durable audit queue and an explicit eventual-consistency contract.

Authorization denials are audited at the authorization boundary, not inside permissions.js

What I chose:
Route-level authorization failures call the audit helper and then preserve the existing authorization response, while permissions.js remains a resolver.

Why:
The API contract checks denied attempts and reason codes. During implementation, denial paths across member, device, invite, grant, and audit-read operations were connected without changing the permission resolver API. The final API suite passed 66/66.

What I rejected:
Making every resolve() denial write an audit event. A resolver call is not necessarily an authorization attempt; it can be used to calculate UI state or inspect permissions.

What would change my mind:
A contract stating that every permission-resolution call itself is a security event that must be persisted.

Refresh-token organization scope is preserved through the existing family field

What I chose:
The refresh-token family metadata preserves the issuing organization together with the rotation lineage, without adding a new schema column.

Why:
The existing refresh_tokens schema has no org_id. Multi-organization refresh behavior still requires the server to remember which organization the refresh family belongs to. The implementation therefore reused the existing family field while retaining random opaque credentials and hashed storage. check-api.js remained 66/66.

What I rejected:
Adding a late schema migration solely to introduce a dedicated refresh-token org_id field. That would expand the data model when the existing family mechanism can preserve the required scope.

What would change my mind:
A requirement making refresh_tokens.org_id a first-class authoritative database field, or evidence that encoding the scope in the family metadata creates ambiguity or unsafe rotation behavior.

The effective-permissions endpoint delegates resolution to the existing permission engine

What I chose:
GET /v1/orgs/:org/users/:userId/effective performs organization-isolated target lookup, allows self-access, requires user:read for other users, and returns the result of the existing resolve() function.

Why:
The endpoint was absent while the permission engine already represented the effective result. Reusing resolve() avoids creating a second permission implementation. The full API contract remained 66/66 after the endpoint was added.

What I rejected:
Reimplementing permission aggregation specifically for the endpoint. That would create a second authorization model capable of disagreeing with the model used elsewhere.

What would change my mind:
A separate endpoint contract requiring a materially different permission calculation from the existing resolver.

The SPA treats server authorization as authoritative

What I chose:
The frontend uses server-returned permissions and device-specific authorization results to control visibility, while access tokens remain in memory rather than browser storage.

Why:
The Playwright suite directly checks permission-driven rendering, server-side permission withdrawal, organization isolation, and the absence of tokens in web storage. The final UI result was 25/25.

What I rejected:
Duplicating the complete permission matrix in the frontend and treating UI checks as authorization. Client-side visibility is not a security boundary and would become stale when server-side permissions change.

What would change my mind:
A product contract explicitly making the browser the authoritative policy engine and removing server-side authorization enforcement.

The database remains responsible for invariants that it can enforce

What I chose:
Where the schema provides uniqueness/foreign-key/exclusivity guarantees, the implementation relies on those constraints rather than recreating every invariant as an application-only precheck.

Why:
The implementation work repeatedly used the schema as the enforcement boundary for relationships and uniqueness, while the supplied API and personalization checks exercised the resulting behavior. This also avoids race-prone check-then-insert patterns.

What I rejected:
Assuming that an application-level existence check is sufficient before every mutation. Two concurrent requests can pass the same check unless the database constraint is the final authority.

What would change my mind:
A constraint that is absent, disabled, or insufficient for the invariant, or a requirement that a specific conflict must be converted into a particular application-level error before the database is reached.

Where this repo argues with itself

Refresh-token organization scope

The schema has no dedicated org_id column on refresh_tokens, while multi-organization refresh behavior requires the refresh family to preserve its issuing organization. I built against the existing schema and used the existing family field to retain organization scope with rotation lineage rather than introducing a new migration.

Permission scope precedence

A device-scoped allow can appear more specific than an organization-wide deny, but the observed validation behavior required the explicit organization-level deny to remain effective. The implementation therefore treats the explicit denial as authoritative rather than allowing scope specificity alone to override it.

No other document/schema contradiction was established strongly enough during implementation to claim one. Where the supplied documents, schema, and tests agreed, I followed that combined evidence rather than inventing a contradiction.

Deliberately not built

Additional hidden-test infrastructure

I did not create a separate test suite solely to make the supplied tests pass. The supplied check scripts and Playwright contract were preserved. Focused tests for refresh replay, concurrent operations, exact session expiry, and additional effective-permissions edge cases remain useful hardening work.

Real remote device control

The device/session subsystem records authorization and session state. It does not create a real connection to or control a physical device because that transport is outside the supplied application scope.

Client-side authorization as a security boundary

The SPA does not replace server authorization with client-side rules. Client checks control presentation; the server remains responsible for authorization.

A separate refresh-token org_id schema migration

The existing schema did not contain refresh_tokens.org_id, so organization scope was preserved through the existing refresh-family field instead of expanding the schema late in the implementation.

Broad fuzz and concurrency testing

The supplied validation establishes the documented behavior, but a broader fuzz/concurrency campaign was not added.These are appropriate follow-up hardening areas rather than prerequisites for changing the current implementation contract.