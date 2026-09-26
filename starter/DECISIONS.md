# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### <the decision, as a claim — not "permissions", but "the org-level view counts device-scoped grants">

**What I chose:**
**Why:** _(evidence: test, log line, commit)_
**What I rejected:** _(the plausible alternative, and the specific reason it fails)_
**What would change my mind:**

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

### The access-token verifier performs cryptographic validation only

**What I chose:** `verifyAccessToken` validates the JWT structure, decodes the header and payload,
pins the algorithm to HS256 and the type to JWT, verifies the HMAC-SHA256 signature with a
constant-time comparison, validates issuer, audience, expiry, and `jti`, then returns the signed
claims unchanged.
**Why:** The focused implementation check, `node starter/scripts/check-jwt.js`, passed all 43
cases, including malformed tokens, algorithm substitution, signature tampering, expiry equality,
issuer/audience failures, and missing or empty `jti`. Diagnostics also reported no problems.
**What I rejected:** Putting membership lookup, `perm_version` freshness, or permission
resolution inside the verifier. That alternative would mix cryptographic token authenticity with
database-backed authorization, make the verifier responsible for more than the token it receives,
and duplicate the request-context/permission boundaries that the starter defines.
**What would change my mind:** A tested authentication contract that required the verifier itself
to access the database, or evidence that a valid signed token could otherwise bypass the separate
freshness and authorization checks.

### Stub — the shape of a weak "Why"

**What I chose:** the obvious thing.
**Why:** it is what the brief says to do.
**What I rejected:** nothing, the alternative seemed worse.
**What would change my mind:** I do not know.

_Reads as a memory of the document, not a model of the system. Scores nothing._

---

### Stub — the shape of a strong "Why"

**What I chose:** X.
**Why:** I implemented Y first, because Y is the intuitive precedence rule. `node scripts/check-
permissions.js` reported `<the actual reason string it reported>` on the case where the two grants
disagree. That is only reachable if the two are evaluated in a different order than Y assumes.
Moved to X in `<commit>` and the case passed. Logged in `BUILD-LOG.md` under Phase 2.
**What I rejected:** Y, and also "resolve the narrower one last" — both fail the same case for the
same reason.
**What would change my mind:** a case where a narrower grant is expected to survive a broader
refusal. I could not construct one, which is itself evidence for X.

_Shows what you believed, what disproved it, and what you did next._

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
