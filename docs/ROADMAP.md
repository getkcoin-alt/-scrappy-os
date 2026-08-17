# Roadmap

Each version earns the next. The ordering is deliberate: capability that would
be unsafe or unverifiable at the current level of control comes later, not
sooner.

---

## v0.1 — Single-node Linux control plane ✅

**Shipped.** A human gives Scrappy OS a diagnostic objective on a Linux server.
It plans, invokes safe read-only tools, reasons over the observations, produces
a conclusion, records everything, and refuses privileged or destructive
mutations unless specifically approved.

- Typed domain models, async event bus, in-process transport
- Provider abstraction: OpenAI-compatible, Ollama, deterministic development stub
- Brahma / Vishnu / Mahesh with typed output schemas
- Orchestration loop with five independent budgets
- 24 typed tools across system, filesystem, process, git, shell and HTTP
- Four risk levels, fail-closed policy, single-use approvals, SQLite audit
- Working and episodic memory; semantic memory as an interface
- CLI, local API, doctor, systemd unit

**Not in v0.1:** API authentication, multi-user, remote nodes, browser, voice,
semantic recall, plan-level approval.

---

## v0.2 — Authentication, then browser and richer system tools

### Shipped: API authentication and actor identity ✅

The largest known gap in v0.1 is closed. The assumption "the API is safe because
it is bound to localhost" is replaced by an explicit authenticated request and a
typed actor identity that survives the whole run.

- Bearer authentication on every endpoint but `GET /health`, fail-closed when no
  token is configured
- Typed `Actor` (human / service / node / system) with scopes and an
  authentication method, frozen and attenuation-only
- Centralised authorization: six scopes, unknown scopes denied, decided in one
  place rather than compared as strings in endpoints
- Identity propagated from request through task, orchestration, policy, tool
  call and every audit row - `actor_id` is never null
- Authentication, authorization, policy and tool failures kept as four distinct
  audit event types
- `doctor` FAILs on a non-loopback bind with no credential
- CLI keeps driving the runtime in-process, labelled `local_process`, with the
  reasoning documented rather than a token check that would enforce nothing

**Deliberately not yet:** mTLS, node identities, OIDC, per-actor policy. The
`Authenticator` protocol is the seam these arrive through; none of them requires
reworking the token checker.

### Shipped: credential lifecycle (v0.2.1) ✅

One token meaning one identity was the next limitation to fall. Authority is now
per-credential, and a credential is a separate thing from the actor it proves -
which is what makes several keys per principal, and losing one of them, ordinary
events rather than outages.

- Persisted credentials with their own actor, type, scopes and metadata; one
  actor may hold any number
- `scrappy token create / list / inspect / rotate / revoke / prune`
- Raw tokens shown once and never stored: what persists is
  `HMAC-SHA256(pepper, secret)` under a non-secret credential id, so lookup stays
  O(1) and a copied database yields verifiers rather than tokens
- Expiry optional per credential, evaluated against the clock on every request
- Revocation effective on the next request - no cache, no restart
- Overlap rotation: the replacement is issued while the original still works, in
  one transaction, so no failure leaves a principal with nothing valid
- Every administrative change audited with the administrator's own identity, and
  every request's audit row naming the credential that proved it
- `SCRAPPY_API_TOKEN` still accepted, with stored credentials taking precedence;
  `doctor` reports pepper provenance and warns while both are in use

**Deliberately not built:** HTTP credential administration (the CLI's authority
is the local-process boundary, and an HTTP path would need a scope that can mint
scopes), and `token migrate-legacy` - it could not preserve the old token's
value, so every client needs reconfiguring either way and the command would save
typing rather than risk.

### Still to come in v0.2

The theme is **more capability at the same level of control**. Everything below
is a typed tool with a declared risk level; none of it is a new bypass.
- **Browser automation** as typed operations - navigate, extract, screenshot -
  not "drive a browser however you like". Fetched page content joins the
  untrusted-data category, with the same delimiters as tool output.
- **Mutating git**: commit, branch, push, each separately classified. Push is
  PRIVILEGED because it leaves the machine.
- **Package and service tools** replacing `shell.run` for the common cases -
  `service.restart`, `package.install` - so the escape hatch is needed less
  often. A typed tool is auditable in a way a command line is not.
- **Log analysis** with structured parsing rather than `grep` through
  `shell.run`.
- **Plan-level approval.** Approving ten related privileged steps individually
  trains operators to click through. One approval showing the whole plan, still
  single-use and still exact, is safer than ten reflexive ones.
- **DNS pinning** for the HTTP tool, closing the rebinding race noted in the
  threat model.

---

## v0.3 — Voice and vision interfaces

New *interfaces*, not new authority. Both are additional `Face` implementations
speaking to the same runtime.

- Speech-to-text objective entry; spoken status and conclusions.
- Screenshot and image understanding for reading dashboards and consoles.
- **Approval stays textual and explicit.** A DESTRUCTIVE operation will not be
  approvable by voice - "yes" is too easy to say, too easy to mishear, and too
  easy to trigger with a recording. The typed confirmation phrase stays typed.

---

## v0.4 — Remote Scrappy nodes

The **Legs**. One control plane operating several machines.

- Node registry, mutual authentication, per-node capability grants.
- Distributed audit: every node's actions visible in one trail, with the
  originating node recorded.
- Fleet-wide policy, and per-node risk ceilings - a production database host
  can be read-only while a staging box is not.
- The event bus moves out of process (Redis Streams or NATS). This is why
  `EventBus` is a protocol in v0.1.
- **Blast radius becomes the central problem.** One approved action across
  fifty machines is a different risk from the same action on one, and the
  approval UI has to say which it is.

---

## v0.5 — VM and container operator layer

Scrappy OS operates virtualised guests.

- Container lifecycle as typed operations (Docker/Podman), not `docker` through
  the shell. Note that access to the Docker socket is equivalent to root on the
  host - it will be a separately gated capability, off by default.
- VM lifecycle via libvirt.
- **Windows and macOS arrive here**, as guests reached through explicit
  adapters, or through virtualisation - not by diluting the Linux core with
  cross-platform abstractions. The v0.1 core stays a Linux control plane.
- Snapshot-based rollback, which is the first point at which recovery becomes
  genuinely reliable rather than best-effort.

---

## v1.0 — Stable AI-native machine operating environment

The point at which the interfaces stop moving.

- Stable tool protocol and event schema; third-party tools without forking.
- Semantic memory with provenance and expiry - the design constraints are
  already written down in `memory/semantic.py`.
- Signed, tamper-evident audit chain.
- Supervised autonomy: policy-bounded reactions to *named* conditions, still
  going through the same approval gate. This is the one place the "heartbeat is
  not permission to invent work" rule relaxes, and it relaxes narrowly - a
  named condition, a named response, a bounded risk level, an audit entry.
- Multi-user with per-user permissions and delegated approval.

---

## Principles that do not change

Whatever gets added:

1. **Every machine-changing action passes through the policy engine.** No
   version adds a bypass, including for recovery.
2. **The AI never receives unrestricted root by default.**
3. **Every tool invocation creates an audit record**, including denials.
4. **Model output never becomes a command without validation.**
5. **Unknown actions default to deny.**
6. **Destructive operations require explicit human confirmation.**
7. **Autonomy expands only where the control to bound it already exists.**

## Explicitly not planned

- Scrappy OS as a kernel or a Linux distribution. Linux is the body; this is
  the layer above it.
- An agent that acts without a stated objective.
- A "trust me" mode that disables the policy engine.
- Cross-platform abstraction in the core. Other operating systems arrive
  through adapters at v0.5, so the Linux path stays honest.
