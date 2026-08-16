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

## v0.2 — Browser and richer system tools

The theme is **more capability at the same level of control**. Everything below
is a typed tool with a declared risk level; none of it is a new bypass.

- **API authentication.** Token or mTLS, so exposing the API is a configuration
  choice rather than a mistake. This is the largest known gap in v0.1.
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
