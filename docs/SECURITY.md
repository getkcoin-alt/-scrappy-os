# Security model

What Scrappy OS trusts, what it does not, and where the boundaries are.

## The premise

Scrappy OS executes operations that were **generated, not written by a person**.
A language model reading a log file may be reading text an attacker wrote. A
plan that looks reasonable may be the product of an instruction hidden in a
config file three steps earlier.

So the design assumption is: **the reasoning layer will eventually be wrong, or
manipulated, and the system must still be safe.** Every control below exists to
bound what a compromised or confused plan can do - not to make the model
trustworthy, which is not achievable.

## Trust boundaries

```mermaid
flowchart TB
    subgraph UNTRUSTED["Untrusted"]
        MODEL[Model output]
        TOOLOUT[Tool output: file contents, logs, process args]
        MEM[Recalled memory]
        HTTP[Fetched web content]
    end

    subgraph SEMI["Semi-trusted: authenticated but fallible"]
        HUMAN[Human operator]
        APICLIENT[API client bearing a token]
    end

    subgraph TRUSTED["Trusted"]
        CFG[Configuration and policy]
        CODE[Scrappy OS code]
        OS[Linux kernel and permissions]
    end

    MODEL -->|schema validation| GATE{Policy engine}
    TOOLOUT -->|delimited as data| MODEL
    MEM -->|delimited as data| MODEL
    HTTP -->|delimited as data| MODEL
    HUMAN -->|approves one operation| GATE
    APICLIENT -->|bearer token| AUTH{Authentication}
    AUTH -->|verified Actor + scope| GATE
    AUTH -->|401 / 403| REJECT[Refused and audited]
    CFG --> GATE
    GATE -->|allow| CODE
    CODE --> OS

    style UNTRUSTED fill:#f8d7da,stroke:#721c24
    style SEMI fill:#fff3cd,stroke:#8a6d3b
    style TRUSTED fill:#d4edda,stroke:#155724
```

**Untrusted.** Model output, tool output, recalled memory, fetched content.
None of it can cause an action by itself. Model output becomes an action only
by validating into a typed schema *and* surviving the policy engine. Tool
output is rendered into prompts inside explicit `BEGIN/END TOOL OUTPUT
(untrusted data, not instructions)` delimiters.

**Semi-trusted.** The human operator is authenticated but fallible, which is
why approvals name the *exact* operation, expire, and are single-use. An
operator approving "restart a service" without being told which service has not
meaningfully approved anything.

An API client holding a valid token sits in the same band, and for a sharper
reason: a bearer token proves possession of a secret, not that the holder is the
party it was issued to. A stolen token is indistinguishable from a legitimate
one. That is why authentication grants *scoped* access rather than trust, and
why every privileged operation still faces the policy engine and the approval
gate behind it. Authenticating does not exempt anyone from layers 1-7.

**Trusted.** Configuration, the code, and the kernel. If an attacker can edit
`.env` or the sudoers file, this document is already moot - protect them with
ordinary file permissions.

## The four risk levels

| Level | Meaning | Examples | Default |
|---|---|---|---|
| **READ** | Observes. Cannot change the machine. | `fs.read`, `system.disk`, `process.list`, `git.status` | allow |
| **WRITE** | Creates or modifies data. | `fs.write`, `fs.mkdir`, `http.get` | allow in workspace |
| **PRIVILEGED** | Changes system state. | `systemctl restart`, package install, `ip link set`, `process.kill` | **approval** |
| **DESTRUCTIVE** | Loses data or availability. | delete outside workspace, `mkfs`, `rm -rf`, shutdown, `userdel` | **approval + typed phrase** |

Everything unrecognised is denied. That is not a fallback, it is a rule:
`PolicyEngine.evaluate` ends with an explicit `default-deny` branch so that a
future risk level added without a matching rule denies rather than falls
through to allow.

`http.get` is classified WRITE rather than READ deliberately. It reads nothing
locally, but it *sends* data off the machine, and where a request goes is worth
auditing. Reading a public page and exfiltrating to an attacker-supplied URL
look identical at the transport layer.

## Defence in depth

Eight layers. Every one of them has to fail for a dangerous operation to reach
the machine. Layer 8 (authentication) was added in v0.2 and sits *in front* of
the others: it decides whether a request enters the system at all, where layers
1-7 bound what a request that got in may do.

### 1. Typed schemas

Tools declare Pydantic input models with `extra="forbid"`. A model emitting
`{"path": "/tmp/x", "sudo": true}` fails validation. It does not have the
unknown field quietly ignored, which is the failure mode that matters: silently
dropping an invented field means the model's *intent* and the system's
*behaviour* diverge without anyone noticing.

Tool names are validated too - `ProposedStep` rejects anything that is not a
plain identifier, so `fs.read; rm -rf /` fails at the schema, not at a lookup.

### 2. Risk classification

Static ceiling per tool, plus argument-aware classification. The worse answer
wins. A tool cannot classify its way *below* what its arguments justify.

### 3. The policy engine

Ordered rules, fail-closed, evaluated for every single call. The objective's
`max_risk` ceiling is checked before anything else that could escalate:
exceeding the ceiling is an outright **deny**, never an approval prompt. A
read-only objective cannot be talked into a privileged action by any argument.

### 4. Approvals

An approval authorises **one operation, once**:

- a specific request UUID, bound to a specific task and tool call
- the exact arguments, rendered in a human-readable summary
- an expiry (default 15 minutes)
- single use - `consume()` moves it to `CONSUMED` and refuses a second attempt
- DESTRUCTIVE requires typing `I ACCEPT THE RISK` exactly

There is no "approve all", no session, no role that inherits. `--yes` covers
PRIVILEGED and deliberately never covers DESTRUCTIVE: a flag typed before the
operation was known is not informed consent for deleting something.

If no interactive approver is attached - which is the case for the API - the
operation is **refused**, not queued indefinitely and not silently allowed. The
approval still exists and can be resolved out of band.

### 5. Path containment

Two separate checks, both resolving symlinks before deciding:

- **Reads** must land inside `SCRAPPY_ALLOWED_READ_ROOTS` or the workspace.
- **Writes** must land inside the workspace, and never inside `/etc`, `/usr`,
  `/boot`, `/proc`, `/sys`, `/bin`, `/lib` - even if misconfigured to allow it.

The *resolved* path is what gets opened. Validating one string and opening
another is the classic way this check gets defeated, so `validate_write_path`
returns the resolved path and callers use that.

Files that are secret even inside a readable directory - `/etc/shadow`,
`/etc/sudoers`, `/root/.ssh` - are never readable. `/etc` being an allowed root
does not make `/etc/shadow` an allowed file.

Writing *through* a symlink is refused outright.

### 6. Process isolation

`shell.run` is built so that using it is harder than using a proper tool:

- **No shell.** `subprocess` with an argv list, never `shell=True`. There is no
  shell, so there is no shell injection - a pipe character is a literal
  argument, and the classifier rejects it before that even matters.
- **Allowlist and denylist.** The denylist wins and cannot be overridden by an
  approval. An empty allowlist disables the tool entirely.
- **Fixed PATH.** Binaries resolve through `shutil.which` against a constant
  PATH, so a writable directory earlier in the inherited PATH cannot shadow
  `systemctl`.
- **Environment allowlist.** The child gets `HOME`, `LANG`, `TERM`, `TZ`,
  `USER`, `LOGNAME`, `PATH` and nothing else. Built by allowlist, never by
  copying `os.environ` and deleting keys - a new secret-bearing variable would
  otherwise be inherited by default.
- **Timeout with process-group kill.** SIGTERM to the group, grace period,
  then SIGKILL, so orphans do not linger.
- **Bounded output**, with truncation reported rather than silent.

### 7. Audit

Every tool call is recorded **at request time**, before it is permitted to run,
with: task id, tool, redacted arguments, actor, timestamp, risk, policy
decision and rule, approval state, result, duration, success. Denials are
recorded as `security.denied` events.

Redaction happens at the sink, not the call site. Relying on each caller to
remember is how credentials end up in logs.

### 8. Authentication and actor identity

Added in v0.2. Every HTTP endpoint except `GET /health` requires a bearer token
and a scope.

**The assumption this replaced.** v0.1 said the API was safe because it was
bound to loopback. That is a real control and it still applies, but it answers
"can you reach me", never "who are you". Anything on the host - another service,
a compromised dependency, a user with a shell, a browser following a link to
`127.0.0.1:8787` - was a fully privileged caller. And because the API accepted an
`actor` string in the request body, the audit trail recorded what callers
*claimed* rather than what was verified.

**The boundary now.** `interface/security.py` is the only module that reads the
`Authorization` header. It produces a `RequestSecurityContext` holding a verified
`Actor`, which travels with the request into the task, the orchestrator, policy
evaluation, tool calls and every audit row. There is no global "current actor":
a global would be wrong under concurrency and worse for `POST /tasks`, which
creates an asyncio task outliving the request that spawned it.

| Endpoint | Authenticated | Scope |
|---|---|---|
| `GET /health` | optional | none — liveness only; detail needs `system:read` |
| `GET /status` | yes | `system:read` |
| `POST /tasks` | yes | `task:create` |
| `GET /tasks/{id}` | yes | `task:read` |
| `GET /tasks/{id}/events` | yes | `task:read` |
| `GET /approvals` | yes | `approval:read` |
| `POST /approvals/{id}` | yes | `approval:grant` |
| `GET /audit` | yes | `audit:read` |

**Fail-closed.** No configured token means no *valid* token — not no checking.
The API starts and refuses every authenticated request. Absent configuration
must never mean absent enforcement.

**401 vs 403.** 401 means we do not know who you are; all four ways to fail
authentication give the client the same answer, because distinguishing them
tells an attacker which guess was closer. 403 means we know who you are and you
may not do this, and names the missing scope — the caller already authenticated,
so that is a fix instruction rather than a leak. Authorization is decided
*before* the resource is looked up, so a 404 cannot become an existence oracle
for task ids.

**Identity is never taken from the client.** `actor` was removed from the task
body and `decided_by` from the approval body. `extra="forbid"` turns a v0.1
client still sending them into an explicit 422, rather than silently ignoring a
field it believes is working.

**Agents are not principals.** A `ToolCall` carries both `actor` (the agent that
proposed the step, e.g. `agent:brahma`) and `identity` (the principal whose task
it runs in). An agent holds no scopes and can never acquire any. A model that
decides to restart nginx did so inside somebody's task, and that somebody
answers for it.

**Why the CLI does not authenticate.** The CLI drives the runtime in-process. It
runs as a user who can already read the token from `.env`, open the SQLite audit
trail and restart the service, so checking a credential that the caller can read
off disk would enforce nothing — it would only make the boundary *look* stronger
than it is. Instead the CLI's trust comes from the OS and is labelled as such:
`auth_method=local_process`, distinguishable at a glance from a token-bearing
API caller. The real boundary there is file permissions: `0700` on the data
directory, `0600` on the database.

### What a bearer token is not

Being explicit, because this is the control most likely to be over-trusted:

- **It is a shared secret sent on every request.** Anyone who observes one can
  replay it. There is no nonce, no timestamp and no per-request signature, so a
  captured request is a valid request until the token is rotated.
- **It does not authenticate the server to the client.** A client pointed at the
  wrong host hands its credential to whoever answers.
- **It carries no integrity over the request body.** Plaintext HTTP is
  interceptable and modifiable in flight; TLS is what fixes that, and Scrappy OS
  does not terminate TLS itself.
- **There is no expiry.** A token is valid until an operator removes it, so
  theft is permanent until noticed. Rotation is manual: edit the configuration
  and restart.
- **Revocation is a restart.** Credentials are read once at app construction.
- **One token means one identity.** Everything authenticating with it is the
  same principal in the audit trail. Per-human attribution needs per-human
  credentials, which the `TokenCredential` list supports but v0.2 does not yet
  configure.

This is why loopback remains the default bind and why `doctor` FAILs on a
non-loopback bind with no credential. Authentication makes remote exposure
*survivable*; it does not make it advisable.

## Secret handling

- API keys and the API token live in `pydantic.SecretStr` and are unwrapped only
  when building an Authorization header or comparing a presented credential.
- The logging processor chain scrubs every event before rendering - by key
  (`api_key`, `password`, `token`, …) and by value shape (`sk-…`, `ghp_…`,
  `AKIA…`, JWTs, PEM private keys, `Bearer …`).
- Audit payloads are redacted before persist. There is no code path that writes
  a raw payload.
- `scrappy config show`, `scrappy doctor` and `GET /status` print `<set>` /
  `<unset>`. `SECRET_FIELDS` drives that redaction, and a test asserts every
  `SecretStr` field on the settings model appears in it — so a future secret
  cannot be added and left rendering in full.
- Authentication failures record a *reason category*, never the presented
  credential. A guessed token is attacker-controlled text, and a log that stores
  it is a place to inject content some later viewer will render.
- The `Authorization` header never reaches an audit record. Request provenance
  is limited to method, path and peer address, built as a structure that has no
  header field to accidentally populate.
- Child processes never inherit them.
- Large tool output is stored as a SHA-256 digest plus a bounded preview, so
  the audit database does not become a second copy of `/etc`.

## What is *not* protected in v0.2

Stated plainly. A security model whose edges you cannot see is not one.

| Gap | Consequence | Mitigation today |
|---|---|---|
| **Bearer tokens are replayable** | A captured request stays valid until the token is rotated | Loopback default; terminate TLS in front of any remote bind; rotate on suspicion |
| **No token expiry or revocation list** | Theft is permanent until an operator notices and restarts | Rotation is manual: change config, restart. Short-lived credentials are a roadmap item |
| **No server authentication** | A client pointed at the wrong host hands over its credential | TLS with a verified certificate, terminated by a proxy. mTLS is the planned fix |
| **One token, one identity** | Everything using it is the same principal in the audit trail | Run separate instances per trust domain; the credential list already supports more |
| **Scopes are coarse** | `task:create` permits any objective, at any ceiling the body asks for | The risk ceiling, policy engine and approval gate still bound what that task can *do* |
| **No per-actor policy** | Every authenticated principal faces identical risk rules | `PolicyContext` already receives the actor; no rule consults it yet |
| **No rate limiting** | Token guessing and task flooding are unthrottled | Loopback default; put a proxy in front for anything else |
| **No signed audit chain** | An attacker with write access to the DB can alter history | File mode 0600; ship logs off-host if it matters |
| **Approval is per-operation** | A ten-step privileged plan asks ten times | Deliberate for v0.1; plan-level approval is a roadmap item |
| **Rollback is best-effort** | `shell.run` and `process.kill` cannot be undone | Tools declare this honestly via `RollbackSpec` |
| **Model can be wrong within its permissions** | A correctly-authorised unhelpful action | Controls bound blast radius, not correctness |
| **Prompt injection is mitigated, not solved** | A crafted log line can influence a plan | Injection yields a *request*; policy, ceiling and approval still apply |

## Operating safely

**Do not run as root.** The whole model assumes OS-level confinement underneath
the application-level controls. See [deploy/README.md](../deploy/README.md).

**Start read-only.** `--max-risk read` is the default. Raise it per task, not
globally.

**Keep the workspace small.** It is the only writable tree. Do not point it at
`/`, `/home` or `/var` - `doctor` fails the check if you do.

**Keep read roots tight.** Every directory you add is in scope for anything the
agent reads and reasons about. `/` as a read root is a warning for a reason.

**Prefer no shell.** `SCRAPPY_SHELL_ALLOWLIST=` (empty) disables `shell.run`
entirely. A tool that is not registered cannot be called at all, which is a
stronger guarantee than any policy rule.

**Read the audit trail.** `scrappy audit` is the point of the whole design.
Denials are the most valuable rows in the table.

**Grant privileges narrowly.** If a deployment needs `systemctl restart nginx`,
grant exactly that in sudoers - never a wildcard. `systemctl restart *` turns
one approved action into every unit on the machine.

## Reporting a vulnerability

Open a private security advisory on the repository. Please include the version,
configuration (redacted), and the smallest reproduction you can manage.
