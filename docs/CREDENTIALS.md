# Credentials

How Scrappy OS issues, stores, verifies and retires the credentials that
authenticate API callers.

This document is referenced from `security/credentials.py`,
`security/credential_service.py` and `security/pepper.py`. It covers the
operational side: where the pepper should live, who may administer credentials,
and what an operator should do when one leaks.

For the trust boundaries this sits inside, see [SECURITY.md](SECURITY.md). For
the attacks it is meant to survive, see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## 1. Actors and credentials are different things

An **actor** is *who*. A **credential** is *one way of proving it*.

Keeping them apart is the central design decision of this subsystem. A person
may hold a laptop token and a CI token, lose one, rotate it, and remain the same
principal in the audit trail. Collapsing the two — making the credential the
identity — is what forces "revoke the token" and "delete the user" to be the same
operation.

```
Actor: alice (human)
  ├── cred_a8f13e9c2b41   laptop     active
  ├── cred_5c02be71fa93   CI runner  active
  └── cred_9e44a0d17b28   old laptop revoked 2026-08-01
```

Revoking the third changes nothing about who `alice` is, and every audit row she
ever produced still attributes to her.

Authorization reads `Actor.scopes`. It never reads the actor's *type*, id or
display name. Adding a new `ActorType` therefore cannot silently widen access.

---

## 2. Token format

```
scrp_a8f13e9c2b41_kJ8sQ2vN...
└──┘ └──────────┘ └─────────┘
 │        │            └─ secret: 256 bits from secrets.token_urlsafe
 │        └─ credential id (not secret): finds the row
 └─ prefix: makes a leaked token greppable and scanner-visible
```

The id half is **not** a secret. It exists so authentication reads exactly one
row instead of hashing the presented value against every credential in the
table, which keeps verification O(1) as credentials accumulate.

The `scrp_` prefix is a deliberate giveaway. A token pasted into a log, a CI
transcript or a GitHub comment should be findable with `grep -r scrp_` and
recognisable to a secret scanner on sight.

---

## 3. What is stored

**The raw token is never persisted.** What lands in the database is:

```
verifier = HMAC-SHA256(pepper, secret)
```

plus the non-secret identifiers needed to find and describe the credential. An
operator who steals `scrappy.db` gets verifiers, not tokens, and cannot present
them to the API.

### Why HMAC and not Argon2id or scrypt

Slow KDFs exist to make *guessing* expensive, and guessing is only a threat when
the secret is guessable. These secrets are 256 bits from the OS CSPRNG; brute
force is not on the table at any cost factor. A memory-hard KDF would buy
nothing and would add a dependency plus per-request latency on the
authentication hot path.

The real threat to a high-entropy token is **theft of the stored value**, and
that is what the pepper addresses: a verifier is useless without a key the
database does not contain.

**The honest limitation:** an attacker who takes the pepper *and* the database
can confirm a guessed token offline. They still cannot reverse a verifier into a
token.

---

## 4. Where the pepper should live

The pepper is the key that makes a stolen database insufficient. Its location
decides how much that is worth.

### Production: `SCRAPPY_TOKEN_PEPPER`

Put it in the service's environment file, root-owned, mode `0640`:

```ini
# /etc/scrappy-os/scrappy.env
SCRAPPY_TOKEN_PEPPER=<32+ random URL-safe characters>
```

Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

The key then lives outside the data directory, so stealing the database is
genuinely not enough.

### Fallback: generated in the data directory

If `SCRAPPY_TOKEN_PEPPER` is unset, Scrappy generates a pepper on first use and
stores it as `token_pepper` (mode `0600`) beside the database.

This makes the system work out of the box without an operator inventing a
secret, and it is **honestly weaker**: the pepper sits next to the database it
protects, so anything that can read one can usually read the other. `scrappy
doctor` reports this as a WARN rather than a clean bill.

The fallback is generated **once and persisted**, never per start. A pepper that
changed at startup would silently invalidate every credential in the database,
which reads to an operator as "all my tokens broke for no reason".

### Changing the pepper invalidates everything

Every verifier is keyed by it. Introducing `SCRAPPY_TOKEN_PEPPER` after
credentials were issued under the generated fallback will make all of them fail
authentication. Reissue them, or copy the generated value into the environment
variable.

`doctor` warns about this before it can bite you.

---

## 5. Who may administer credentials

`scrappy token` is **local-only**. There is no HTTP equivalent, and its absence
is a decision rather than an oversight.

Whoever can run `scrappy token` can already read the database, the pepper and
the environment file. A credential check there would verify a secret the caller
could simply read off disk — a boundary that looks like security and enforces
nothing. The real authority is the host's file permissions.

An HTTP credential-minting endpoint would be a genuinely new attack surface: a
remote caller issuing itself authority. It is not needed to make rotation and
revocation work, so it does not exist.

Every lifecycle operation is audited with the administrator's identity, so
"who issued this credential" is answerable even though the operation is not
itself authenticated.

---

## 6. Lifecycle

### Issue

```bash
scrappy token create --actor svc-ci --scopes task:create,task:read --name "CI runner"
scrappy token create --actor alice --type human --scopes audit:read --expires-in 30d
```

Scopes are **required**. There is no default set, because a default would
eventually be the wrong one and nobody would notice. Grant the narrowest set
that works.

The token is printed **once**. Nothing recorded it and no command can print it
again.

### Inspect

```bash
scrappy token list              # active only
scrappy token list --all        # including revoked and expired
scrappy token inspect cred_a8f13e9c2b41
```

None of these can show a token, a verifier or the pepper.

### Rotate

```bash
scrappy token rotate cred_a8f13e9c2b41                     # overlap (default)
scrappy token rotate cred_a8f13e9c2b41 --revoke-previous   # immediate cutover
```

The default **leaves the original valid**. That is the point: update clients to
the new token, confirm they work, then revoke the old one.

```bash
scrappy token revoke cred_a8f13e9c2b41
```

Rotating by deleting first guarantees an outage of exactly the length of the
operator's reaction time, which is why `--revoke-previous` is opt-in.

The insert and the optional revoke share one transaction, so the pair cannot
half-apply and strand an actor with no working credential.

### Revoke

```bash
scrappy token revoke cred_a8f13e9c2b41
```

Effective on the **next request** — authentication reads the row every time, so
there is no cache to invalidate, no restart needed and no window in which a
revoked credential still works.

Revocation is idempotent and keeps the original timestamp. The moment authority
was withdrawn is a fact, and a second command should not rewrite it.

### Prune

```bash
scrappy token prune --older-than 90d
```

Deletes **revoked or expired** credential records last relevant before the
cutoff. Active credentials are never removed regardless of age — "old" is not
"unwanted".

This is the only operation that loses data. The audit events describing each
credential's creation and revocation survive it, so the trail still explains
what happened.

`--older-than` accepts a duration (`90d`) or an absolute ISO-8601 timestamp with
a timezone. A duration reaches *backwards* from now.

---

## 7. What a failed authentication tells the caller

Unparseable, no such id, wrong secret, revoked and expired are five genuinely
different events for an operator, and **exactly one answer for a caller**: 401,
"the presented credential is not recognised".

- Distinguishing "no such credential" from "wrong secret" is a
  credential-enumeration oracle.
- Distinguishing "revoked" would tell a thief precisely when they were noticed.

The distinctions are preserved internally and recorded in the audit trail, where
the operator can see them and the client cannot.

Verification against a missing credential still performs a dummy HMAC, so
"no such id" and "wrong secret" take comparable time and an attacker cannot
probe which ids exist by timing the response.

---

## 8. If a token leaks

1. **Revoke it.** `scrappy token revoke <id>` — effective immediately, no
   restart.
2. **Check what it did.** Every audit row carries the `actor_id` and the
   `credential_id` that produced it:

   ```bash
   scrappy audit --json -n 500 | jq 'select(.credential_id == "cred_a8f13e9c2b41")'
   ```

   There is no `--actor` filter on `scrappy audit` yet; filtering the JSON is
   the current answer.
3. **Issue a replacement** if the actor still needs one.
4. **Do not rotate the pepper** unless you believe the *database* was taken as
   well. Rotating it invalidates every credential in the system.

If the database and the pepper were both taken, treat every credential as
compromised: revoke all of them, change `SCRAPPY_TOKEN_PEPPER`, and reissue.

---

## 9. Residual risk

Stated plainly, because a credential system that oversells itself is worse than
one that does not exist.

| Risk | Status |
|---|---|
| **Bearer tokens are replayable.** Anyone who intercepts one can use it until it is revoked or expires. | Not mitigated. Terminate TLS in front of the API, or keep it on loopback and reach it over SSH. |
| **The token is sent on every request.** Any intermediary that logs headers captures it. | Not mitigated by design. mTLS or a signed-request scheme would fix it; neither is implemented. |
| **A generated pepper sits beside the database.** One stolen directory yields both. | Mitigated only by using `SCRAPPY_TOKEN_PEPPER`. `doctor` warns. |
| **Pepper + database together allow offline guess confirmation.** | Accepted. High-entropy secrets make it useless in practice. |
| **`scrappy token` is unauthenticated.** | Accepted and documented above — the boundary is host file permissions. |
| **No rate limiting on authentication attempts.** | Not implemented. Loopback binding is the current mitigation; this becomes real if the API is ever exposed. |
| **Scopes are coarse.** A credential holding `approval:grant` can approve anything, not a specific class of operation. | Accepted for now. Capability delegation is a later milestone. |

---

## 10. Seams for later

The subsystem is shaped so these can be added without rewriting it:

- **`CredentialStore` is a Protocol.** A shared control plane or a node-local
  store implements it and nothing above changes.
- **`SupportsDeletion` is separate**, so an append-only or WORM-backed store can
  legitimately refuse to delete and `prune` fails loudly rather than lying.
- **`Authenticator` is a Protocol.** mTLS, OIDC and node identities arrive as
  siblings of `CredentialAuthenticator`, not as branches inside a token checker.
- **`AuthMethod` is recorded on every credential and audit row**, so a
  token-bearing caller stays distinguishable from a future certificate-bearing
  one.
- **`expires_at` already exists**, so short-lived capability tokens need a
  minting path, not a schema change.
