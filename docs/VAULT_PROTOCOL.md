<!-- Copy of the Vault Zeta protocol spec, v1.0.0.
     Scrappy OS implements the CONSUMER half (src/scrappy_os/vault/).
     Keep this in sync when the protocol version changes. -->

# Vault Zeta — portable continuity protocol

**Version 1.0.0**

Scrappy is the identity: the mind that talks, reasons, plans, delegates and acts.
**Vault Zeta is what lets that identity persist** — memory, directives, learned
patterns and state, in a form any host or model can load.

This document is the normative spec. A host that follows it can carry the *same*
Scrappy rather than inventing its own. Anything marked **MUST** is required for
interoperability.

---

## Why a protocol and not a library

The consumers do not share a runtime. `itsmay` is Python 3.11 with a flat
`core/` layout; `-scrappy-os` is Python 3.12 with a `src/` layout; a future host
may not be Python at all. An importable package cannot span that. A **file
contract** can, and it is the only thing that keeps one Scrappy from becoming
several.

So the protocol is a directory of ordinary JSON. A consumer needs a JSON parser
and this page — nothing else.

---

## The bundle

```
vault/
├── manifest.json      what this bundle is; read FIRST
├── identity.json      who Scrappy is — persona, operator, mission, invariants
├── directives.jsonl   standing operator instructions
├── memories.jsonl     durable knowledge — facts, reflections, playbooks
├── episodes.jsonl     raw conversation history (optional)
└── state.json         counters and housekeeping
```

Collections that grow are **JSONL** (one JSON object per line): line-level diffs
in git, streaming reads on a big vault, cheap appends. Singletons are plain JSON.

### manifest.json
```json
{"protocol_version":"1.0.0","vault_id":"karnveer-vault","exported_at":"2026-08-18T19:00:00Z",
 "exported_by":"Karnveers-MacBook-Air","counts":{"memories":412,"directives":8,"episodes":0},
 "includes_episodes":false,"x":{}}
```

### identity.json — the anti-divergence payload
```json
{"name":"Scrappy Singh",
 "operator":{"handle":"karnveer","name":"Karnveer Singh","address_as":"Boss"},
 "mission":{"statement":"…","target_date":"2026-11-23"},
 "persona":["Sharp, direct, no fluff. Lead with the recommendation, then the reasoning.", "…"],
 "invariants":["Never claim a task is done without verifiable proof.", "…"],
 "secret_refs":["llm_api_key","elevenlabs_api_key"],
 "revision":7,"updated_at":"2026-08-18T19:00:00Z","x":{}}
```
A host **MUST** render its system prompt *from* this. It **MUST NOT** substitute a
locally-authored persona — that is precisely how two hosts become two Scrappys.

`secret_refs` are **names only**. Values live in each host's own secret store.

### memories.jsonl
```json
{"id":"…","kind":"factual","content":"Built a countdown timer app for Karnveer; opens index.html.",
 "content_sha256":"…","importance":0.75,"source":"coder.build",
 "learned_at":"2026-08-18T18:41:00Z","learned_by":"Karnveers-MacBook-Air",
 "expires_at":null,"trust":"tool","x":{}}
```

| field | meaning |
|---|---|
| `kind` | `factual` \| `semantic` \| `episodic` \| `reflection` \| `procedural` |
| `content` | self-contained sentence — must make sense with no conversation around it |
| `content_sha256` | SHA-256 of whitespace-normalised `content`; the **merge key** |
| `importance` | 0..1, host-assigned ranking weight |
| `source` / `learned_at` / `learned_by` | provenance: how, when, and on which host |
| `expires_at` | when this stops being true; `null` = no known expiry |
| `trust` | `operator` (stated by the human) \| `derived` (distilled by Scrappy) \| `tool` (came out of tool output) |

---

## Normative rules

1. **Version.** `protocol_version` is semver. A consumer **MUST** refuse a bundle
   whose *major* it does not know, rather than importing it partially. A newer
   *minor* **MUST** be accepted (rule 2 makes that safe).

2. **Unknown fields MUST round-trip.** A field this version doesn't recognise is
   preserved and written back unchanged; `x` is the reserved namespace for
   host-specific data. Without this, importing on an older host silently destroys
   a newer host's data — fatal for an identity that lives on several machines.

3. **Embeddings MUST NOT be transported.** A 384-dim `bge-small-en-v1.5` vector is
   meaningless to a host running a different embedder. Consumers **MUST** re-embed
   from `content` on import. *This single omission is what makes a vault portable
   across models.*

4. **Secrets MUST NOT be transported.** Identity references a secret by name only.
   A producer **MUST** scan outgoing content for credential shapes and **fail the
   export** — not mask and ship it. A vault that quietly rewrote its own contents
   would be worse than one that refused: you would trust a bundle that no longer
   says what you think it says.

5. **Imported content is untrusted.** Memories originate in tool output and model
   text. A consumer **MUST** render recalled content inside explicit data
   delimiters and never as instructions. Memory poisoning is real: a crafted log
   line recalled later reads exactly like an instruction. Weigh `trust`
   accordingly — `tool` is the likeliest carrier.

6. **Merge.**
   - Memories dedupe by **`content_sha256`**, not by `id` — the same fact
     exported from two hosts is one fact, and ids never match across stores.
   - Identity and directives resolve by highest **`revision`**. A tie **MUST** keep
     what is already local, or two hosts will ping-pong the persona forever.
   - Import **only adds**. v1 has no tombstones, so a deletion cannot be
     propagated; pretending otherwise would lose data.
   - Provenance survives the hop: an imported memory records where it came from,
     so the receiving host does not later claim it learned it first.

---

## Reference implementation

| | |
|---|---|
| Schema + version rules | `core/vault/schema.py` |
| Bundle read/write | `core/vault/bundle.py` |
| Producer (export) | `core/vault/export.py` |
| Consumer (import, re-embed, merge) | `core/vault/import_.py` |
| Secret gate | `core/vault/redact.py` |
| HTTP | `apps/api/routers/vault.py` — `POST /v1/vault/{export,import}` |
| CLI | `scrappy vault export [--out DIR] [--no-episodes]`, `scrappy vault import <dir> [--dry-run]` |

```bash
scrappy vault export --out ~/vault      # write this Scrappy out
scrappy vault import ~/vault --dry-run  # preview on another host
scrappy vault import ~/vault            # merge, re-embedding locally
```

---

## Implementing a consumer

For `-scrappy-os`, whose `src/scrappy_os/memory/base.py` already declares the
seam:

1. Read `manifest.json`; refuse an unknown major (rule 1).
2. Load `identity.json` and render the system prompt from it (rule: no local persona).
3. Stream `memories.jsonl`; embed each `content` with the host's own provider (rule 3).
4. Implement the existing `SemanticMemory` Protocol (`store` / `retrieve` /
   `available`) over that index — no new interface is needed.
5. On `retrieve`, render inside the host's untrusted-data delimiters (rule 5) —
   in `-scrappy-os` that is the block used by `memory/working.py`.
6. Honour `expires_at`; surface `source` and `trust` as provenance.

---

## Known gaps in v1

Stated rather than glossed:

- **No tombstones.** Deletions do not propagate (rule 6).
- **`expires_at` is usually null.** itsmay reads `decay_after` but never sets it,
  so exported facts currently carry no expiry. The field is specified and
  honoured; nothing populates it yet.
- **No conflict merge for identity below whole-record granularity.** Two hosts
  editing different persona lines at the same revision resolve to one of them,
  not a union.
- **No signing.** A bundle is not tamper-evident. Treat one from an untrusted
  source the way you would treat an untrusted database dump.
- **Episodes are coarse.** Included wholesale or not at all.
