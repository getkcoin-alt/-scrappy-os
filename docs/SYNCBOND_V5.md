# SYNCBOND v5 — Scrappy Continuity Contract

Status: **architecture milestone / additive contract**

SYNCBOND is the versioned protocol shared by Vault Zeta, Scrappy OS, Scrappy Forge and Karnveer Command Center. It is intentionally model-neutral and transport-neutral.

## System roles

- **Vault Zeta** owns identity, long-horizon goals, durable memory, reflection and distilled experience.
- **Scrappy OS** owns machine/world observation, policy, approvals, execution, verification and authoritative action audit.
- **Scrappy Forge** owns bounded software experiments, patches, benchmarks and evidence for system evolution.
- **Karnveer Command Center** is the human governance/read-model surface. It is never the source of truth.
- **Omni-City** is the progressively richer world-model benchmark: simulation first, physical integrations later.

## Core rule

No component invents its own meaning for an Objective, Observation, Experience, Experiment or Node status. Cross-system traffic uses a `SyncEnvelope` with a stable actor, correlation ID, source, timestamp, schema version and typed event name.

## Event families

- `objective.requested`
- `objective.completed`
- `world.observed`
- `world.entity.changed`
- `action.proposed`
- `action.result`
- `approval.requested`
- `approval.resolved`
- `experience.recorded`
- `experiment.requested`
- `experiment.result`
- `node.status`

## Null-pointer policy

Unknown information is explicit. A field whose state matters must resolve to one of:

- `known`
- `unknown`
- `pending`
- `conflicted`
- `unauthorized`
- `unavailable`

Never silently coerce unknown to true, missing to safe, or confidence to certainty.

## World-model contract

A world entity has a stable ID, type, attributes and zero or more observations. Observations carry source, timestamp, confidence and provenance. Observations do not overwrite reality merely because they are newer; conflicting observations may coexist until reconciled.

Minimum entity classes for the first milestone:

- machine
- process
- file
- socket
- service
- repository
- deployment
- database
- api
- device
- sensor
- person_authorized_resource
- location
- vehicle
- building
- environment

Minimum relation vocabulary:

- `hosts`
- `runs`
- `depends_on`
- `connects_to`
- `observed_by`
- `located_at`
- `controls`
- `uses`
- `derived_from`

## Ownership boundaries

### Vault Zeta → Scrappy OS

Vault may submit an Objective. It does not directly mutate machines.

### Scrappy OS → Vault Zeta

Scrappy OS returns verified outcomes and Experiences suitable for durable learning. Raw operational logs remain in the execution/audit system unless intentionally distilled.

### Scrappy OS / Vault Zeta → Forge

Failures, regressions and missing capabilities may become Experiment requests. Forge may research, patch, test and report evidence. Core merge/deploy remains separately authorized.

### Command Center

Command Center consumes read models and emits authenticated user intent/approval. It must not fabricate health, node state or completion.

## Continuity invariant

Scrappy is not a single LLM process.

`Scrappy = identity + continuity + memory + objectives + world model + reasoning + tooling + policy + experience + verification + learning`

Models are replaceable reasoning engines. A model swap, process restart or UI replacement must not erase identity, goals, durable memory, audit provenance or world-state references.

## Phase-0 acceptance criteria

1. All four repositories pin protocol version `5.0.0`.
2. All cross-system events can be represented by the shared envelope.
3. Stable actor IDs and correlation IDs exist end-to-end.
4. Unknown/uncertain state is explicit.
5. Command Center status data can distinguish `unknown` from `healthy`.
6. No existing runtime behavior is weakened to adopt the contract.

## Next milestone

Wire real transports:

`Vault Objective -> Scrappy OS -> verified ActionResult/Experience -> Vault`

Then expose a read-only aggregate status to Command Center and route reproducible failures into Forge experiments.
