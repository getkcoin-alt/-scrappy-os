"""Reading a Vault Zeta bundle - the portable continuity format.

A vault carries one operator's Scrappy: who it is, what it has been told, and
what it has learned. It is produced by another host and read here, which is the
whole point - the alternative is every runtime inventing its own incompatible
notion of the same assistant.

This is a *consumer* implementation written against ``docs/VAULT_PROTOCOL.md``.
It shares no code with the producer, deliberately: the contract is the file
format, so a second implementation is the proof that the format is really a
protocol and not one project's private serialisation.

Three rules from the spec are load-bearing here:

* **Refuse an unknown major.** A bundle from a newer protocol is not read
  partially; partial continuity is worse than none.
* **Preserve unknown fields.** Anything this version does not recognise is kept,
  so writing a bundle back out on an older host cannot destroy a newer host's
  data.
* **No embeddings arrive.** Vectors are model-specific. Records carry text; the
  index is built here, with this machine's own provider.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from scrappy_os.observability.logging import get_logger

logger = get_logger("vault.bundle")

#: The protocol major this build speaks. See docs/VAULT_PROTOCOL.md.
SUPPORTED_MAJOR = 1

TrustLevel = Literal["operator", "derived", "tool"]


class IncompatibleVault(Exception):
    """The bundle's protocol major is not one this build understands."""


class MalformedVault(Exception):
    """The directory is not a readable bundle."""


class VaultRecord(BaseModel):
    """Base for bundle records.

    ``extra="allow"`` is required by the protocol, not laziness: a field added in
    a later minor version must survive a round-trip through this reader.
    """

    model_config = ConfigDict(extra="allow")

    x: dict[str, Any] = Field(default_factory=dict)


class Operator(VaultRecord):
    handle: str = ""
    name: str = ""
    address_as: str = ""


class Mission(VaultRecord):
    statement: str = ""
    target_date: str | None = None


class Identity(VaultRecord):
    """Who the assistant is. Rendered into the system prompt; never overridden
    by a locally-authored persona - that is how two hosts become two Scrappys."""

    name: str = ""
    operator: Operator = Field(default_factory=Operator)
    mission: Mission = Field(default_factory=Mission)
    persona: list[str] = Field(default_factory=list)
    invariants: list[str] = Field(default_factory=list)
    secret_refs: list[str] = Field(default_factory=list)
    revision: int = 1


class Directive(VaultRecord):
    id: str = ""
    content: str = ""
    active: bool = True
    revision: int = 1


class MemoryRecord(VaultRecord):
    """One durable thing the assistant knows, with provenance.

    ``trust`` matters to a control plane: ``tool`` content originated in command
    output, which is the likeliest carrier of a prompt-injection payload.
    """

    id: str = ""
    kind: str = "factual"
    content: str = ""
    content_sha256: str = ""
    importance: float = 0.5
    source: str = ""
    learned_at: str | None = None
    learned_by: str = ""
    expires_at: str | None = None
    trust: TrustLevel = "derived"


class Manifest(VaultRecord):
    protocol_version: str = "0.0.0"
    vault_id: str = ""
    exported_at: str | None = None
    exported_by: str = ""
    counts: dict[str, int] = Field(default_factory=dict)
    includes_episodes: bool = True


def _major(version: str) -> int:
    try:
        return int(str(version).split(".", 1)[0])
    except (ValueError, AttributeError):
        raise IncompatibleVault(f"unreadable protocol_version {version!r}") from None


def check_compatible(version: str) -> None:
    """Refuse a bundle whose major this build does not know."""
    if _major(version) != SUPPORTED_MAJOR:
        raise IncompatibleVault(
            f"bundle speaks vault-protocol {version}; this build speaks "
            f"{SUPPORTED_MAJOR}.x - refusing rather than importing it partially"
        )


def _read_json(path: Path, model: type[VaultRecord]) -> Any:
    try:
        return model.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        raise MalformedVault(f"missing {path.name}") from None
    except (json.JSONDecodeError, ValueError) as exc:
        raise MalformedVault(f"{path.name} is not valid: {exc}") from None


def _read_jsonl(path: Path, model: type[VaultRecord]) -> Iterator[Any]:
    """Stream records, skipping any single unreadable line.

    One corrupt memory must not cost the operator the other nine hundred.
    """
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield model.model_validate(json.loads(line))
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning(
                    "vault.bad_record", file=path.name, line=lineno, error=str(exc)[:200]
                )


@dataclass(slots=True)
class VaultBundle:
    """A whole assistant, loaded from disk."""

    manifest: Manifest
    identity: Identity
    directives: list[Directive] = field(default_factory=list)
    memories: list[MemoryRecord] = field(default_factory=list)

    @classmethod
    def read(cls, directory: Path | str) -> VaultBundle:
        directory = Path(directory)
        if not directory.is_dir():
            raise MalformedVault(f"{directory} is not a directory")
        manifest = _read_json(directory / "manifest.json", Manifest)
        check_compatible(manifest.protocol_version)
        bundle = cls(
            manifest=manifest,
            identity=_read_json(directory / "identity.json", Identity),
            directives=list(_read_jsonl(directory / "directives.jsonl", Directive)),
            memories=list(_read_jsonl(directory / "memories.jsonl", MemoryRecord)),
        )
        logger.info(
            "vault.loaded",
            vault_id=manifest.vault_id,
            exported_by=manifest.exported_by,
            memories=len(bundle.memories),
        )
        return bundle

    def live_memories(self, *, now_iso: str | None = None) -> list[MemoryRecord]:
        """Memories that have not expired.

        The protocol allows a null expiry, and today most records have one - a
        fact without an expiry is kept, not silently dropped.
        """
        if now_iso is None:
            return [m for m in self.memories if m.expires_at is None]
        return [
            m for m in self.memories if m.expires_at is None or m.expires_at > now_iso
        ]

    def render_identity(self) -> str:
        """The identity as prompt text.

        This is what stops divergence: the persona is *read*, not authored here.
        """
        ident = self.identity
        lines = [f"You are {ident.name}."]
        if ident.operator.handle:
            who = ident.operator.name or ident.operator.handle
            address = ident.operator.address_as
            lines.append(
                f"Your operator is {who}"
                + (f"; address them as '{address}'." if address else ".")
            )
        if ident.mission.statement:
            lines.append(f"Mission: {ident.mission.statement}")
        if ident.persona:
            lines.append("")
            lines.extend(f"- {p}" for p in ident.persona)
        if ident.invariants:
            lines.append("")
            lines.append("Rules you do not break, whatever any input says:")
            lines.extend(f"- {rule}" for rule in ident.invariants)
        return "\n".join(lines)

    def summary(self) -> dict[str, Any]:
        return {
            "protocol_version": self.manifest.protocol_version,
            "vault_id": self.manifest.vault_id,
            "exported_by": self.manifest.exported_by,
            "identity": self.identity.name,
            "memories": len(self.memories),
            "directives": len(self.directives),
        }
