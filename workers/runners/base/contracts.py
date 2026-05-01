from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any


@dataclass(slots=True, frozen=True)
class EvidenceArtifact:
    name: str
    content_type: str
    data: bytes
    kind: str = "raw"

    @property
    def digest(self) -> str:
        return sha256(self.data).hexdigest()


@dataclass(slots=True, frozen=True)
class ProtectedSecretMaterial:
    artifact_name: str
    value: str
    secret_kind: str = "protected_material"
    purpose: str = "task.protected_material"
    display_label: str | None = None
    content_type: str = "text/plain"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return sha256(self.value.encode("utf-8")).hexdigest()


@dataclass(slots=True, frozen=True)
class RunnerRequest:
    tool: str
    targets: list[str]
    params: dict[str, Any] = field(default_factory=dict)
    scope_allowlist: dict[str, Any] = field(default_factory=dict)
    initiated_by: str = "system"


@dataclass(slots=True, frozen=True)
class RunnerExecution:
    tool: str
    exit_code: int
    stdout: str
    stderr: str
    metadata: dict[str, Any] = field(default_factory=dict)
    artifacts: list[EvidenceArtifact] = field(default_factory=list)
    protected_outputs: list[ProtectedSecretMaterial] = field(default_factory=list)
