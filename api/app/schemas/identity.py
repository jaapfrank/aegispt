from __future__ import annotations

from pydantic import BaseModel, Field


class IdentityPermissionRead(BaseModel):
    permission_id: str
    name: str
    description: str | None = None


class IdentityRoleRead(BaseModel):
    role_id: str
    name: str
    permissions: list[str] = Field(default_factory=list)


class IdentitySubjectRead(BaseModel):
    subject_id: str
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    attributes: dict[str, str] = Field(default_factory=dict)


class AuthContextRead(BaseModel):
    subject_id: str | None = None
    active_roles: list[str] = Field(default_factory=list)
    granted_permissions: list[str] = Field(default_factory=list)
    source_system: str | None = None
    notes: list[str] = Field(default_factory=list)
