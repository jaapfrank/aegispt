from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    app: str
    environment: str
    detail: str
    runtime_state: str = "healthy"
    checked_at: str | None = None
    diagnostics: list[str] = Field(default_factory=list)
