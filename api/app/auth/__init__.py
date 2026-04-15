from fastapi import Header


def get_current_actor(x_actor: str | None = Header(default=None)) -> str:
    return x_actor or "local-dev"
