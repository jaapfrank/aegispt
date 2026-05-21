"""Specialist agents — narrow, single-purpose roles dispatched by the
:class:`api.app.agents.coordinator.MetaCoordinator`.

Each specialist module exposes a single ``run(...)`` entrypoint and
declares its tool ACL via the central
:func:`api.app.agents.coordinator.SpecialistACL.for_role` lookup.
Specialists are intentionally thin in this slice — they compose existing
backlog primitives (410 episodic memory, 413 validator, 414 exploit
developer) rather than introducing new logic.
"""

__all__: list[str] = []
