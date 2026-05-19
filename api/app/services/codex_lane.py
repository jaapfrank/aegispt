from __future__ import annotations

from api.app.models import CapabilityPack
from api.app.schemas.codex import (
    CodexBuildArtifactRead,
    CodexBuildContextRead,
    CodexOperatorVisibilityRead,
    CodexRepoConventionRead,
    CodexReviewBundleRead,
    CodexValidationHookRead,
)
from api.app.schemas.packs import (
    CapabilityPackApprovalRead,
    CapabilityPackArtifactRead,
    CapabilityPackDeploymentRead,
    CapabilityPackRead,
    CapabilityPackValidationRead,
)
from api.app.services.packs import latest_validation_for_pack, validation_checks_for_artifact_type


def _branch_slug(pack: CapabilityPack) -> str:
    short_id = str(pack.id).split("-", maxsplit=1)[0]
    return f"codex/pack-{short_id}-{pack.version.lower()}"


def _workspace_root(pack: CapabilityPack) -> str:
    safe_name = pack.name.strip().lower().replace(" ", "-")
    return f"codex-workspaces/{safe_name}-{pack.version}"


def _artifact_specific_validation_hooks(
    pack: CapabilityPack,
    *,
    sorted_artifacts: list,
) -> list[CodexValidationHookRead]:
    hooks: list[CodexValidationHookRead] = []
    workspace_root = f"./{_workspace_root(pack)}"

    artifact_specs = [
        (
            "playwright_flow",
            "artifact.playwright_flow.validate",
            "Validate exported Playwright flows through the existing pack validation lane.",
        ),
        (
            "zap_job",
            "artifact.zap_job.validate",
            "Validate exported ZAP jobs through the existing pack validation lane.",
        ),
    ]

    for artifact_type, hook_name, description in artifact_specs:
        matching_artifacts = [artifact for artifact in sorted_artifacts if artifact.artifact_type == artifact_type]
        if not matching_artifacts:
            continue
        hooks.append(
            CodexValidationHookRead(
                name=hook_name,
                method="POST",
                path=f"/api/v1/packs/{pack.id}/validate",
                description=description,
                artifact_types=[artifact_type],
                expected_checks=validation_checks_for_artifact_type(artifact_type),
                workspace_files=[
                    f"{workspace_root}/artifacts/{artifact.logical_name}"
                    for artifact in matching_artifacts
                ]
                + [f"{workspace_root}/validation-result.json"],
            )
        )

    return hooks


def build_codex_context(pack: CapabilityPack) -> CodexBuildContextRead:
    latest_validation = latest_validation_for_pack(pack)
    sorted_artifacts = sorted(pack.artifacts, key=lambda item: (item.artifact_type, item.logical_name))
    artifact_specific_hooks = _artifact_specific_validation_hooks(pack, sorted_artifacts=sorted_artifacts)

    return CodexBuildContextRead(
        pack_id=pack.id,
        engagement_id=pack.engagement_id,
        pack_name=pack.name,
        pack_version=pack.version,
        pack_status=pack.status,
        generation_mode=pack.generation_mode,
        relevance_decision_id=pack.relevance_decision_id,
        source_inventory_snapshot_id=pack.source_inventory_snapshot_id,
        source_threat_intel_refs=list(pack.source_threat_intel_refs_json),
        methodology_tags=list(pack.methodology_tags),
        generation_reason=pack.manifest_json.get("generation_reason") if isinstance(pack.manifest_json, dict) else None,
        active_runtime_mutation_allowed=False,
        latest_validation_status=latest_validation.status if latest_validation is not None else None,
        runtime_guardrails=[
            "Use Codex only after inventory and relevance analysis complete.",
            "Keep all refinement inside the supervised build lane.",
            "Do not mutate active assessment runtime behavior or installed runtime tooling.",
            "Preserve existing methodology tags, provenance, and evidence references.",
            "Require validation, approval, and deployment before any runtime binding.",
        ],
        repo_conventions=CodexRepoConventionRead(
            suggested_branch_name=_branch_slug(pack),
            workspace_root=_workspace_root(pack),
            artifact_directory="artifacts/",
            notes_file="operator-notes.md",
            change_summary_file="codex-change-summary.md",
            review_bundle_file="codex-review-bundle.json",
            export_command=f"bash scripts/export_codex_pack_workspace.sh <base_url> {pack.id} ./{_workspace_root(pack)}",
            validation_command=f"bash scripts/validate_codex_pack.sh <base_url> {pack.id}",
            rules=[
                "Treat Prompt 1 and Prompt 2 methodology and adaptive pack fields as authoritative.",
                "Edit exported pack artifacts and review notes, not the active runtime path.",
                "Keep generated changes reviewable, versioned, and tied to the pack id/version.",
                "Stage validated Codex output through the controlled reimport API as a child pack; never edit deployed runtime packs in place.",
                "Record operator notes before approval and deployment.",
                "Use the existing validate, approve, and deploy hooks instead of side-loading artifacts into runtime.",
            ],
        ),
        validation_hooks=[
            CodexValidationHookRead(
                name="pack.validate",
                method="POST",
                path=f"/api/v1/packs/{pack.id}/validate",
                description="Run the existing validation lane against the current pack artifacts.",
                blocking=True,
            ),
            CodexValidationHookRead(
                name="pack.codex_reimport_stage",
                method="POST",
                path=f"/api/v1/packs/{pack.id}/codex-reimport",
                description=(
                    "Stage validated Codex workspace artifacts as a generated child pack; "
                    "approval, deployment, and runtime binding still require the existing pack lifecycle."
                ),
                blocking=True,
            ),
            CodexValidationHookRead(
                name="pack.approve",
                method="POST",
                path=f"/api/v1/packs/{pack.id}/approve",
                description="Operator approval after a successful validation result.",
                blocking=True,
            ),
            CodexValidationHookRead(
                name="pack.deploy",
                method="POST",
                path=f"/api/v1/packs/{pack.id}/deploy",
                description="Explicit promotion into deployment-ready runtime binding.",
                blocking=True,
            ),
            CodexValidationHookRead(
                name="pack.artifacts",
                method="GET",
                path=f"/api/v1/packs/{pack.id}/artifacts",
                description="Retrieve the current artifact set for review or workspace export.",
            ),
        ]
        + artifact_specific_hooks,
        operator_visibility=CodexOperatorVisibilityRead(
            required_badges=[
                "Pack status",
                "Latest validation status",
                "Generation mode",
                "Runtime mutation blocked",
            ],
            required_fields=[
                "Pack id and version",
                "Inventory snapshot source",
                "Relevance decision id",
                "Threat intel references",
                "Methodology tags",
                "Generated-by and approval trail",
            ],
            review_sections=[
                "Pack overview",
                "Artifact diff or content review",
                "Validation blockers",
                "Approval readiness",
                "Deployment target and binding status",
            ],
            finding_provenance_fields=[
                "finding_origin",
                "source_pack_id",
                "source_pack_version",
                "source_pack_artifact_id",
                "source_inventory_snapshot_id",
                "source_relevance_decision_id",
            ],
        ),
        artifacts=[
            CodexBuildArtifactRead(
                artifact_id=artifact.id,
                artifact_type=artifact.artifact_type,
                logical_name=artifact.logical_name,
                status=artifact.status,
                checksum_sha256=artifact.checksum_sha256,
                methodology_tags=list(artifact.methodology_tags),
                provenance_json=dict(artifact.provenance_json),
                validation_checks=validation_checks_for_artifact_type(artifact.artifact_type),
                has_content_text=artifact.content_text is not None,
                has_content_json=artifact.content_json is not None,
            )
            for artifact in sorted_artifacts
        ],
    )


def build_codex_review_bundle(pack: CapabilityPack) -> CodexReviewBundleRead:
    return CodexReviewBundleRead(
        context=build_codex_context(pack),
        pack=CapabilityPackRead.model_validate(pack),
        artifacts=[
            CapabilityPackArtifactRead.model_validate(artifact)
            for artifact in sorted(pack.artifacts, key=lambda item: (item.artifact_type, item.logical_name))
        ],
        validations=[
            CapabilityPackValidationRead.model_validate(validation)
            for validation in sorted(pack.validation_results, key=lambda item: (item.created_at, item.id.hex))
        ],
        approvals=[
            CapabilityPackApprovalRead.model_validate(approval)
            for approval in sorted(pack.approvals, key=lambda item: (item.created_at, item.id.hex))
        ],
        deployments=[
            CapabilityPackDeploymentRead.model_validate(deployment)
            for deployment in sorted(pack.deployments, key=lambda item: (item.created_at, item.id.hex))
        ],
    )
