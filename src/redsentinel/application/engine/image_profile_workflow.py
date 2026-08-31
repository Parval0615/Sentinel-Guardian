from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable, Iterable
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from redsentinel.application.attack_profile import (
    build_attack_profile,
    image_profile_sha256,
)
from redsentinel.application.contracts import AgentRegistration
from redsentinel.application.engine.dynamic_profile_probe import (
    DynamicProbeRisk,
    DynamicProfileProbe,
    synchronize_profile_derivations,
)
from redsentinel.application.engine.image_profile_redaction import (
    safe_image_profile_error,
    sanitize_image_profile_payload,
)
from redsentinel.application.engine.storage import ProductStorage, safe_component
from redsentinel.application.image_profile_contracts import (
    AttackProfileNotApplicable,
    ANALYSIS_STAGE_ORDER,
    AgentDirectoryDescriptor,
    AnalysisError,
    AnalysisStageName,
    AnalysisStageState,
    CoverageStatistic,
    ImageAgentProfile,
    ImageAnalysisStatus,
    ImageIdentity,
    ProfileCompleteness,
    dynamic_required_claim_ids,
    profile_configuration_digest,
    profile_version_digest,
)
from redsentinel.core.image_profile_graph import AnalysisLimitation, ProfileEdge
from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence
from redsentinel.profiling.dataflow import DataflowAnalysisResult, analyze_dataflow
from redsentinel.profiling.frameworks import FrameworkAnalysis, analyze_frameworks
from redsentinel.profiling.image import (
    FileRecord,
    LayerRecord,
    ParsedImageArtifact,
    SanitizedImageConfig,
    parse_image_artifact,
)
from redsentinel.profiling.semantic import GraphFragment as SemanticGraphFragment
from redsentinel.profiling.semantic import GraphNode, GraphRelation, SemanticEnricher
from redsentinel.profiling.static_facts import StaticFactIndex, extract_static_facts


_NON_FATAL_STAGES = {"semantic_enrich", "dynamic_verify"}
_INFORMATIONAL_COMPLETENESS_LIMITATIONS = {
    "dataflow_unresolved",
    "dependency_source_omitted",
    "dynamic_only_edge",
    "dynamic_only_node",
    "framework_adapter_shallow",
    "framework_node_type_conflict",
    "runtime_source_omitted",
    "semantic_enrichment_skipped",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest_suffix(digest: str) -> str:
    return digest.removeprefix("sha256:")[:16]


def _profile_version_suffix(image_digest: str, configuration_digest: str) -> str:
    return _digest_suffix(profile_version_digest(image_digest, configuration_digest))


class ImageProfileWorkflowError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class ImageProfileCreateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "image-profile-create-response-v0.1"
    analysis: ImageAnalysisStatus
    cached: bool = False


class ImageProfileRecoveryTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    agent_id: str
    analysis_id: str


class ImageProfileWorkflowService:
    """Runs and persists the evidence-bound image profiling state machine."""

    def __init__(
        self,
        storage: ProductStorage,
        *,
        asset_root_provider: Callable[[], Path | None] | None = None,
        semantic_enricher: SemanticEnricher | None = None,
        dynamic_probe_factory: Callable[[Path], DynamicProfileProbe] = DynamicProfileProbe,
        image_ref_resolver: Callable[[dict[str, Any]], str | None] | None = None,
        agent_writer: Callable[[AgentRegistration], AgentRegistration] | None = None,
    ) -> None:
        self.storage = storage
        self._asset_root_provider = asset_root_provider or _asset_root_from_environment
        self._semantic_enricher = semantic_enricher or SemanticEnricher(None)
        self._dynamic_probe_factory = dynamic_probe_factory
        self._image_ref_resolver = image_ref_resolver or (lambda _: None)
        self._agent_writer = agent_writer

    def create(self, *, tenant_id: str, agent_id: str) -> ImageProfileCreateResult:
        record = self._asset_record(tenant_id, agent_id)
        digest = str(record["image_digest"])
        configuration_digest = str(record["configuration_digest"])
        suffix = _profile_version_suffix(digest, configuration_digest)
        analysis_id = f"analysis:{agent_id}:{suffix}"
        with self.storage.image_profile_lease(tenant_id, agent_id, suffix) as acquired:
            if not acquired:
                status = self.get_status(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    analysis_id=analysis_id,
                )
                self._write_latest(tenant_id, agent_id, suffix, record, status)
                return ImageProfileCreateResult(analysis=status, cached=True)
            path = self.storage.image_profile_status_path(tenant_id, agent_id, suffix)
            if path.is_file():
                status = ImageAnalysisStatus.model_validate(self.storage.read_json(path))
                if (
                    status.analysis_id != analysis_id
                    or status.image_digest != digest
                    or status.configuration_digest != configuration_digest
                ):
                    raise ImageProfileWorkflowError(
                        "profile_identity_mismatch",
                        "The cached profile status does not match its image and configuration.",
                        status_code=409,
                    )
                self._write_latest(tenant_id, agent_id, suffix, record, status)
                return ImageProfileCreateResult(
                    analysis=status,
                    cached=status.status in {"completed", "partial"},
                )
            analysis = ImageAnalysisStatus(
                analysis_id=analysis_id,
                agent_id=agent_id,
                image_digest=digest,
                configuration_digest=configuration_digest,
            )
            self._write_status(tenant_id, agent_id, suffix, analysis)
            self._write_latest(tenant_id, agent_id, suffix, record, analysis)
            return ImageProfileCreateResult(analysis=analysis)

    def run(self, *, tenant_id: str, agent_id: str, analysis_id: str | None = None) -> ImageAnalysisStatus:
        status = self.get_status(tenant_id=tenant_id, agent_id=agent_id, analysis_id=analysis_id)
        record = self._asset_record(tenant_id, agent_id)
        if (
            record["image_digest"] != status.image_digest
            or record["configuration_digest"] != status.configuration_digest
        ):
            raise ImageProfileWorkflowError(
                "profile_identity_changed",
                "The analysis is bound to an older image or profile configuration.",
                status_code=409,
            )
        if status.status == "failed":
            raise ImageProfileWorkflowError(
                "profile_retry_required",
                "The failed image profile must be reset through the retry operation.",
                status_code=409,
            )
        suffix = _profile_version_suffix(
            status.image_digest,
            status.configuration_digest,
        )
        with self.storage.image_profile_lease(tenant_id, agent_id, suffix) as acquired:
            if not acquired:
                return self.get_status(tenant_id=tenant_id, agent_id=agent_id, analysis_id=analysis_id)
            status = self.get_status(tenant_id=tenant_id, agent_id=agent_id, analysis_id=analysis_id)
            if status.status in {"completed", "partial"}:
                return status
            status = self._normalize_interrupted(status)
            context: dict[str, Any] = {}
            for stage in ANALYSIS_STAGE_ORDER:
                state = next(item for item in status.stages if item.stage == stage)
                checkpoint = self._read_checkpoint(
                    tenant_id,
                    agent_id,
                    suffix,
                    stage,
                    status,
                )
                if checkpoint is not None and state.status != "failed":
                    context[stage] = checkpoint["output"]
                    if state.status not in {"completed", "skipped"}:
                        path = self.storage.image_profile_checkpoint_path(tenant_id, agent_id, suffix, stage)
                        status = self._mark_finished(
                            status,
                            stage,
                            path.relative_to(self.storage.root).as_posix(),
                            skipped=checkpoint.get("status") == "skipped",
                        )
                        if stage == "finalize" and checkpoint["output"].get("status") == "partial":
                            status = status.model_copy(update={"status": "partial"})
                        self._write_status(tenant_id, agent_id, suffix, status)
                    continue
                status = self._mark_running(status, stage)
                self._write_status(tenant_id, agent_id, suffix, status)
                try:
                    output, skipped = self._execute_stage(
                        stage,
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        suffix=suffix,
                        status=status,
                        context=context,
                    )
                    checkpoint_ref = self._write_checkpoint(
                        tenant_id,
                        agent_id,
                        suffix,
                        stage,
                        status.analysis_id,
                        status.image_digest,
                        status.configuration_digest,
                        output,
                        skipped=skipped,
                    )
                    context[stage] = output
                    status = self._mark_finished(status, stage, checkpoint_ref, skipped=skipped)
                    if stage == "finalize" and output.get("status") == "partial":
                        status = status.model_copy(update={"status": "partial"})
                except Exception as exc:
                    status = self._mark_failed(status, stage, exc)
                    if stage not in _NON_FATAL_STAGES:
                        self._sync_agent_failure(tenant_id, agent_id, status)
                        break
                    context[stage] = {"error": _safe_error(exc)}
                if stage != "finalize":
                    self._write_status(tenant_id, agent_id, suffix, status)
        self._write_status(tenant_id, agent_id, suffix, status)
        return status

    def retry(self, *, tenant_id: str, agent_id: str, analysis_id: str) -> ImageAnalysisStatus:
        status = self.get_status(tenant_id=tenant_id, agent_id=agent_id, analysis_id=analysis_id)
        record = self._asset_record(tenant_id, agent_id)
        if (
            record["image_digest"] != status.image_digest
            or record["configuration_digest"] != status.configuration_digest
        ):
            raise ImageProfileWorkflowError(
                "profile_identity_changed",
                "The failed analysis is bound to an older image or profile configuration; create a new profile version.",
                status_code=409,
            )
        failed = [item.stage for item in status.stages if item.status == "failed"]
        if not failed:
            raise ImageProfileWorkflowError(
                "profile_not_retryable",
                "The image profile has no failed stage to retry.",
                status_code=409,
            )
        first = min(ANALYSIS_STAGE_ORDER.index(stage) for stage in failed)
        stages: list[AnalysisStageState] = []
        for index, state in enumerate(status.stages):
            if index < first and state.status in {"completed", "skipped"}:
                stages.append(state)
            elif index == first:
                stages.append(
                    AnalysisStageState(
                        stage=state.stage,
                        status="running",
                        started_at=_now(),
                    )
                )
            else:
                stages.append(AnalysisStageState(stage=state.stage))
        reset = status.model_copy(
            update={
                "status": "running",
                "stages": stages,
                "errors": [],
            }
        )
        suffix = _profile_version_suffix(
            status.image_digest,
            status.configuration_digest,
        )
        self._write_status(tenant_id, agent_id, suffix, reset)
        for stage in ANALYSIS_STAGE_ORDER[first:]:
            self.storage.image_profile_checkpoint_path(tenant_id, agent_id, suffix, stage).unlink(missing_ok=True)
        return reset

    def list_recovery_tasks(self) -> list[ImageProfileRecoveryTask]:
        tasks: list[ImageProfileRecoveryTask] = []
        for latest_path in sorted(self.storage.root.glob("*/image_profiles/*/latest.json")):
            try:
                latest = self.storage.read_json(latest_path)
                tenant_id = latest_path.parents[2].name
                agent_id = latest_path.parent.name
                suffix = str(latest["digest_suffix"])
                status = ImageAnalysisStatus.model_validate(
                    self.storage.read_json(
                        self.storage.image_profile_status_path(
                            tenant_id,
                            agent_id,
                            suffix,
                        )
                    )
                )
                if status.status not in {"queued", "running"}:
                    continue
                normalized = self._normalize_interrupted(status)
                self._write_status(tenant_id, agent_id, suffix, normalized)
                tasks.append(
                    ImageProfileRecoveryTask(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        analysis_id=normalized.analysis_id,
                    )
                )
            except (KeyError, OSError, ValueError, json.JSONDecodeError):
                continue
        return tasks

    def get_status(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        analysis_id: str | None = None,
    ) -> ImageAnalysisStatus:
        if analysis_id is None:
            latest = self._latest(tenant_id, agent_id)
            paths = [self.storage.image_profile_status_path(tenant_id, agent_id, latest["digest_suffix"])]
        else:
            profile_root = self.storage.tenant_dir(tenant_id) / "image_profiles" / safe_component(agent_id, "agent_id")
            paths = sorted(profile_root.glob("*/status.json"))
        for path in paths:
            if not path.is_file():
                continue
            payload = self.storage.read_json(path)
            sanitized = sanitize_image_profile_payload(payload)
            if sanitized != payload:
                self.storage.write_json(path, sanitized)
            status = ImageAnalysisStatus.model_validate(sanitized)
            if analysis_id is None or status.analysis_id == analysis_id:
                return status
        raise ImageProfileWorkflowError(
            "profile_analysis_not_found",
            "Image profile analysis not found.",
            status_code=404,
        )

    def get_latest_profile(self, *, tenant_id: str, agent_id: str) -> ImageAgentProfile:
        latest = self._latest(tenant_id, agent_id)
        return self.get_profile(tenant_id=tenant_id, agent_id=agent_id, profile_id=latest["profile_id"])

    def get_profile(self, *, tenant_id: str, agent_id: str, profile_id: str) -> ImageAgentProfile:
        try:
            safe_component(profile_id, "profile_id")
        except ValueError as exc:
            raise ImageProfileWorkflowError(
                "image_profile_not_found",
                "Published image profile not found.",
                status_code=404,
            ) from exc
        latest = self._latest(tenant_id, agent_id)
        candidates = [latest]
        version_root = self.storage.tenant_dir(tenant_id) / "image_profiles" / safe_component(agent_id, "agent_id")
        for path in version_root.glob("*/status.json"):
            suffix = path.parent.name
            candidates.append({"digest_suffix": suffix, "profile_id": f"image-profile-{agent_id}-{suffix}"})
        match = next((item for item in candidates if item.get("profile_id") == profile_id), None)
        if match is None:
            raise ImageProfileWorkflowError(
                "image_profile_not_found", "Published image profile not found.", status_code=404
            )
        path = self.storage.image_profile_artifact_path(
            tenant_id, agent_id, str(match["digest_suffix"]), "published-profile"
        )
        if not path.is_file():
            raise ImageProfileWorkflowError(
                "image_profile_not_found", "Published image profile not found.", status_code=404
            )
        payload = self.storage.read_json(path)
        sanitized = sanitize_image_profile_payload(payload)
        if sanitized != payload:
            self.storage.write_json(path, sanitized)
        return ImageAgentProfile.model_validate(sanitized)

    def _execute_stage(
        self,
        stage: AnalysisStageName,
        *,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        status: ImageAnalysisStatus,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        if stage == "inventory":
            return self._inventory(tenant_id, agent_id, status), False
        if stage == "unpack":
            return self._unpack(tenant_id, agent_id, suffix, context["inventory"]), False
        if stage == "static_extract":
            parsed = _parsed_image(context["unpack"])
            facts = extract_static_facts(parsed)
            payload = facts.model_dump(mode="json")
            self._write_artifact(tenant_id, agent_id, suffix, "static-facts", payload)
            return payload, False
        if stage == "framework_detect":
            facts = StaticFactIndex.model_validate(context["static_extract"])
            analysis = analyze_frameworks(facts)
            payload = analysis.model_dump(mode="json")
            self._write_artifact(tenant_id, agent_id, suffix, "framework-analysis", payload)
            return payload, False
        if stage == "graph_reconstruct":
            facts = StaticFactIndex.model_validate(context["static_extract"])
            frameworks = FrameworkAnalysis.model_validate(context["framework_detect"])
            dataflow = analyze_dataflow(facts, _parsed_image(context["unpack"]).rootfs_path)
            payload = {
                "schema_version": "graph-reconstruction-v0.1",
                "framework": frameworks.model_dump(mode="json"),
                "dataflow": dataflow.model_dump(mode="json"),
            }
            self._write_artifact(tenant_id, agent_id, suffix, "graph-fragments", payload)
            return payload, False
        if stage == "semantic_enrich":
            facts = StaticFactIndex.model_validate(context["static_extract"])
            graph = _semantic_graph(context["graph_reconstruct"])
            result = self._semantic_enricher.enrich(facts, graph)
            payload = result.model_dump(mode="json")
            self._write_artifact(tenant_id, agent_id, suffix, "semantic-evidence", payload)
            return payload, result.outcome == "skipped"
        if stage == "dynamic_verify":
            draft = self._build_profile(tenant_id, agent_id, status, context, final=False)
            runtime = context["inventory"]["descriptor"].get("runtime", {})
            risk = DynamicProbeRisk(
                requires_privileged=bool(runtime.get("requires_privileged")),
                required_host_mounts=tuple(runtime.get("required_host_mounts", [])),
            )
            platform = f"{draft.image.os}/{draft.image.architecture}"
            if platform not in {"linux/amd64", "linux/arm64"}:
                raise ImageProfileWorkflowError(
                    "unsupported_platform",
                    f"dynamic probe does not support platform {platform}",
                )
            if risk.requires_privileged:
                raise ImageProfileWorkflowError(
                    "privileged_runtime_required",
                    "image requires privileged execution; dynamic verification was refused",
                )
            if risk.required_host_mounts:
                raise ImageProfileWorkflowError(
                    "dangerous_mount_required",
                    "image requires host mounts outside the controlled probe artifact directory",
                )
            image_ref = self._image_ref_resolver(context["inventory"])
            if not image_ref:
                self._write_artifact(
                    tenant_id,
                    agent_id,
                    suffix,
                    "dynamic-events",
                    {"events": [], "status": "skipped", "reason": "verified_runtime_image_unavailable"},
                )
                raise ImageProfileWorkflowError(
                    "dynamic_image_unavailable",
                    "The offline image artifact has no verified local runtime image reference.",
                )
            probe = self._dynamic_probe_factory(self.storage.image_profile_dir(tenant_id, agent_id, suffix) / "dynamic")
            result = probe.run(
                draft,
                image_ref=image_ref,
                risk=risk,
                target_module=runtime.get("probe_module"),
            )
            events = [item.model_dump(mode="json") for item in result.events]
            self._write_artifact(tenant_id, agent_id, suffix, "dynamic-events", {"events": events})
            if not result.succeeded:
                raise ImageProfileWorkflowError(
                    result.profile.analysis.errors[-1].code,
                    result.error or "Dynamic verification failed.",
                )
            return {
                "profile": result.profile.model_dump(mode="json"),
                "events": events,
                "command": list(result.command),
            }, False
        if stage == "finalize":
            profile = self._build_profile(tenant_id, agent_id, status, context, final=True)
            self._publish(tenant_id, agent_id, suffix, profile)
            return {"profile_id": profile.profile_id, "status": profile.analysis.status}, False
        raise RuntimeError(f"unsupported image profile stage: {stage}")

    def _inventory(self, tenant_id: str, agent_id: str, status: ImageAnalysisStatus) -> dict[str, Any]:
        record = self._asset_record(tenant_id, agent_id)
        if (
            record["image_digest"] != status.image_digest
            or record["configuration_digest"] != status.configuration_digest
        ):
            raise ImageProfileWorkflowError(
                "profile_identity_changed",
                "The indexed image or profile configuration changed; create a new profile version.",
                status_code=409,
            )
        if record.get("asset_source") == "managed_upload":
            root = self.storage.managed_agent_assets_dir(tenant_id)
            directory_ref = record.get("asset_directory_ref")
            if not isinstance(directory_ref, str) or not directory_ref:
                raise ImageProfileWorkflowError(
                    "asset_path_invalid",
                    "The managed Agent asset has no storage reference.",
                )
            directory = (root / directory_ref).resolve()
        else:
            root = self._asset_root_provider()
            if root is None:
                raise ImageProfileWorkflowError(
                    "agent_root_unavailable",
                    "The Agent asset directory is not configured.",
                )
            directory = (root / str(record["directory_name"])).resolve()
        root = root.resolve()
        if not directory.is_relative_to(root):
            raise ImageProfileWorkflowError(
                "asset_path_invalid", "The Agent asset directory escapes the configured root."
            )
        descriptor_path = directory / "agent.json"
        descriptor_model = AgentDirectoryDescriptor.model_validate_json(descriptor_path.read_text(encoding="utf-8"))
        descriptor = descriptor_model.model_dump(mode="json")
        if profile_configuration_digest(descriptor_model) != status.configuration_digest:
            raise ImageProfileWorkflowError(
                "profile_configuration_changed",
                "The Agent profile configuration changed after indexing.",
                status_code=409,
            )
        image_path = (directory / descriptor["image"]["path"]).resolve(strict=True)
        if not image_path.is_relative_to(directory):
            raise ImageProfileWorkflowError("asset_path_invalid", "The image artifact escapes its Agent directory.")
        return {
            "record": record,
            "descriptor": descriptor,
            "image_path": str(image_path),
        }

    def _unpack(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        output = self.storage.image_profile_unpack_root(tenant_id, agent_id, suffix)
        if output.exists():
            _remove_read_only_tree(output)
        descriptor = inventory["descriptor"]
        parsed = parse_image_artifact(
            inventory["image_path"],
            output,
            image_type=descriptor["image"]["type"],
            platform=descriptor.get("platform"),
        )
        authoritative_digest = inventory["record"]["image_digest"]
        if parsed.image_digest != authoritative_digest:
            parsed = replace(parsed, image_digest=authoritative_digest)
        return _serialize_parsed_image(parsed)

    def _build_profile(
        self,
        tenant_id: str,
        agent_id: str,
        status: ImageAnalysisStatus,
        context: dict[str, Any],
        *,
        final: bool,
    ) -> ImageAgentProfile:
        parsed = _parsed_image(context["unpack"])
        facts = StaticFactIndex.model_validate(context["static_extract"])
        frameworks = FrameworkAnalysis.model_validate(context["framework_detect"])
        graph_payload = context["graph_reconstruct"]
        dataflow = DataflowAnalysisResult.model_validate(graph_payload["dataflow"])
        nodes = _merge_claims([*frameworks.nodes, *dataflow.nodes], "node_id")
        edges = _merge_claims([*frameworks.edges, *dataflow.edges], "edge_id")
        semantic = context.get("semantic_enrich", {})
        semantic_graph = semantic.get("graph") if isinstance(semantic, dict) else None
        if isinstance(semantic_graph, dict):
            existing_edges = {item.edge_id for item in edges}
            for relation in SemanticGraphFragment.model_validate(semantic_graph).relations:
                if relation.relation_id not in existing_edges:
                    edges.append(
                        ProfileEdge(
                            edge_id=relation.relation_id,
                            edge_type=relation.relation_type,
                            source_node_id=relation.source_node_id,
                            target_node_id=relation.target_node_id,
                            evidence_refs=list(relation.evidence_refs),
                            confidence=0.5,
                            verification_status=relation.verification_status,
                        )
                    )
        image_evidence = _image_evidence(status.image_digest, parsed)
        evidence = _dedupe_evidence(
            [
                image_evidence,
                *facts.all_evidence(),
                *frameworks.evidence,
                *dataflow.evidence,
            ]
        )
        limitations = _dedupe_limitations(
            [
                *frameworks.limitations,
                *dataflow.limitations,
                *(
                    [
                        AnalysisLimitation(
                            code="semantic_enrichment_skipped",
                            message=str(semantic.get("error") or "Semantic enrichment was not executed."),
                        )
                    ]
                    if semantic.get("outcome") in {"skipped", "fallback", "rejected"}
                    else []
                ),
            ]
        )
        analysis = status
        if final:
            analysis = self._final_analysis(status)
            for error in analysis.errors:
                limitations.append(AnalysisLimitation(code=error.code, message=error.message))
            limitations = _dedupe_limitations(limitations)
        image = _image_identity(status.image_digest, parsed, image_evidence.evidence_id)
        profile = ImageAgentProfile(
            profile_id=(
                f"image-profile-{agent_id}-{_profile_version_suffix(status.image_digest, status.configuration_digest)}"
            ),
            tenant_id=tenant_id,
            agent_id=agent_id,
            generated_at=_now(),
            image=image,
            analysis=analysis,
            frameworks=list(frameworks.frameworks),
            nodes=nodes,
            edges=edges,
            capabilities=list(dataflow.capabilities),
            permissions=list(dataflow.permissions),
            controls=list(dataflow.controls),
            evidence=evidence,
            risk_paths=list(dataflow.risk_paths),
            limitations=limitations,
        )
        dynamic = context.get("dynamic_verify")
        if isinstance(dynamic, dict) and isinstance(dynamic.get("profile"), dict):
            dynamic_profile = ImageAgentProfile.model_validate(dynamic["profile"])
            payload = profile.model_dump(mode="json")
            payload.update(
                {
                    "nodes": [item.model_dump(mode="json") for item in dynamic_profile.nodes],
                    "edges": [item.model_dump(mode="json") for item in dynamic_profile.edges],
                    "capabilities": [item.model_dump(mode="json") for item in dynamic_profile.capabilities],
                    "permissions": [item.model_dump(mode="json") for item in dynamic_profile.permissions],
                    "controls": [item.model_dump(mode="json") for item in dynamic_profile.controls],
                    "evidence": [item.model_dump(mode="json") for item in dynamic_profile.evidence],
                    "risk_paths": [item.model_dump(mode="json") for item in dynamic_profile.risk_paths],
                    "limitations": [item.model_dump(mode="json") for item in dynamic_profile.limitations],
                    "analysis": analysis.model_dump(mode="json"),
                }
            )
            profile = synchronize_profile_derivations(ImageAgentProfile.model_validate(payload))
        if final:
            completeness = _profile_completeness(
                facts=facts,
                expected_frameworks=context["inventory"]["descriptor"].get("expected_frameworks", []),
                static_nodes=nodes,
                static_edges=edges,
                static_controls=list(dataflow.controls),
                profile=profile,
            )
            analysis = profile.analysis.model_copy(
                update={"status": ("completed" if completeness.conclusion == "complete" else "partial")}
            )
            profile = ImageAgentProfile.model_validate(
                {
                    **profile.model_dump(mode="json"),
                    "analysis": analysis.model_dump(mode="json"),
                    "completeness": completeness.model_dump(mode="json"),
                }
            )
        return profile

    def _publish(self, tenant_id: str, agent_id: str, suffix: str, profile: ImageAgentProfile) -> None:
        payload = profile.model_dump(mode="json")
        self._write_artifact(tenant_id, agent_id, suffix, "published-profile", payload)
        evidence_index = {
            "schema_version": "image-profile-evidence-index-v0.1",
            "profile_id": profile.profile_id,
            "image_digest": profile.image.digest,
            "configuration_digest": profile.analysis.configuration_digest,
            "evidence": [item.model_dump(mode="json") for item in profile.evidence],
        }
        self._write_artifact(tenant_id, agent_id, suffix, "evidence-index", evidence_index)
        self._write_artifact(tenant_id, agent_id, suffix, "attack-profile", _attack_handoff(profile))
        latest = self._latest(tenant_id, agent_id)
        latest["published_at"] = _now()
        latest["profile_status"] = profile.analysis.status
        self.storage.write_json(self.storage.image_profile_latest_path(tenant_id, agent_id), latest)
        self._sync_agent_profile(tenant_id, agent_id, profile)

    def _sync_agent_profile(
        self,
        tenant_id: str,
        agent_id: str,
        profile: ImageAgentProfile,
    ) -> None:
        path = self.storage.agent_path(tenant_id, agent_id)
        if not path.is_file():
            return
        agent = AgentRegistration.model_validate(self.storage.read_json(path))
        framework = ", ".join(item.name for item in profile.frameworks) or "unknown"
        detected_openmanus = any(
            "openmanus" in f"{item.framework_id} {item.name}".casefold()
            for item in profile.frameworks
        )
        data_boundary = {
            **agent.data_boundary,
            "image_digest": profile.image.digest,
            "profile_configuration_digest": profile.analysis.configuration_digest,
            "profile_id": profile.profile_id,
            "profile_sha256": image_profile_sha256(profile),
            "profile_status": profile.analysis.status,
        }
        updated = agent.model_copy(
            update={
                "framework": framework,
                "adapter_type": (
                    "openmanus"
                    if detected_openmanus
                    else agent.adapter_type
                ),
                "status": "ready",
                "data_boundary": data_boundary,
            }
        )
        self._write_agent(updated)
        record_path = self.storage.agent_asset_index_path(tenant_id, agent_id)
        if record_path.is_file():
            record = self.storage.read_json(record_path)
            record["status"] = f"profile_{profile.analysis.status}"
            self.storage.write_json(record_path, record)

    def _sync_agent_failure(
        self,
        tenant_id: str,
        agent_id: str,
        status: ImageAnalysisStatus,
    ) -> None:
        path = self.storage.agent_path(tenant_id, agent_id)
        if not path.is_file():
            return
        agent = AgentRegistration.model_validate(self.storage.read_json(path))
        updated = agent.model_copy(
            update={
                "status": "failed",
                "data_boundary": {
                    **agent.data_boundary,
                    "profile_status": status.status,
                    "profile_analysis_id": status.analysis_id,
                },
            }
        )
        self._write_agent(updated)

    def _write_agent(self, agent: AgentRegistration) -> None:
        if self._agent_writer is not None:
            self._agent_writer(agent)
            return
        self.storage.write_agent(
            agent.tenant_id,
            agent.agent_id,
            agent.model_dump(mode="json"),
        )

    def _asset_record(self, tenant_id: str, agent_id: str) -> dict[str, Any]:
        path = self.storage.agent_asset_index_path(tenant_id, agent_id)
        if not path.is_file():
            raise ImageProfileWorkflowError(
                "image_agent_not_indexed",
                "The Agent has no indexed image artifact.",
                status_code=404,
            )
        return self.storage.read_json(path)

    def _latest(self, tenant_id: str, agent_id: str) -> dict[str, Any]:
        path = self.storage.image_profile_latest_path(tenant_id, agent_id)
        if not path.is_file():
            raise ImageProfileWorkflowError("image_profile_not_found", "Image profile not found.", status_code=404)
        return self.storage.read_json(path)

    def _write_latest(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        record: dict[str, Any],
        status: ImageAnalysisStatus,
    ) -> None:
        self.storage.write_json(
            self.storage.image_profile_latest_path(tenant_id, agent_id),
            {
                "schema_version": "image-profile-latest-v0.1",
                "agent_id": agent_id,
                "image_digest": status.image_digest,
                "configuration_digest": status.configuration_digest,
                "profile_version_digest": record["profile_version_digest"],
                "digest_suffix": suffix,
                "analysis_id": status.analysis_id,
                "profile_id": record["profile_version_id"],
                "profile_status": status.status,
                "updated_at": _now(),
            },
        )

    def _write_status(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        status: ImageAnalysisStatus,
    ) -> None:
        self.storage.write_json(
            self.storage.image_profile_status_path(tenant_id, agent_id, suffix),
            status.model_dump(mode="json"),
        )
        self._sync_agent_analysis(tenant_id, agent_id, status)

    def _sync_agent_analysis(
        self,
        tenant_id: str,
        agent_id: str,
        status: ImageAnalysisStatus,
    ) -> None:
        path = self.storage.agent_path(tenant_id, agent_id)
        if not path.is_file():
            return
        agent = AgentRegistration.model_validate(self.storage.read_json(path))
        active_stage = next(
            (item.stage for item in status.stages if item.status in {"running", "failed"}),
            next(
                (item.stage for item in status.stages if item.status == "pending"),
                None,
            ),
        )
        agent_status = (
            "failed"
            if status.status == "failed"
            else "ready"
            if status.status in {"completed", "partial"}
            else "profiling"
        )
        updated = agent.model_copy(
            update={
                "status": agent_status,
                "data_boundary": {
                    **agent.data_boundary,
                    "profile_status": status.status,
                    "profile_analysis_id": status.analysis_id,
                    "profile_stage": active_stage,
                },
            }
        )
        self.storage.write_agent(
            updated.tenant_id,
            updated.agent_id,
            updated.model_dump(mode="json"),
        )
        record_path = self.storage.agent_asset_index_path(tenant_id, agent_id)
        if record_path.is_file():
            record = self.storage.read_json(record_path)
            record["status"] = f"profile_{status.status}"
            self.storage.write_json(record_path, record)

    def _write_checkpoint(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        stage: AnalysisStageName,
        analysis_id: str,
        image_digest: str,
        configuration_digest: str,
        output: dict[str, Any],
        *,
        skipped: bool,
    ) -> str:
        path = self.storage.image_profile_checkpoint_path(tenant_id, agent_id, suffix, stage)
        self.storage.write_json(
            path,
            {
                "schema_version": "image-profile-checkpoint-v0.1",
                "analysis_id": analysis_id,
                "image_digest": image_digest,
                "configuration_digest": configuration_digest,
                "stage": stage,
                "status": "skipped" if skipped else "completed",
                "completed_at": _now(),
                "output": output,
            },
        )
        return path.relative_to(self.storage.root).as_posix()

    def _read_checkpoint(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        stage: AnalysisStageName,
        status: ImageAnalysisStatus,
    ) -> dict[str, Any] | None:
        path = self.storage.image_profile_checkpoint_path(tenant_id, agent_id, suffix, stage)
        if not path.is_file():
            return None
        payload = self.storage.read_json(path)
        if (
            payload.get("analysis_id") != status.analysis_id
            or payload.get("image_digest") != status.image_digest
            or payload.get("configuration_digest") != status.configuration_digest
            or payload.get("stage") != stage
            or not isinstance(payload.get("output"), dict)
        ):
            return None
        if stage == "unpack":
            payload["output"] = self._validate_unpack_checkpoint(
                tenant_id,
                agent_id,
                suffix,
                payload["output"],
            )
        return payload

    def _validate_unpack_checkpoint(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        output: dict[str, Any],
    ) -> dict[str, Any]:
        rootfs_value = output.get("rootfs_path")
        if not isinstance(rootfs_value, str) or not rootfs_value:
            raise ImageProfileWorkflowError(
                "image_profile_checkpoint_tampered",
                "The unpack checkpoint contains an invalid rootfs path.",
            )
        try:
            unpack_root = self.storage.image_profile_unpack_root(
                tenant_id,
                agent_id,
                suffix,
            ).resolve()
            rootfs_path = Path(rootfs_value).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            raise ImageProfileWorkflowError(
                "image_profile_checkpoint_tampered",
                "The unpack checkpoint contains an invalid rootfs path.",
            ) from exc
        if rootfs_path == unpack_root or not rootfs_path.is_relative_to(unpack_root):
            raise ImageProfileWorkflowError(
                "image_profile_checkpoint_tampered",
                "The unpack checkpoint rootfs path escapes its analysis directory.",
            )
        return {**output, "rootfs_path": str(rootfs_path)}

    def _write_artifact(
        self,
        tenant_id: str,
        agent_id: str,
        suffix: str,
        name: str,
        payload: dict[str, Any],
    ) -> None:
        self.storage.write_json(
            self.storage.image_profile_artifact_path(tenant_id, agent_id, suffix, name),
            payload,
        )

    @staticmethod
    def _normalize_interrupted(status: ImageAnalysisStatus) -> ImageAnalysisStatus:
        stages = [AnalysisStageState(stage=item.stage) if item.status == "running" else item for item in status.stages]
        errors = [
            error
            for error in status.errors
            if next(item for item in stages if item.stage == error.stage).status == "failed"
        ]
        return status.model_copy(update={"status": "queued", "stages": stages, "errors": errors})

    @staticmethod
    def _mark_running(status: ImageAnalysisStatus, stage: AnalysisStageName) -> ImageAnalysisStatus:
        now = _now()
        stages = [
            AnalysisStageState(stage=item.stage, status="running", started_at=now) if item.stage == stage else item
            for item in status.stages
        ]
        return status.model_copy(update={"status": "running", "stages": stages})

    @staticmethod
    def _mark_finished(
        status: ImageAnalysisStatus,
        stage: AnalysisStageName,
        checkpoint_ref: str,
        *,
        skipped: bool,
    ) -> ImageAnalysisStatus:
        now = _now()
        stages = [
            AnalysisStageState(
                stage=item.stage,
                status="skipped" if skipped else "completed",
                started_at=item.started_at,
                completed_at=now,
                checkpoint_ref=checkpoint_ref,
            )
            if item.stage == stage
            else item
            for item in status.stages
        ]
        if stage == "finalize":
            overall = "partial" if any(item.status == "failed" for item in stages) else "completed"
        else:
            overall = "running"
            next_stage = ANALYSIS_STAGE_ORDER[ANALYSIS_STAGE_ORDER.index(stage) + 1]
            stages = [
                AnalysisStageState(stage=item.stage, status="running", started_at=now)
                if item.stage == next_stage
                else item
                for item in stages
            ]
        return status.model_copy(update={"status": overall, "stages": stages})

    @staticmethod
    def _mark_failed(
        status: ImageAnalysisStatus,
        stage: AnalysisStageName,
        exc: Exception,
    ) -> ImageAnalysisStatus:
        now = _now()
        code = exc.code if isinstance(exc, ImageProfileWorkflowError) else f"{stage}_failed"
        retryable = stage in _NON_FATAL_STAGES or isinstance(exc, (OSError, RuntimeError))
        error = AnalysisError(
            error_id=f"error:{stage}:{hashlib.sha256(f'{code}:{exc}'.encode()).hexdigest()[:12]}",
            stage=stage,
            code=code,
            message=_safe_error(exc),
            retryable=retryable,
        )
        stages = [
            AnalysisStageState(
                stage=item.stage,
                status="failed",
                started_at=item.started_at,
                completed_at=now,
            )
            if item.stage == stage
            else item
            for item in status.stages
        ]
        if stage in _NON_FATAL_STAGES:
            next_stage = ANALYSIS_STAGE_ORDER[ANALYSIS_STAGE_ORDER.index(stage) + 1]
            stages = [
                AnalysisStageState(stage=item.stage, status="running", started_at=now)
                if item.stage == next_stage
                else item
                for item in stages
            ]
            overall = "running"
        else:
            overall = "failed"
        errors = [item for item in status.errors if item.stage != stage]
        return status.model_copy(update={"status": overall, "stages": stages, "errors": [*errors, error]})

    @staticmethod
    def _final_analysis(status: ImageAnalysisStatus) -> ImageAnalysisStatus:
        now = _now()
        stages = [
            AnalysisStageState(
                stage=item.stage,
                status="completed",
                started_at=item.started_at,
                completed_at=now,
                checkpoint_ref=item.checkpoint_ref,
            )
            if item.stage == "finalize"
            else item
            for item in status.stages
        ]
        overall = "partial" if any(item.status == "failed" for item in stages) else "completed"
        return status.model_copy(update={"status": overall, "stages": stages})


def _asset_root_from_environment() -> Path | None:
    value = os.environ.get("RED_SENTINEL_AGENT_ROOT", "").strip()
    return Path(value).expanduser() if value else None


def _serialize_parsed_image(parsed: ParsedImageArtifact) -> dict[str, Any]:
    return {
        "image_type": parsed.image_type,
        "image_digest": parsed.image_digest,
        "config": asdict(parsed.config),
        "layers": [asdict(item) for item in parsed.layers],
        "files": [asdict(item) for item in parsed.files],
        "rootfs_path": str(parsed.rootfs_path),
    }


def _parsed_image(payload: dict[str, Any]) -> ParsedImageArtifact:
    return ParsedImageArtifact(
        image_type=payload["image_type"],
        image_digest=payload["image_digest"],
        config=SanitizedImageConfig(**payload["config"]),
        layers=tuple(LayerRecord(**item) for item in payload["layers"]),
        files=tuple(FileRecord(**item) for item in payload["files"]),
        rootfs_path=Path(payload["rootfs_path"]),
    )


def _image_evidence(digest: str, parsed: ParsedImageArtifact) -> ProfileEvidence:
    content = json.dumps(asdict(parsed.config), sort_keys=True, separators=(",", ":")).encode()
    return ProfileEvidence(
        evidence_id=f"evidence:image:{_digest_suffix(digest)}",
        artifact_digest=digest,
        locator=EvidenceLocator(config_key="image.config"),
        extractor="image_parser",
        method="image_config",
        content_sha256=hashlib.sha256(content).hexdigest(),
        summary="Sanitized image runtime configuration.",
    )


def _image_identity(digest: str, parsed: ParsedImageArtifact, evidence_id: str) -> ImageIdentity:
    platform = parsed.config.platform.split("/")
    return ImageIdentity(
        digest=digest,
        os=platform[0] if platform else "unknown",
        architecture=platform[1] if len(platform) > 1 else "unknown",
        variant=platform[2] if len(platform) > 2 else None,
        created_at=parsed.config.created,
        entrypoint=list(parsed.config.entrypoint),
        command=list(parsed.config.cmd),
        working_directory=parsed.config.working_dir,
        environment_variables=list(parsed.config.env_keys),
        layer_digests=[item.digest for item in parsed.layers],
        evidence_refs=[evidence_id],
        confidence=1.0,
        verification_status="supported",
    )


def _merge_claims(items: Iterable[Any], identifier: str) -> list[Any]:
    merged: dict[str, Any] = {}
    for item in items:
        key = getattr(item, identifier)
        current = merged.get(key)
        if current is None:
            merged[key] = item
            continue
        update = {
            "evidence_refs": sorted(set(current.evidence_refs) | set(item.evidence_refs)),
            "confidence": max(current.confidence, item.confidence),
        }
        merged[key] = current.model_copy(update=update)
    return [merged[key] for key in sorted(merged)]


def _dedupe_evidence(items: Iterable[ProfileEvidence]) -> list[ProfileEvidence]:
    values = {item.evidence_id: item for item in items}
    return [values[key] for key in sorted(values)]


def _dedupe_limitations(items: Iterable[AnalysisLimitation]) -> list[AnalysisLimitation]:
    values: dict[tuple[str, str], AnalysisLimitation] = {}
    for item in items:
        key = (item.code, item.message)
        current = values.get(key)
        values[key] = (
            item
            if current is None
            else current.model_copy(
                update={"evidence_refs": sorted(set(current.evidence_refs) | set(item.evidence_refs))}
            )
        )
    return [values[key] for key in sorted(values)]


def _profile_completeness(
    *,
    facts: StaticFactIndex,
    expected_frameworks: list[str],
    static_nodes: list[Any],
    static_edges: list[Any],
    static_controls: list[Any],
    profile: ImageAgentProfile,
) -> ProfileCompleteness:
    evidence_index = {item.evidence_id: item for item in profile.evidence}
    final_claims = {
        **{item.node_id: item for item in profile.nodes},
        **{item.edge_id: item for item in profile.edges},
        **{item.control_id: item for item in profile.controls},
    }
    static_claims = [
        *[(item.node_id, item) for item in static_nodes],
        *[(item.edge_id, item) for item in static_edges],
        *[(item.control_id, item) for item in static_controls],
    ]

    graph_covered = 0
    dynamically_corroborated = 0
    for claim_id, _ in static_claims:
        claim = final_claims.get(claim_id)
        if claim is None:
            continue
        methods = {evidence_index[ref].method for ref in claim.evidence_refs if ref in evidence_index}
        if methods & {"image_config", "package_metadata", "static", "framework"}:
            graph_covered += 1

    required_claim_ids = dynamic_required_claim_ids(profile)
    required_claims = [
        final_claims[claim_id]
        for claim_id in sorted(required_claim_ids)
        if claim_id in final_claims
        and {evidence_index[ref].method for ref in final_claims[claim_id].evidence_refs if ref in evidence_index}
        & {"image_config", "package_metadata", "static", "framework"}
    ]
    dynamically_corroborated = sum(
        any(
            evidence_index[ref].method == "dynamic"
            and evidence_index[ref].trust_level == "observed"
            and (evidence_index[ref].summary or "").partition(":")[0]
            in {"agent_invoked", "tool_called", "guard_decision"}
            for ref in claim.evidence_refs
            if ref in evidence_index
        )
        for claim in required_claims
    )

    expected = {_normalized_framework_name(item) for item in expected_frameworks}
    detected = {_normalized_framework_name(item.name) for item in profile.frameworks} | {
        _normalized_framework_name(item.framework_id.removeprefix("framework:")) for item in profile.frameworks
    }
    if expected:
        framework_total = len(expected)
        framework_covered = len(expected & detected)
    else:
        framework_total = len(profile.frameworks)
        framework_covered = framework_total

    blockers = set()
    for limitation in profile.limitations:
        informational = limitation.code in _INFORMATIONAL_COMPLETENESS_LIMITATIONS
        if limitation.code == "unsupported_framework" and "custom" in expected:
            informational = True
        if not informational:
            blockers.add(limitation.code)
    if facts.source_recovery != "complete":
        blockers.add("static_source_recovery_incomplete")
    if framework_total == 0 or framework_covered < framework_total:
        blockers.add("framework_coverage_incomplete")
    if not static_claims or graph_covered < len(static_claims):
        blockers.add("graph_evidence_coverage_incomplete")
    dynamic_stage = next(item for item in profile.analysis.stages if item.stage == "dynamic_verify")
    if dynamic_stage.status != "completed":
        blockers.add("dynamic_verification_failed")
    if not required_claims or dynamically_corroborated < len(required_claims):
        blockers.add("critical_dynamic_corroboration_incomplete")
    dynamic_event_types = {
        (item.summary or "").partition(":")[0] for item in profile.evidence if item.method == "dynamic"
    }
    required_behavior_events = {
        "invocation_started",
        "agent_invoked",
        "output_observed",
        "invocation_completed",
    }
    if not required_behavior_events <= dynamic_event_types:
        blockers.add("dynamic_behavior_protocol_incomplete")
    coverage_targets = {
        (item.summary or "").partition(":")[2].strip().casefold()
        for item in profile.evidence
        if item.method == "dynamic" and (item.summary or "").startswith("coverage_target:")
    }
    observed_targets = {
        (item.summary or "").partition(":")[2].strip().casefold()
        for item in profile.evidence
        if item.method == "dynamic"
        and item.trust_level == "observed"
        and (item.summary or "").partition(":")[0] in {"agent_invoked", "tool_called", "guard_decision"}
    }
    if not coverage_targets:
        blockers.add("dynamic_coverage_manifest_missing")
    elif not coverage_targets <= observed_targets:
        blockers.add("dynamic_critical_coverage_incomplete")
    return ProfileCompleteness(
        static_source_recovery=facts.source_recovery,
        framework_coverage=_coverage(framework_covered, framework_total),
        graph_evidence_coverage=_coverage(graph_covered, len(static_claims)),
        dynamic_corroboration_coverage=_coverage(
            dynamically_corroborated,
            len(required_claims),
        ),
        dynamic_behavior_coverage=_coverage(
            len(coverage_targets & observed_targets),
            len(coverage_targets),
        ),
        unresolved_limitations=len(profile.limitations),
        blocking_limitations=sorted(blockers),
        conclusion="partial" if blockers else "complete",
    )


def _coverage(covered: int, total: int) -> CoverageStatistic:
    return CoverageStatistic(
        covered=covered,
        total=total,
        ratio=covered / total if total else 0.0,
    )


def _normalized_framework_name(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _semantic_graph(payload: dict[str, Any]) -> SemanticGraphFragment:
    framework = FrameworkAnalysis.model_validate(payload["framework"])
    dataflow = DataflowAnalysisResult.model_validate(payload["dataflow"])
    nodes = _merge_claims([*framework.nodes, *dataflow.nodes], "node_id")
    edges = _merge_claims([*framework.edges, *dataflow.edges], "edge_id")
    evidence_ids = {item.evidence_id for item in [*framework.evidence, *dataflow.evidence]}
    return SemanticGraphFragment(
        artifact_digest=framework.artifact_digest,
        nodes=tuple(
            GraphNode(
                node_id=item.node_id,
                node_type=item.node_type,
                name=item.name,
                evidence_refs=tuple(item.evidence_refs),
            )
            for item in nodes
        ),
        relations=tuple(
            GraphRelation(
                relation_id=item.edge_id,
                relation_type=item.edge_type,
                source_node_id=item.source_node_id,
                target_node_id=item.target_node_id,
                evidence_refs=tuple(item.evidence_refs),
                verification_status=item.verification_status,
            )
            for item in edges
        ),
        evidence_ids=tuple(sorted(evidence_ids)),
    )


def _attack_handoff(profile: ImageAgentProfile) -> dict[str, Any]:
    attack = build_attack_profile(profile)
    if attack is None:
        return AttackProfileNotApplicable(
            source_profile_id=profile.profile_id,
            reason="No verified or supported risk path is available.",
        ).model_dump(mode="json")
    return attack.model_dump(mode="json")


def _safe_error(exc: Exception) -> str:
    return safe_image_profile_error(exc)


def _remove_read_only_tree(path: Path) -> None:
    for directory, directory_names, file_names in os.walk(path):
        for name in directory_names:
            candidate = Path(directory) / name
            if not candidate.is_symlink():
                candidate.chmod(0o700)
        for name in file_names:
            candidate = Path(directory) / name
            if not candidate.is_symlink():
                candidate.chmod(0o600)
    path.chmod(0o700)

    def make_writable_and_retry(function: Callable[..., Any], target: str, _: Any) -> None:
        os.chmod(target, 0o700)
        function(target)

    shutil.rmtree(path, onerror=make_writable_and_retry)


__all__ = [
    "ImageProfileCreateResult",
    "ImageProfileWorkflowError",
    "ImageProfileWorkflowService",
]
