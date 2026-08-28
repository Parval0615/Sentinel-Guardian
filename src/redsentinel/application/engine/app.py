from __future__ import annotations

import os
import shutil
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request






from redsentinel.application.engine.agent_library import AgentLibraryService, OFFICIAL_OPENMANUS_AGENT
from redsentinel.application.engine.agent_asset_index import AgentAssetIndexService
from redsentinel.application.engine.agent_image_upload import (
    AgentImageUploadError,
    AgentImageUploadService,
)
from redsentinel.application.engine.auth_config import is_protected_route
from redsentinel.application.engine.auth_service import AuthServiceError, ProductAuthService
from redsentinel.application.engine.audit_preflight import AuditPreflightService
from redsentinel.application.engine.image_profile_redaction import (
    redact_image_profile_text,
)
from redsentinel.application.engine.image_profile_workflow import (
    ImageProfileWorkflowError,
)
from redsentinel.application.contracts import (
    AgentLibraryEntry,
    AgentOnboardingRequest,
    AgentRegistration,
    AuthErrorResponse,
    AuthFieldError,
    AuthLoginRequest,
    AuthRegisterRequest,
    EvaluationRequest,
    SupervisionResponseRequest,
)
from redsentinel.application.audit_contracts import (
    AuditTask,
    ModelRuntimeConfiguration,
    ModelRuntimeRole,
    OpenManusRuntimeConfiguration,
    OpenManusRuntimeStatus,
)
from redsentinel.application.attack_profile import image_profile_sha256
from redsentinel.application.engine.llm_gateway import JsonLLMGateway
from redsentinel.application.engine.monitor_events import SecurityEventReader
from redsentinel.application.engine.model_runtime import ModelRuntimeRegistry
from redsentinel.application.engine.seed import bootstrap_demo_tenant
from redsentinel.application.engine.service import EvaluationRequestError
from redsentinel.application.engine.supervision import (
    SupervisionDecisionError,
    seed_supervision_demo_events,
)
from redsentinel.application import ProductApplicationService
from redsentinel.research.catalog import RQConfigurationError, list_rq_experiment_matrix


ECOMMERCE_DEMO_AGENT_ID = "ecommerce_customer_guide"
ECOMMERCE_DEMO_SOURCE_PATH = (
    Path(__file__).resolve().parents[2] / "adapters" / "engine" / "ecommerce_agent"
)


def _ecommerce_demo_source_path() -> Path:
    resource_root = os.environ.get("RED_SENTINEL_RESOURCE_ROOT", "").strip()
    if resource_root:
        bundled = Path(resource_root).expanduser() / "builtin-agents" / "ecommerce"
        if bundled.is_dir():
            return bundled
    return ECOMMERCE_DEMO_SOURCE_PATH


def _frontend_index_path() -> Path | None:
    configured = os.environ.get("RED_SENTINEL_RESOURCE_ROOT", "").strip()
    candidates = [
        Path(configured).expanduser() / "frontend" / "dist" / "index.html"
        if configured
        else None,
        Path.cwd() / "frontend" / "dist" / "index.html",
        Path.cwd() / "frontend" / "index.html",
        Path(__file__).resolve().parents[4] / "frontend" / "dist" / "index.html",
        Path(__file__).resolve().parents[4] / "frontend" / "index.html",
    ]
    return next(
        (path for path in candidates if path is not None and path.is_file()),
        None,
    )


def create_app(
    storage_root: str | Path = "runs/product",
    seed_demo: bool = False,
    planner_gateway: JsonLLMGateway | None = None,
):
    try:
        from fastapi import Body, Depends, FastAPI, Header, HTTPException
        from fastapi.exceptions import RequestValidationError
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise RuntimeError("FastAPI is not installed. Install with .[product].") from exc

    model_runtime = ModelRuntimeRegistry()
    service = ProductApplicationService(
        storage_root=storage_root,
        planner_gateway=planner_gateway or model_runtime.gateway("attack"),
        defense_gateway=model_runtime.gateway("defense"),
    )
    audit_preflight = AuditPreflightService(service, model_runtime)
    auth_service = ProductAuthService(storage=service.storage)
    agent_library = AgentLibraryService(storage=service.storage)
    agent_asset_index = AgentAssetIndexService(service)
    agent_image_upload = AgentImageUploadService(
        service.storage,
        agent_asset_index,
        service.image_profiles,
    )
    supervision_store = service.supervision
    monitor_events = SecurityEventReader(storage=service.storage)
    if seed_demo:
        app_demo_seed = bootstrap_demo_tenant(auth_service, service)
    else:
        app_demo_seed = None
    app = FastAPI(title="Agent Security Product API", version="0.1.0")
    app.state.demo_seed = app_demo_seed
    app.state.service = service
    app.state.model_runtime = model_runtime
    app.state.audit_preflight = audit_preflight
    app.state.profile_threads = set()
    app.state.audit_threads = set()
    app.state.audit_jobs = set()
    profile_threads_lock = threading.Lock()
    audit_threads_lock = threading.Lock()
    frontend_index_path = _frontend_index_path()

    if frontend_index_path is not None:
        frontend_assets_path = frontend_index_path.parent / "assets"
        if frontend_assets_path.is_dir():
            app.mount(
                "/assets",
                StaticFiles(directory=frontend_assets_path),
                name="frontend-assets",
            )

        @app.get("/", include_in_schema=False)
        def frontend_index():
            return FileResponse(frontend_index_path)

    def lookup_status_code(message: str) -> int:
        lowered = message.lower()
        if "not found" in lowered or "not registered" in lowered:
            return 404
        return 422

    def require_object_payload(payload: dict | None, *, error_code: str, message: str) -> dict:
        if not isinstance(payload, dict) or not payload:
            raise HTTPException(
                status_code=422,
                detail={"error_code": error_code, "message": message},
            )
        return payload

    def validation_error_code(path: str) -> str:
        if path.startswith("/v1/auth/"):
            return "invalid_auth_request"
        if path == "/v1/agents/onboard":
            return "invalid_onboarding_request"
        if path == "/v1/agents":
            return "invalid_agent_registration"
        if path == "/v1/evaluations":
            return "invalid_evaluation_request"
        if path == "/v1/audits":
            return "invalid_audit_request"
        if path == "/v1/logs":
            return "invalid_log_request"
        return "invalid_request"

    def validation_error_message(exc: RequestValidationError) -> str:
        messages: list[str] = []
        for error in exc.errors():
            msg = str(error.get("msg") or "Invalid request.")
            loc = [
                str(part)
                for part in error.get("loc", [])
                if part not in {"body", "query", "path"}
            ]
            messages.append(f"{'.'.join(loc)}: {msg}" if loc else msg)
        return "; ".join(messages) if messages else "Invalid request."

    def validation_field_errors(exc: RequestValidationError) -> list[dict]:
        field_errors: list[dict] = []
        for error in exc.errors():
            loc = [
                str(part)
                for part in error.get("loc", [])
                if part not in {"body", "query", "path"}
            ]
            field_errors.append(
                AuthFieldError(
                    field=".".join(loc) if loc else "request",
                    message=str(error.get("msg") or "Invalid request."),
                    error_code=str(error.get("type") or "invalid_field"),
                ).model_dump(mode="json")
            )
        return field_errors

    def auth_error_response(exc: AuthServiceError) -> HTTPException:
        return HTTPException(status_code=exc.status_code, detail=exc.to_detail())

    @app.middleware("http")
    async def require_authentication_for_protected_routes(request: Request, call_next):
        if is_protected_route(request.method, request.url.path):
            try:
                auth_service.require_user_from_authorization(request.headers.get("authorization"))
            except AuthServiceError as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": exc.to_detail()})
        return await call_next(request)

    def require_authenticated_user(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        try:
            return auth_service.require_user_from_authorization(authorization)
        except AuthServiceError as exc:
            raise auth_error_response(exc) from exc

    def require_admin(
        user: dict[str, Any] = Depends(require_authenticated_user),
    ) -> dict[str, Any]:
        if user.get("role") != "admin":
            raise HTTPException(
                status_code=403,
                detail={"error_code": "admin_required", "message": "Admin role is required."},
            )
        return user

    def tenant_id_for_user(user: dict[str, Any]) -> str:
        return str(user["username"])

    def bind_onboarding_request(request: AgentOnboardingRequest, user: dict[str, Any]) -> AgentOnboardingRequest:
        tenant_id = tenant_id_for_user(user)
        return request.model_copy(update={"tenant_id": tenant_id, "username": user["username"]})

    def bind_agent_registration(registration: AgentRegistration, user: dict[str, Any]) -> AgentRegistration:
        tenant_id = tenant_id_for_user(user)
        return registration.model_copy(update={"tenant_id": tenant_id, "username": user["username"]})

    def bind_evaluation_request(request: EvaluationRequest, user: dict[str, Any]) -> EvaluationRequest:
        return request.model_copy(update={"tenant_id": tenant_id_for_user(user)})




    def bind_audit_task(task: AuditTask, user: dict[str, Any]) -> AuditTask:
        tenant_id = tenant_id_for_user(user)
        updates: dict[str, Any] = {"tenant_id": tenant_id}
        try:
            profile = service.image_profiles.get_latest_profile(
                tenant_id=tenant_id,
                agent_id=task.agent_id,
            )
        except ImageProfileWorkflowError:
            return task.model_copy(update=updates)
        updates.update(
            {
                "image_digest": profile.image.digest,
                "profile_id": profile.profile_id,
                "profile_sha256": image_profile_sha256(profile),
            }
        )
        agent = service.get_agent(agent_id=task.agent_id, tenant_id=tenant_id)
        if agent.adapter_type == "openmanus":
            updates.update(
                {
                    "benchmark_id": "openmanus-security-v0.1",
                    "runtime_mode": "openmanus_real",
                }
            )
        return task.model_copy(update=updates)

    def refresh_agent_assets(user: dict[str, Any]) -> None:
        configured = os.environ.get("RED_SENTINEL_AGENT_ROOT", "").strip()
        if configured:
            agent_asset_index.refresh(
                Path(configured).expanduser(),
                tenant_id=tenant_id_for_user(user),
                username=str(user["username"]),
            )

    def profile_error(exc: ImageProfileWorkflowError) -> HTTPException:
        return HTTPException(
            status_code=exc.status_code,
            detail={
                "error_code": exc.code,
                "message": redact_image_profile_text(exc.message),
            },
        )

    def run_profile(tenant_id: str, agent_id: str, analysis_id: str) -> None:
        try:
            service.image_profiles.run(
                tenant_id=tenant_id,
                agent_id=agent_id,
                analysis_id=analysis_id,
            )
        finally:
            with profile_threads_lock:
                app.state.profile_threads.discard(threading.current_thread())

    def start_profile(tenant_id: str, agent_id: str, analysis_id: str) -> None:
        thread = threading.Thread(
            target=run_profile,
            args=(tenant_id, agent_id, analysis_id),
            daemon=True,
        )
        with profile_threads_lock:
            app.state.profile_threads.add(thread)
        thread.start()

    def run_audit(tenant_id: str, audit_id: str) -> None:
        try:
            with model_runtime.tenant_context(tenant_id):
                service.run_audit(audit_id, tenant_id=tenant_id)
        finally:
            with audit_threads_lock:
                app.state.audit_threads.discard(threading.current_thread())
                app.state.audit_jobs.discard((tenant_id, audit_id))

    def start_audit(tenant_id: str, audit_id: str) -> bool:
        thread = threading.Thread(
            target=run_audit,
            args=(tenant_id, audit_id),
            daemon=True,
        )
        with audit_threads_lock:
            job_key = (tenant_id, audit_id)
            if job_key in app.state.audit_jobs:
                return False
            app.state.audit_jobs.add(job_key)
            app.state.audit_threads.add(thread)
        thread.start()
        return True

    def require_audit_models(audit_id: str, tenant_id: str) -> None:
        run = service.get_audit(audit_id, tenant_id=tenant_id)
        agent = service.get_agent(
            agent_id=run.agent_id,
            tenant_id=tenant_id,
        )
        if agent.adapter_type == "openmanus":
            model_runtime.require_ready(
                tenant_id,
                ("target", "attack", "defense"),
            )

    def require_audit_runtime(audit_id: str, tenant_id: str) -> None:
        run = service.get_audit(audit_id, tenant_id=tenant_id)
        status = audit_preflight.check(
            tenant_id=tenant_id,
            agent_id=run.agent_id,
        )
        blockers = [
            check.check_id
            for check in status.checks
            if check.status == "blocked"
        ]
        if blockers:
            raise ValueError(
                "Audit runtime preflight failed: " + ", ".join(blockers)
            )

    @asynccontextmanager
    async def lifespan(_app):
        service.recover_interrupted_audits()
        for task in service.image_profiles.list_recovery_tasks():
            start_profile(task.tenant_id, task.agent_id, task.analysis_id)
        yield

    app.router.lifespan_context = lifespan

    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(request, exc: RequestValidationError):
        if request.url.path.startswith("/v1/auth/"):
            detail = AuthErrorResponse(
                error_code="invalid_auth_request",
                message=validation_error_message(exc),
                field_errors=validation_field_errors(exc),
            ).model_dump(mode="json")
            return JSONResponse(status_code=422, content={"detail": detail})
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "error_code": validation_error_code(request.url.path),
                    "message": validation_error_message(exc),
                }
            },
        )

    @app.post("/v1/auth/register")
    def register_user(request: AuthRegisterRequest):
        try:
            return auth_service.register(request).model_dump(mode="json")
        except AuthServiceError as exc:
            raise auth_error_response(exc) from exc

    @app.post("/v1/auth/login")
    def login_user(request: AuthLoginRequest):
        try:
            return auth_service.login(request).model_dump(mode="json")
        except AuthServiceError as exc:
            raise auth_error_response(exc) from exc

    @app.get("/v1/auth/me")
    def get_current_user(authorization: str | None = Header(default=None)):
        try:
            return auth_service.current_user_from_authorization(authorization).model_dump(mode="json")
        except AuthServiceError as exc:
            raise auth_error_response(exc) from exc

    @app.post("/v1/auth/logout")
    def logout_user(authorization: str | None = Header(default=None)):
        try:
            return auth_service.logout(authorization).model_dump(mode="json")
        except AuthServiceError as exc:
            raise auth_error_response(exc) from exc

    @app.get("/health", include_in_schema=False)
    def health_check():
        return {"status": "ok"}

    @app.get("/v1/health", include_in_schema=False)
    def v1_health_check():
        return {"status": "ok"}

    @app.post("/v1/agents/onboard")
    def onboard_agent(
        request: AgentOnboardingRequest,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            request = bind_onboarding_request(request, user)
            return service.onboard_agent(request).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_onboarding_request", "message": str(exc)},
            ) from exc

    @app.post("/v1/demo/agents/ecommerce")
    def onboard_ecommerce_demo(
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        source_path = _ecommerce_demo_source_path()
        try:
            response = service.onboard_agent(
                AgentOnboardingRequest(
                    tenant_id=tenant_id_for_user(user),
                    username=str(user["username"]),
                    agent_id=ECOMMERCE_DEMO_AGENT_ID,
                    name="E-commerce Customer Guide Agent",
                    domain="ecommerce",
                    framework="local-sdk",
                    remarks="Built-in ecommerce demo onboarded from repository source.",
                    source_path=str(source_path),
                    build_manifest_path=str(source_path / "sandbox-build.json"),
                )
            )
            return response.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_onboarding_request", "message": str(exc)},
            ) from exc

    @app.post("/v1/agents")
    def register_agent(
        registration: AgentRegistration,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            registration = bind_agent_registration(registration, user)
            return service.register_agent(registration).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_agent_registration", "message": str(exc)},
            ) from exc

    @app.post("/v1/agents/import-image", status_code=202)
    async def import_agent_image(
        request: Request,
        agent_id: str,
        name: str,
        domain: str = "general",
        probe_module: str | None = None,
        expected_frameworks: str = "",
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        content_length = request.headers.get("content-length")
        try:
            result = await agent_image_upload.import_archive(
                tenant_id=tenant_id_for_user(user),
                username=str(user["username"]),
                agent_id=agent_id,
                name=name,
                domain=domain,
                probe_module=probe_module,
                expected_frameworks=expected_frameworks.split(","),
                chunks=request.stream(),
                content_length=int(content_length) if content_length else None,
            )
            start_profile(
                tenant_id_for_user(user),
                agent_id,
                result.profile.analysis.analysis_id,
            )
            return result.model_dump(mode="json")
        except AgentImageUploadError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"error_code": exc.code, "message": exc.message},
            ) from exc

    @app.get("/v1/agents/index-errors")
    def list_agent_index_errors(
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        refresh_agent_assets(user)
        return [
            item.model_dump(mode="json")
            for item in agent_asset_index.list_errors(tenant_id_for_user(user))
        ]

    @app.get("/v1/agents")
    def list_agents(user: dict[str, Any] = Depends(require_authenticated_user)):
        refresh_agent_assets(user)
        return [
            agent.model_dump(mode="json")
            for agent in service.list_agents(tenant_id=tenant_id_for_user(user))
        ]

    @app.get("/v1/agents/{agent_id}")
    def get_agent(agent_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            refresh_agent_assets(user)
            return service.get_agent(agent_id=agent_id, tenant_id=tenant_id_for_user(user)).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "agent_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/agents/{agent_id}/profile")
    def get_agent_profile(agent_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            try:
                profile = service.image_profiles.get_latest_profile(
                    tenant_id=tenant_id_for_user(user),
                    agent_id=agent_id,
                )
            except ImageProfileWorkflowError:
                profile = service.get_agent_profile(
                    agent_id=agent_id,
                    tenant_id=tenant_id_for_user(user),
                )
            return profile.model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "agent_profile_not_found", "message": str(exc)},
            ) from exc

    @app.post("/v1/agents/{agent_id}/profiles", status_code=202)
    def create_agent_profile(
        agent_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        tenant_id = tenant_id_for_user(user)
        try:
            refresh_agent_assets(user)
            result = service.image_profiles.create(
                tenant_id=tenant_id,
                agent_id=agent_id,
            )
            start_profile(tenant_id, agent_id, result.analysis.analysis_id)
            return result.model_dump(mode="json")
        except ImageProfileWorkflowError as exc:
            raise profile_error(exc) from exc

    @app.get("/v1/agents/{agent_id}/profiles/latest")
    def get_latest_agent_profile(
        agent_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            profile = service.image_profiles.get_latest_profile(
                tenant_id=tenant_id_for_user(user),
                agent_id=agent_id,
            )
            response = JSONResponse(content=profile.model_dump(mode="json"))
            response.headers["ETag"] = f'"{image_profile_sha256(profile)}"'
            return response
        except ImageProfileWorkflowError as exc:
            raise profile_error(exc) from exc

    @app.get("/v1/agents/{agent_id}/profiles/{analysis_id}/status")
    def get_agent_profile_status(
        agent_id: str,
        analysis_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            return service.image_profiles.get_status(
                tenant_id=tenant_id_for_user(user),
                agent_id=agent_id,
                analysis_id=analysis_id,
            ).model_dump(mode="json")
        except ImageProfileWorkflowError as exc:
            raise profile_error(exc) from exc

    @app.post(
        "/v1/agents/{agent_id}/profiles/{analysis_id}/retry",
        status_code=202,
    )
    def retry_agent_profile(
        agent_id: str,
        analysis_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        tenant_id = tenant_id_for_user(user)
        try:
            status = service.image_profiles.retry(
                tenant_id=tenant_id,
                agent_id=agent_id,
                analysis_id=analysis_id,
            )
            start_profile(tenant_id, agent_id, analysis_id)
            return status.model_dump(mode="json")
        except ImageProfileWorkflowError as exc:
            raise profile_error(exc) from exc

    @app.delete("/v1/agents/{agent_id}")
    def delete_agent(
        agent_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        tenant_id = tenant_id_for_user(user)
        try:
            service.get_agent(agent_id=agent_id, tenant_id=tenant_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "agent_not_found", "message": str(exc)},
            ) from exc
        active = [
            audit
            for audit in service.storage.list_audits(tenant_id)
            if audit.get("agent_id") == agent_id
            and audit.get("state") not in {"completed", "failed"}
        ]
        if active:
            raise HTTPException(
                status_code=409,
                detail={
                    "error_code": "agent_has_active_audits",
                    "message": "Agent has active audits.",
                },
            )
        index_path = service.storage.agent_asset_index_path(tenant_id, agent_id)
        index_record = (
            service.storage.read_json(index_path) if index_path.is_file() else None
        )

        def remove_agent_files() -> None:
            if index_record is not None and index_record.get("asset_source") == "configured_root":
                agent_asset_index.suppress_configured_asset(tenant_id, agent_id)
            service.unregister_agent(agent_id=agent_id, tenant_id=tenant_id)
            service.storage.agent_path(tenant_id, agent_id).unlink(missing_ok=True)
            index_path.unlink(missing_ok=True)
            service.storage.material_path(
                tenant_id, f"material-{agent_id}"
            ).unlink(missing_ok=True)
            service.storage.profile_path(
                tenant_id, f"profile-{agent_id}"
            ).unlink(missing_ok=True)
            shutil.rmtree(
                service.storage.tenant_dir(tenant_id)
                / "agent_asset_index"
                / "versions"
                / agent_id,
                ignore_errors=True,
            )
            shutil.rmtree(
                service.storage.managed_agent_assets_dir(tenant_id) / agent_id,
                ignore_errors=True,
            )
            profile_root = (
                service.storage.tenant_dir(tenant_id)
                / "image_profiles"
                / agent_id
            )
            if profile_root.exists():
                for candidate in profile_root.rglob("*"):
                    if not candidate.is_symlink():
                        candidate.chmod(0o700)
                profile_root.chmod(0o700)
                shutil.rmtree(profile_root)

        profile_version_digest = (
            index_record.get("profile_version_digest")
            if index_record is not None
            else None
        )
        if profile_version_digest:
            digest_suffix = str(profile_version_digest).removeprefix("sha256:")[:16]
            with service.storage.image_profile_lease(
                tenant_id,
                agent_id,
                digest_suffix,
            ) as acquired:
                if not acquired:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "error_code": "agent_profile_active",
                            "message": "Agent profile analysis is active.",
                        },
                    )
                remove_agent_files()
        else:
            remove_agent_files()
        return {
            "schema_version": "agent-delete-response-v0.1",
            "agent_id": agent_id,
            "deleted": True,
        }

    @app.post("/v1/agents/{agent_id}/sessions")
    def create_session(agent_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.create_session(tenant_id=tenant_id_for_user(user), agent_id=agent_id)
        except ValueError as exc:
            message = str(exc)
            raise HTTPException(
                status_code=lookup_status_code(message),
                detail={"error_code": "session_agent_not_found", "message": message},
            ) from exc

    @app.post("/v1/evaluations")
    def create_evaluation(
        request: EvaluationRequest,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            request = bind_evaluation_request(request, user)
            return service.run_evaluation(request).model_dump(mode="json")
        except EvaluationRequestError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.to_detail()) from exc




























    @app.post("/v1/audits")
    def create_audit(
        task: AuditTask,
        background: bool = False,
        prepare_only: bool = False,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            task = bind_audit_task(task, user)
            agent = service.get_agent(
                agent_id=task.agent_id,
                tenant_id=task.tenant_id,
            )
            if agent.adapter_type == "openmanus":
                model_runtime.require_ready(
                    task.tenant_id,
                    ("target", "attack", "defense"),
                )
            material_path = service.storage.material_path(
                task.tenant_id,
                f"material-{task.agent_id}",
            )
            if not material_path.is_file():
                if agent.adapter_type == "ecommerce_demo":
                    source_path = _ecommerce_demo_source_path()
                    service.onboard_agent(
                        AgentOnboardingRequest(
                            tenant_id=task.tenant_id,
                            username=str(user["username"]),
                            agent_id=agent.agent_id,
                            name=agent.name,
                            domain=agent.domain,
                            framework=agent.framework,
                            remarks=agent.remarks,
                            source_path=str(source_path),
                            build_manifest_path=str(
                                source_path / "sandbox-build.json"
                            ),
                        )
                    )
            run = service.create_audit(task)
            if prepare_only:
                with model_runtime.tenant_context(task.tenant_id):
                    return service.prepare_audit(
                        task.audit_id,
                        tenant_id=task.tenant_id,
                    ).model_dump(mode="json")
            if background:
                start_audit(task.tenant_id, task.audit_id)
                return run.model_dump(mode="json")
            with model_runtime.tenant_context(task.tenant_id):
                return service.run_audit(
                    task.audit_id,
                    tenant_id=task.tenant_id,
                ).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "audit_creation_failed", "message": str(exc)},
            ) from exc

    @app.post("/v1/audits/{audit_id}/execute")
    def execute_audit(
        audit_id: str,
        background: bool = True,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        tenant_id = tenant_id_for_user(user)
        try:
            require_audit_runtime(audit_id, tenant_id)
            run = service.get_audit(audit_id, tenant_id=tenant_id)
            if run.state != "attack_review":
                raise ValueError(
                    "Audit must be in attack_review before formal execution."
                )
            if background:
                if not start_audit(tenant_id, audit_id):
                    raise ValueError("Audit execution is already running.")
                return run.model_dump(mode="json")
            with model_runtime.tenant_context(tenant_id):
                return service.run_audit(
                    audit_id,
                    tenant_id=tenant_id,
                ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "audit_execution_failed",
                    "message": str(exc),
                },
            ) from exc

    @app.get("/v1/audits")
    def list_audits(user: dict[str, Any] = Depends(require_authenticated_user)):
        return [
            item.model_dump(mode="json")
            for item in service.list_audits(
                tenant_id=tenant_id_for_user(user),
            )
        ]

    @app.get("/v1/audits/{audit_id}")
    def get_audit(audit_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_audit(
                audit_id,
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/audits/{audit_id}/plan")
    def get_audit_plan(audit_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_audit_plan_view(
                audit_id,
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_plan_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/audits/{audit_id}/decision")
    def get_audit_decision(
        audit_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            return service.get_audit_decision(
                audit_id,
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_decision_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/audits/{audit_id}/workspace")
    def get_audit_workspace(
        audit_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            return service.get_audit_workspace(
                audit_id,
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_workspace_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/audits/{audit_id}/status")
    def get_audit_status(audit_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_audit_status(
                audit_id,
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/audits/{audit_id}/evidence")
    def get_audit_evidence(audit_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_audit_evidence_index(
                audit_id,
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_evidence_not_found", "message": str(exc)},
            ) from exc

    @app.post("/v1/audits/{audit_id}/resume")
    def resume_audit(
        audit_id: str,
        background: bool = False,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        tenant_id = tenant_id_for_user(user)
        try:
            require_audit_runtime(audit_id, tenant_id)
            if background:
                run = service.get_audit(audit_id, tenant_id=tenant_id)
                if run.state == "attack_review":
                    raise ValueError(
                        "Reviewed attack plans must be approved through formal execution."
                    )
                if not start_audit(tenant_id, audit_id):
                    raise ValueError("Audit execution is already running.")
                return run.model_dump(mode="json")
            with model_runtime.tenant_context(tenant_id):
                return service.resume_audit(
                    audit_id,
                    tenant_id=tenant_id,
                ).model_dump(mode="json")
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "audit_not_found", "message": str(exc)},
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "audit_resume_failed", "message": str(exc)},
            ) from exc

    @app.post("/v1/audits/{audit_id}/next-round")
    def create_next_audit_round(
        audit_id: str,
        background: bool = False,
        prepare_only: bool = False,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        tenant_id = tenant_id_for_user(user)
        try:
            require_audit_models(audit_id, tenant_id)
            with model_runtime.tenant_context(tenant_id):
                next_run = service.create_next_audit_round(
                    audit_id,
                    tenant_id=tenant_id,
                    run_immediately=not background and not prepare_only,
                )
            if prepare_only:
                with model_runtime.tenant_context(tenant_id):
                    return service.prepare_audit(
                        next_run.audit_id,
                        tenant_id=tenant_id,
                    ).model_dump(mode="json")
            if background:
                start_audit(tenant_id, next_run.audit_id)
            return next_run.model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "next_audit_round_failed",
                    "message": str(exc),
                },
            ) from exc

    @app.get("/v1/runtime/openmanus/status")
    def get_openmanus_runtime_status(
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        status = model_runtime.status(
            tenant_id_for_user(user),
            "target",
        )
        parsed = urlsplit(status.base_url) if status.base_url else None
        return OpenManusRuntimeStatus(
            configured=status.configured,
            base_url=(
                f"{parsed.scheme}://{parsed.netloc}"
                if parsed is not None and parsed.scheme and parsed.netloc
                else None
            ),
            model=status.model,
        ).model_dump(mode="json")

    @app.get("/v1/runtime/models/status")
    def get_model_runtime_statuses(
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        return [
            status.model_dump(mode="json")
            for status in model_runtime.statuses(tenant_id_for_user(user))
        ]

    @app.get("/v1/runtime/audit-preflight/{agent_id}")
    def get_audit_preflight(
        agent_id: str,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            return audit_preflight.check(
                tenant_id=tenant_id_for_user(user),
                agent_id=agent_id,
            ).model_dump(mode="json")
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={
                    "error_code": "agent_not_found",
                    "message": str(exc),
                },
            ) from exc

    @app.post("/v1/runtime/models/{role}/test")
    def test_model_runtime_configuration(
        role: ModelRuntimeRole,
        configuration: ModelRuntimeConfiguration,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        return model_runtime.test_and_store(
            tenant_id_for_user(user),
            role,
            configuration,
        ).model_dump(mode="json")

    @app.post("/v1/runtime/openmanus/config")
    def configure_openmanus_runtime(
        configuration: OpenManusRuntimeConfiguration,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        status = model_runtime.configure(
            tenant_id_for_user(user),
            "target",
            ModelRuntimeConfiguration.model_validate(
                configuration.model_dump()
            ),
        )
        parsed = urlsplit(status.base_url) if status.base_url else None
        return OpenManusRuntimeStatus(
            configured=True,
            base_url=(
                f"{parsed.scheme}://{parsed.netloc}"
                if parsed is not None and parsed.scheme and parsed.netloc
                else None
            ),
            model=status.model,
        ).model_dump(mode="json")

    @app.get("/v1/evaluations/{evaluation_id}")
    def get_evaluation(evaluation_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_evaluation(evaluation_id, tenant_id=tenant_id_for_user(user)).model_dump(mode="json")
        except ValueError as exc:
            message = str(exc)
            raise HTTPException(
                status_code=lookup_status_code(message),
                detail={"error_code": "evaluation_not_found", "message": message},
            ) from exc

    @app.post("/v1/evaluations/{evaluation_id}/next-round")
    def create_next_round(evaluation_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.create_next_round(evaluation_id, tenant_id=tenant_id_for_user(user)).model_dump(mode="json")
        except ValueError as exc:
            message = str(exc)
            status_code = 404 if "not found" in message.lower() else 422
            raise HTTPException(
                status_code=status_code,
                detail={"error_code": "next_round_failed", "message": message},
            ) from exc

    @app.get("/v1/reports/{report_id}")
    def get_report(report_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_report(report_id, tenant_id=tenant_id_for_user(user)).model_dump(mode="json")
        except ValueError as exc:
            message = str(exc)
            status_code = lookup_status_code(message)
            raise HTTPException(
                status_code=status_code,
                detail={
                    "error_code": "report_not_found" if status_code == 404 else "report_lookup_failed",
                    "message": message,
                },
            ) from exc

    @app.get("/v1/logs")
    def list_logs(agent_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return [
                item.model_dump(mode="json")
                for item in service.list_logs(agent_id=agent_id, tenant_id=tenant_id_for_user(user))
            ]
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "logs_agent_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/logs/{evaluation_id}")
    def get_log_detail(evaluation_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_log_detail(evaluation_id, tenant_id=tenant_id_for_user(user)).model_dump(mode="json")
        except ValueError as exc:
            message = str(exc)
            status_code = 404 if "not found" in message.lower() else 422
            raise HTTPException(
                status_code=status_code,
                detail={"error_code": "log_lookup_failed", "message": message},
            ) from exc

    @app.get("/v1/dashboard/summary")
    def get_dashboard_summary(agent_id: str, user: dict[str, Any] = Depends(require_authenticated_user)):
        try:
            return service.get_dashboard_summary(agent_id=agent_id, tenant_id=tenant_id_for_user(user)).model_dump(
                mode="json"
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "dashboard_agent_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/supervision/latest")
    def get_supervision_latest(user: dict[str, Any] = Depends(require_authenticated_user)):
        return supervision_store.write_latest_snapshot(tenant_id=tenant_id_for_user(user))

    @app.get("/v1/supervision/events")
    def list_supervision_events(limit: int = 50, user: dict[str, Any] = Depends(require_authenticated_user)):
        bounded_limit = max(1, min(limit, 200))
        return [
            event.model_dump(mode="json")
            for event in supervision_store.read_recent_events(limit=bounded_limit, tenant_id=tenant_id_for_user(user))
        ]

    @app.post("/v1/supervision/demo-seed")
    def seed_supervision_demo(user: dict[str, Any] = Depends(require_authenticated_user)):
        tenant_id = tenant_id_for_user(user)
        return seed_supervision_demo_events(
            service.storage.root,
            tenant_id=tenant_id,
            agent_id="demo_supervised_agent",
        )

    @app.post("/v1/supervision/ask/{event_id}/respond")
    def respond_to_supervision_ask(
        event_id: str,
        request: SupervisionResponseRequest,
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            response = supervision_store.respond_to_pending(
                event_id,
                action=request.action,
                operator=request.operator or str(user["username"]),
                reason=request.reason,
                tenant_id=tenant_id_for_user(user),
            )
            return response.model_dump(mode="json")
        except SupervisionDecisionError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"error_code": exc.error_code, "message": str(exc)},
            ) from exc

    @app.get("/v1/monitor/events")
    def list_monitor_events(
        agent_id: str | None = None,
        decision: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
        user: dict[str, Any] = Depends(require_admin),
    ):
        return monitor_events.read_security_events(
            limit=limit,
            agent_id=agent_id,
            decision=decision,
            session_id=session_id,
        )

    @app.get("/v1/monitor/events/summary")
    def summarize_monitor_events(
        agent_id: str | None = None,
        decision: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
        user: dict[str, Any] = Depends(require_admin),
    ):
        return monitor_events.summarize_security_events(
            limit=limit,
            agent_id=agent_id,
            decision=decision,
            session_id=session_id,
        )

    @app.post("/v1/admin/agents/openmanus")
    def register_openmanus_agent(user: dict[str, Any] = Depends(require_admin)):
        library_entry = agent_library.upsert_entry(
            OFFICIAL_OPENMANUS_AGENT,
            created_by=str(user["username"]),
        )
        agent = service.register_agent(
            AgentRegistration(
                tenant_id=tenant_id_for_user(user),
                username=str(user["username"]),
                agent_id=library_entry.agent_id,
                name=library_entry.name,
                domain="general",
                integration_type="source",
                framework=library_entry.framework,
                adapter_type="openmanus",
                status="ready",
                remarks="Official OpenManus adapter registered by platform admin.",
                data_boundary={"deployment": "admin_registered", "integration_type": "source"},
            )
        )
        return {
            "schema_version": "openmanus-admin-registration-v0.1",
            "status": "registered",
            "library_entry": library_entry.model_dump(mode="json"),
            "agent": agent.model_dump(mode="json"),
        }

    @app.get("/v1/benchmarks")
    def list_benchmarks():
        return [item.model_dump(mode="json") for item in service.list_benchmarks()]

    @app.get("/v1/benchmarks/{benchmark_id}/versions")
    def list_benchmark_versions(benchmark_id: str):
        try:
            return [item.model_dump(mode="json") for item in service.list_benchmark_versions(benchmark_id)]
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "benchmark_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/benchmarks/{benchmark_id}/versions/{version}")
    def get_benchmark_version(benchmark_id: str, version: str):
        try:
            return service.get_benchmark_version(benchmark_id, version).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "benchmark_version_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/research/experiments")
    def list_research_experiments():
        return list_rq_experiment_matrix()

    @app.get("/v1/research/experiments/{rq_id}")
    def get_research_experiment(rq_id: str):
        if rq_id not in {"RQ1", "RQ2", "RQ3", "RQ4", "RQ5"}:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "research_question_not_found", "message": f"Research question not found: {rq_id}"},
            )
        try:
            return list_rq_experiment_matrix(rq_id=rq_id)
        except RQConfigurationError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "research_question_not_found", "message": str(exc)},
            ) from exc

    @app.get("/v1/admin/agent-library")
    def list_agent_library(user: dict[str, Any] = Depends(require_admin)):
        return [item.model_dump(mode="json") for item in agent_library.list_entries()]

    @app.post("/v1/admin/agent-library")
    def upsert_agent_library_entry(
        entry: AgentLibraryEntry,
        user: dict[str, Any] = Depends(require_admin),
    ):
        return agent_library.upsert_entry(entry, created_by=str(user["username"])).model_dump(mode="json")

    @app.get("/v1/admin/agent-library/{agent_id}")
    def get_agent_library_entry(agent_id: str, user: dict[str, Any] = Depends(require_admin)):
        try:
            return agent_library.get_entry(agent_id).model_dump(mode="json")
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"error_code": "agent_library_entry_not_found", "message": str(exc)},
            ) from exc

    @app.post("/v1/comparisons")
    def compare_reports(
        payload: dict | None = Body(default=None),
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            payload = require_object_payload(
                payload,
                error_code="invalid_comparison_request",
                message="Comparison payload must include before_report_id and after_report_id.",
            )
            return service.compare_reports(
                before_report_id=str(payload["before_report_id"]),
                after_report_id=str(payload["after_report_id"]),
                tenant_id=tenant_id_for_user(user),
            ).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_comparison_request", "message": f"Missing field: {exc.args[0]}"},
            ) from exc
        except ValueError as exc:
            message = str(exc)
            raise HTTPException(
                status_code=lookup_status_code(message),
                detail={"error_code": "comparison_failed", "message": message},
            ) from exc

    @app.post("/v1/trajectories")
    def upload_trajectory(
        payload: dict | None = Body(default=None),
        user: dict[str, Any] = Depends(require_authenticated_user),
    ):
        try:
            payload = require_object_payload(
                payload,
                error_code="invalid_trajectory_request",
                message="Trajectory payload must include agent_id and trajectory.",
            )
            tenant_id = tenant_id_for_user(user)
            agent_id = str(payload["agent_id"])
            trajectory = payload["trajectory"]
            if not isinstance(trajectory, dict) or not trajectory:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error_code": "invalid_trajectory_request",
                        "message": "Trajectory must be a non-empty object.",
                    },
                )
            return service.upload_trajectory(
                tenant_id=tenant_id,
                agent_id=agent_id,
                trajectory=trajectory,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_trajectory_request", "message": f"Missing field: {exc.args[0]}"},
            ) from exc
        except ValueError as exc:
            message = str(exc)
            raise HTTPException(
                status_code=lookup_status_code(message),
                detail={"error_code": "trajectory_upload_failed", "message": message},
            ) from exc

    return app
