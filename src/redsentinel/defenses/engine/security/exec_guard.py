from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ExecDecisionValue = Literal["allow", "deny", "ask"]

_DANGEROUS_CODE_PATTERNS = (
    "rm -rf",
    "format c:",
    "del /s",
    "shutdown",
    "curl http",
    "wget http",
    "os.system",
    "subprocess",
    "socket.",
    "requests.post",
)


class CodeExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    language: str = "python"
    entrypoint: str | None = None
    working_dir: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecGuardDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ExecDecisionValue
    allowed: bool
    reason: str = Field(min_length=1)
    risk_level: str
    sandbox_required: bool = True
    artifact_plan: dict[str, Any] = Field(default_factory=dict)
    audit_payload: dict[str, str] = Field(default_factory=dict)


def evaluate_code_execution(
    request: CodeExecutionRequest,
    *,
    workspace_root: str | None = None,
) -> ExecGuardDecision:
    lowered = request.code.lower()
    matched = [pattern for pattern in _DANGEROUS_CODE_PATTERNS if pattern in lowered]
    if matched:
        return _decision(
            request,
            "deny",
            f"Code execution denied because it matched dangerous patterns: {', '.join(matched[:3])}.",
            "critical",
            workspace_root=workspace_root,
        )

    if _is_safe_arithmetic(request.code):
        return _decision(
            request,
            "allow",
            "Code execution is limited to allowlisted arithmetic.",
            "low",
            workspace_root=workspace_root,
        )

    if _is_safe_arithmetic(request.code):
        return _decision(
            request,
            "allow",
            "Code execution is limited to allowlisted arithmetic.",
            "low",
            workspace_root=workspace_root,
        )

    if _is_safe_arithmetic(request.code):
        return _decision(
            request,
            "allow",
            "Code execution is limited to allowlisted arithmetic.",
            "low",
            workspace_root=workspace_root,
        )

    if _is_safe_arithmetic(request.code):
        return _decision(
            request,
            "allow",
            "Code execution is limited to allowlisted arithmetic.",
            "low",
            workspace_root=workspace_root,
        )

    return _decision(
        request,
        "ask",
        "Code execution requires supervisor confirmation and Docker sandbox isolation.",
        "high",
        workspace_root=workspace_root,
    )


def _is_safe_arithmetic(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    allowed_nodes = (
        ast.Module,
        ast.Expr,
        ast.Call,
        ast.Name,
        ast.Load,
        ast.Constant,
        ast.BinOp,
        ast.UnaryOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.UAdd,
        ast.USub,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            return False
        if isinstance(node, ast.Call) and (
            not isinstance(node.func, ast.Name)
            or node.func.id != "print"
            or node.keywords
        ):
            return False
        if isinstance(node, ast.Name) and node.id != "print":
            return False
        if isinstance(node, ast.Constant) and (
            isinstance(node.value, bool)
            or not isinstance(node.value, (int, float))
        ):
            return False
    return bool(tree.body)


def _decision(
    request: CodeExecutionRequest,
    decision: ExecDecisionValue,
    reason: str,
    risk_level: str,
    *,
    workspace_root: str | None,
) -> ExecGuardDecision:
    code_hash = hashlib.sha256(request.code.encode("utf-8")).hexdigest()
    artifact_plan = {
        "sandbox": "docker",
        "language": request.language,
        "entrypoint": request.entrypoint,
        "working_dir": _resolve_working_dir(request.working_dir, workspace_root),
        "expected_artifacts": ["stdout", "stderr", "trajectory", "audit"],
        "code_sha256": code_hash,
    }
    return ExecGuardDecision(
        decision=decision,
        allowed=decision == "allow",
        reason=reason,
        risk_level=risk_level,
        sandbox_required=True,
        artifact_plan=artifact_plan,
        audit_payload={
            "user_id": "exec_guard",
            "role": "system",
            "operation": "code_execution_guard",
            "input_content": f"language={request.language}; sha256={code_hash}",
            "result": f"{decision}: {reason}",
            "risk_level": risk_level,
        },
    )


def _resolve_working_dir(working_dir: str | None, workspace_root: str | None) -> str | None:
    if working_dir is None:
        return None
    path = Path(working_dir)
    if path.is_absolute() or workspace_root is None:
        return str(path)
    return str((Path(workspace_root) / path).resolve())


__all__ = [
    "CodeExecutionRequest",
    "ExecGuardDecision",
    "evaluate_code_execution",
]
