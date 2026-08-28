from __future__ import annotations

from dataclasses import dataclass

from redsentinel.core.image_profile_graph import (
    ControlType,
    PermissionType,
    ProfileNodeType,
    ProfileRiskLevel,
)
from redsentinel.profiling.dataflow.models import SinkType, SourceType


@dataclass(frozen=True)
class SinkRule:
    sink_type: SinkType
    names: tuple[str, ...]
    node_type: ProfileNodeType
    operation: str
    risk_level: ProfileRiskLevel
    permission_type: PermissionType | None


SOURCE_CALLS: dict[SourceType, tuple[str, ...]] = {
    "user": ("input", "read_user_input", "get_user_input"),
    "http": (
        "request.json",
        "request.get_json",
        "request.form",
        "request.body",
        "request.query_params",
    ),
    "cli": ("argparse.parse_args", "parser.parse_args", "click.prompt"),
    "message": ("receive_message", "get_message", "message.content", "event.text"),
    "retrieval": (
        "retrieve",
        "retriever.invoke",
        "retriever.get_relevant_documents",
        "similarity_search",
        "vectorstore.similarity_search",
        "knowledge_base.search",
    ),
    "tool_result": ("tool.invoke", "tool.run", "call_tool", "execute_tool"),
    "memory": ("memory.get", "memory.load", "memory.search", "memory.recall", "recall"),
    "network": (
        "requests.get",
        "requests.request",
        "httpx.get",
        "httpx.request",
        "urllib.request.urlopen",
        "response.json",
        "response.text",
    ),
}

SINK_RULES: tuple[SinkRule, ...] = (
    SinkRule(
        "llm_prompt",
        (
            "llm.invoke",
            "llm.generate",
            "llm.predict",
            "model.invoke",
            "model.generate",
            "chat.invoke",
            "client.chat.completions.create",
            "chat.completions.create",
            "openai.chat.completions.create",
        ),
        "llm",
        "prompt",
        "high",
        None,
    ),
    SinkRule(
        "shell",
        (
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "os.system",
            "os.popen",
            "eval",
            "exec",
        ),
        "shell",
        "execute",
        "critical",
        "shell",
    ),
    SinkRule(
        "file",
        (
            "open",
            "Path.open",
            "Path.write_text",
            "Path.write_bytes",
            "write_text",
            "write_bytes",
            "shutil.copy",
            "shutil.move",
            "shutil.rmtree",
        ),
        "file",
        "read_or_write",
        "high",
        "file",
    ),
    SinkRule(
        "browser",
        (
            "page.goto",
            "page.fill",
            "page.evaluate",
            "browser.open",
            "driver.get",
            "webdriver.get",
        ),
        "browser",
        "automate",
        "high",
        "browser",
    ),
    SinkRule(
        "api",
        (
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.patch",
            "httpx.delete",
            "httpx.request",
            "client.request",
        ),
        "external_api",
        "request",
        "high",
        "external_api",
    ),
    SinkRule(
        "database",
        (
            "cursor.execute",
            "connection.execute",
            "session.execute",
            "db.execute",
            "database.execute",
            "collection.insert_one",
            "collection.update_one",
            "collection.delete_one",
        ),
        "database",
        "query_or_mutate",
        "high",
        "database",
    ),
    SinkRule(
        "memory",
        (
            "memory.add",
            "memory.save",
            "memory.put",
            "memory.store",
            "memory.update",
            "vectorstore.add",
            "vectorstore.add_texts",
            "vectorstore.add_documents",
            "knowledge_base.add",
            "knowledge_base.upsert",
        ),
        "memory",
        "persist",
        "high",
        "database",
    ),
    SinkRule(
        "credential",
        (
            "set_api_key",
            "set_token",
            "set_credentials",
            "credentials.update",
            "auth.configure",
            "session.headers.update",
        ),
        "tool",
        "configure_credential",
        "critical",
        "credential",
    ),
    SinkRule(
        "tool",
        ("tool.invoke", "tool.run", "call_tool", "execute_tool", "tools.invoke"),
        "tool",
        "invoke",
        "high",
        None,
    ),
)

CONTROL_CALLS: dict[ControlType, tuple[str, ...]] = {
    "parameter_validation": (
        "validate",
        "validate_input",
        "validate_parameters",
        "model_validate",
        "is_valid",
        "check_schema",
    ),
    "allowlist": ("is_allowed", "check_allowlist", "allowlisted", "allowed_command", "allowed_url"),
    "authorization": (
        "authorize",
        "authorized",
        "check_permission",
        "has_permission",
        "require_permission",
        "require_role",
        "check_access",
    ),
    "human_approval": ("approve", "approved", "human_approval", "human_review", "confirm_action"),
    "input_guard": ("input_guard", "guard_input", "sanitize_prompt", "moderate_input", "prompt_guard"),
    "output_guard": ("output_guard", "guard_output", "filter_output", "moderate_output"),
}

NORMALIZATION_CALLS: tuple[str, ...] = (
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "casefold",
    "normalize",
    "canonicalize",
    "json.loads",
    "urllib.parse.unquote",
    "url_decode",
    "parse",
)

SOURCE_PARAMETER_KEYWORDS: dict[SourceType, tuple[str, ...]] = {
    "http": ("request", "http_request", "body", "form", "query_param"),
    "cli": ("argv", "cli_arg", "command_line"),
    "message": ("message", "event", "chat_message"),
    "retrieval": ("retrieved", "documents", "docs", "context"),
    "tool_result": ("tool_result", "tool_output", "observation"),
    "memory": ("memory_value", "memory_entry", "recalled"),
    "network": ("response", "network_data", "remote_content"),
    "user": ("user_input", "user_text", "prompt", "query", "input_text", "command"),
}

HTTP_DECORATORS: tuple[str, ...] = (
    "app.get",
    "app.post",
    "app.put",
    "app.patch",
    "app.delete",
    "router.get",
    "router.post",
    "router.put",
    "router.patch",
    "router.delete",
    "route",
)

AUTH_DECORATOR_KEYWORDS: tuple[str, ...] = ("auth", "permission", "role", "login_required")

__all__ = [
    "AUTH_DECORATOR_KEYWORDS",
    "CONTROL_CALLS",
    "HTTP_DECORATORS",
    "NORMALIZATION_CALLS",
    "SINK_RULES",
    "SOURCE_CALLS",
    "SOURCE_PARAMETER_KEYWORDS",
    "SinkRule",
]
