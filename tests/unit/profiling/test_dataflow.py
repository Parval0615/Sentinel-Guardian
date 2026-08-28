from __future__ import annotations

from pathlib import Path

import pytest

from redsentinel.profiling import analyze_dataflow, extract_static_facts
from redsentinel.profiling.dataflow import SINK_RULES, SOURCE_CALLS


def _analyze(tmp_path: Path, files: dict[str, str], *, max_call_depth: int = 3):
    root = tmp_path / "rootfs"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    index = extract_static_facts(root)
    return analyze_dataflow(index, root, max_call_depth=max_call_depth)


def _paths_for(result, threat: str):
    return [path for path in result.risk_paths if threat in path.applicable_threats]


def test_catalog_covers_required_source_and_sink_classes() -> None:
    assert set(SOURCE_CALLS) == {
        "user",
        "http",
        "cli",
        "message",
        "retrieval",
        "tool_result",
        "memory",
        "network",
    }
    assert {rule.sink_type for rule in SINK_RULES} == {
        "llm_prompt",
        "shell",
        "file",
        "browser",
        "api",
        "database",
        "memory",
        "credential",
        "tool",
    }


def test_annotation_without_value_does_not_abort_analysis(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "app.py": """
def run(user_input):
    pending: str
    return subprocess.run(user_input)
"""
        },
    )

    assert _paths_for(result, "command_injection")


def test_direct_prompt_injection_emits_supported_ordered_path(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "app.py": """
def chat(user_input):
    prompt = "Answer: " + user_input
    return llm.invoke(prompt)
"""
        },
    )

    path = _paths_for(result, "direct_prompt_injection")[0]
    source = next(item for item in result.sources if item.node_id == path.source_node_id)
    sink = next(item for item in result.sinks if item.node_id == path.sink_node_id)

    assert source.source_type == "user"
    assert sink.sink_type == "llm_prompt"
    assert path.verification_status == "supported"
    assert path.confidence >= 0.65
    assert path.control_gaps == ["missing_input_guard"]
    assert len(path.edge_ids) == len(path.node_ids) - 1
    assert all(item.verification_status != "verified" for item in result.risk_paths)


def test_three_level_project_call_propagation_reaches_shell(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "app.py": """
def execute(value):
    return subprocess.run(value, shell=True)

def dispatch(value):
    return execute(value)

@app.post("/run")
def endpoint(request):
    command = request.json()
    return dispatch(command)
"""
        },
    )

    paths = _paths_for(result, "command_injection")
    http_path = next(
        path
        for path in paths
        if next(item for item in result.sources if item.node_id == path.source_node_id).source_type == "http"
    )
    names = [next(item.name for item in result.nodes if item.node_id == node_id) for node_id in http_path.node_ids]

    assert names[0].startswith("http ")
    assert "call dispatch" in names
    assert "call execute" in names
    assert names[-1].startswith("shell sink")
    assert http_path.risk_level == "critical"


def test_repeated_calls_to_same_local_function_share_one_graph_node(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        {
            "app.py": """
def execute(value):
    return subprocess.run(value, shell=True)

def first(user_input):
    return execute(user_input)

def second(user_input):
    return execute(user_input)
"""
        },
    )

    matches = [node for node in result.nodes if node.name == "call execute"]

    assert len(matches) == 1
    assert {item.permission_type for item in result.permissions} >= {"shell"}


def test_import_aliases_are_normalized_for_sink_and_cross_module_calls(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "helpers.py": """
import subprocess as process

def execute(value):
    return process.run(value)
""",
            "app.py": """
from helpers import execute as dispatch

def handle(user_input):
    return dispatch(user_input)
""",
        },
    )

    path = _paths_for(result, "command_injection")[0]
    names = [next(item.name for item in result.nodes if item.node_id == node_id) for node_id in path.node_ids]

    assert "call execute" in names
    assert names[-1] == "shell sink subprocess.run"


def test_tools_module_call_is_a_tool_sink(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "shop/tools.py": """
def product_search(query):
    return {"query": query}
""",
            "shop/agent.py": """
from shop import tools

def route(message):
    return tools.product_search(message)
""",
        },
    )

    path = _paths_for(result, "tool_argument_injection")[0]
    sink = next(item for item in result.sinks if item.node_id == path.sink_node_id)

    assert sink.sink_type == "tool"
    assert sink.expression == "shop.tools.product_search"
    assert path.control_gaps == ["missing_parameter_validation", "missing_authorization"]


def test_indirect_prompt_injection_from_retrieval_tool_memory_and_network(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "agent.py": """
def from_rag(query):
    context = retriever.invoke(query)
    return llm.invoke(context)

def from_tool(query):
    observation = call_tool(query)
    return model.invoke(observation)

def from_memory(query):
    recalled = memory.load(query)
    return chat.invoke(recalled)

def from_network(url):
    remote_content = requests.get(url)
    return llm.invoke(remote_content)
"""
        },
    )

    paths = _paths_for(result, "indirect_prompt_injection")
    source_types = {
        next(item for item in result.sources if item.node_id == path.source_node_id).source_type for path in paths
    }

    assert source_types >= {"retrieval", "tool_result", "memory", "network"}
    assert all(path.verification_status == "supported" for path in paths)


def test_rag_and_memory_poisoning_are_distinguished(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "ingest.py": """
@app.post("/documents")
def ingest(request):
    documents = request.json()
    vectorstore.add_documents(documents)

def remember(message):
    memory.save(message)
"""
        },
    )

    rag_path = _paths_for(result, "rag_poisoning")[0]
    memory_path = _paths_for(result, "memory_poisoning")[0]

    assert rag_path.sink_node_id != memory_path.sink_node_id
    assert rag_path.risk_level == "high"
    assert memory_path.risk_level == "high"
    assert all("missing_input_guard" in path.control_gaps for path in (rag_path, memory_path))


def test_controls_are_attached_and_normalization_remains_weak(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "controlled.py": """
ALLOWED = {"status", "version"}

@require_role("operator")
def run(command):
    normalized = command.strip()
    if normalized in ALLOWED:
        approved = human_approval(normalized)
        if approved:
            subprocess.run(normalized)
"""
        },
    )

    path = _paths_for(result, "command_injection")[0]
    control_types = {item.control_type for item in result.controls if item.control_id in path.control_ids}

    assert control_types == {"allowlist", "authorization", "human_approval"}
    assert result.weak_controls
    assert "normalization_only_does_not_establish_trust" in path.control_gaps
    assert "missing_allowlist" not in path.control_gaps
    assert "missing_human_approval" not in path.control_gaps
    assert "missing_parameter_validation" in path.control_gaps
    assert path.risk_level == "high"


def test_parameter_validation_and_guards_are_recognized(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "guards.py": """
def execute(user_input):
    checked = validate_input(user_input)
    guarded = input_guard(checked)
    answer = llm.invoke(guarded)
    return output_guard(answer)
"""
        },
    )

    path = _paths_for(result, "direct_prompt_injection")[0]

    assert {item.control_type for item in result.controls} >= {
        "parameter_validation",
        "input_guard",
        "output_guard",
    }
    assert {item.control_type for item in result.controls if item.control_id in path.control_ids} == {
        "parameter_validation",
        "input_guard",
    }
    assert path.control_gaps == []
    assert path.risk_level == "medium"


def test_incomplete_source_degrades_to_inferred_unresolved_flow(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "broken.py": """
def handle(user_input):
    subprocess.run(user_input
"""
        },
    )

    assert result.source_recovery == "partial"
    assert result.risk_paths == []
    assert result.unresolved_flows
    assert {item.reason for item in result.unresolved_flows} == {"parse_error"}
    assert all(item.verification_status == "inferred" for item in result.unresolved_flows)
    assert "dataflow_unresolved" in {item.code for item in result.limitations}
    assert all(item.verification_status != "verified" for item in result.nodes)


def test_depth_limit_records_inferred_unresolved_without_inventing_sink(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        {
            "deep.py": """
def fourth(value):
    return subprocess.run(value)

def third(value):
    return fourth(value)

def second(value):
    return third(value)

def first(user_input):
    return second(user_input)
"""
        },
        max_call_depth=2,
    )

    assert any(item.reason == "call_depth_exceeded" for item in result.unresolved_flows)
    assert not any(
        path.source_node_id == next(source.node_id for source in result.sources if source.symbol == "first")
        for path in result.risk_paths
    )


@pytest.mark.parametrize("depth", [0, 4])
def test_call_depth_is_bounded(depth: int, tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "app.py").write_text("def run(user_input):\n    return user_input\n", encoding="utf-8")
    index = extract_static_facts(root)

    with pytest.raises(ValueError, match="between 1 and 3"):
        analyze_dataflow(index, root, max_call_depth=depth)
