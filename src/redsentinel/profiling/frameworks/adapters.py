from __future__ import annotations

from collections.abc import Iterable

from redsentinel.profiling.frameworks.base import (
    FragmentBuilder,
    FrameworkAdapter,
    _framework_evidence,
    index_evidence,
)
from redsentinel.profiling.frameworks.models import FrameworkCandidate, GraphFragment
from redsentinel.profiling.static_facts import (
    CallFact,
    EvidencedFact,
    StaticFactIndex,
)


def _tail(value: str) -> str:
    return value.rsplit(".", 1)[-1]


def _container_items(value: str | None) -> tuple[str, ...]:
    if not value or not value.startswith("[") or not value.endswith("]"):
        return ()
    return tuple(item for item in value[1:-1].split(",") if item)


def _mapping_items(value: str | None) -> tuple[tuple[str, str], ...]:
    if not value or not value.startswith("{") or not value.endswith("}"):
        return ()
    pairs = []
    for item in value[1:-1].split(","):
        key, separator, target = item.partition(":")
        if separator and key and target:
            pairs.append((key, target))
    return tuple(pairs)


def _argument(call: CallFact, position: int) -> str | None:
    return call.positional_arguments[position] if len(call.positional_arguments) > position else None


def _keyword(call: CallFact, name: str) -> str | None:
    return dict(call.keyword_arguments).get(name)


def _graph_evidence(
    adapter: FrameworkAdapter,
    detection_evidence: tuple,
    facts: Iterable[EvidencedFact],
) -> tuple:
    converted = _framework_evidence(adapter.framework_id, (fact.evidence for fact in facts))
    return tuple({item.evidence_id: item for item in (*detection_evidence, *converted)}[key] for key in sorted(
        {item.evidence_id: item for item in (*detection_evidence, *converted)}
    ))


def _calls(index: StaticFactIndex, names: set[str]) -> list[CallFact]:
    return [call for call in index.calls if _tail(call.callee) in names]


def _owner_node(builder: FragmentBuilder, call: CallFact, node_type: str = "agent") -> str:
    return builder.add_node(
        module=call.module,
        identity=call.caller,
        name=call.caller,
        node_type=node_type,  # type: ignore[arg-type]
        facts=[call],
    )


class LangGraphAdapter(FrameworkAdapter):
    framework_id = "langgraph"
    name = "LangGraph"
    fingerprints = (
        ("dependency", ("langgraph",), 0.5),
        ("import", ("langgraph",), 0.4),
        (
            "call",
            (
                "StateGraph",
                "add_node",
                "add_edge",
                "add_conditional_edges",
                "set_entry_point",
                "set_conditional_entry_point",
                "compile",
            ),
            0.25,
        ),
    )

    def _build_graph(self, index, candidate, evidence) -> GraphFragment:
        calls = _calls(
            index,
            {
                "StateGraph",
                "add_node",
                "add_edge",
                "add_conditional_edges",
                "set_entry_point",
                "set_conditional_entry_point",
                "compile",
            },
        )
        builder = FragmentBuilder(self, candidate, _graph_evidence(self, evidence, calls))
        for call in calls:
            owner = _owner_node(builder, call)
            method = _tail(call.callee)
            if method in {"StateGraph", "compile"}:
                continue
            if method == "add_node":
                label = _argument(call, 0) or _argument(call, 1) or f"node@{call.line}"
                target = builder.add_node(
                    module=call.module,
                    identity=label,
                    name=label,
                    node_type="agent",
                    facts=[call],
                )
                builder.add_edge(owner, target, "calls", [call])
                continue
            if method == "add_edge":
                source_name = _argument(call, 0) or f"source@{call.line}"
                target_name = _argument(call, 1) or f"target@{call.line}"
                source = self._named_node(builder, call, source_name)
                target = self._named_node(builder, call, target_name)
                builder.add_edge(source, target, "routes_to", [call])
                continue
            if method == "add_conditional_edges":
                source_name = _argument(call, 0) or f"source@{call.line}"
                route_name = _argument(call, 1) or f"condition@{call.line}"
                source = self._named_node(builder, call, source_name)
                router = builder.add_node(
                    module=call.module,
                    identity=route_name,
                    name=route_name,
                    node_type="router",
                    facts=[call],
                )
                builder.add_edge(source, router, "routes_to", [call], condition=route_name)
                mapping = _argument(call, 2) or _keyword(call, "path_map")
                for condition, target_name in _mapping_items(mapping):
                    target = self._named_node(builder, call, target_name)
                    builder.add_edge(router, target, "routes_to", [call], condition=condition)
                continue
            target_name = _argument(call, 0) or f"entry@{call.line}"
            entry = builder.add_node(
                module=call.module,
                identity=f"entry:{call.caller}",
                name=f"{call.caller} entry",
                node_type="entrypoint",
                facts=[call],
            )
            target = self._named_node(builder, call, target_name)
            condition = _argument(call, 1) if method == "set_conditional_entry_point" else None
            builder.add_edge(entry, target, "routes_to", [call], condition=condition)
        return builder.build()

    @staticmethod
    def _named_node(builder: FragmentBuilder, call: CallFact, name: str) -> str:
        normalized = _tail(name)
        node_type = "entrypoint" if normalized in {"START", "__start__"} else "router" if normalized in {
            "END",
            "__end__",
        } else "agent"
        return builder.add_node(
            module=call.module,
            identity=name,
            name=name,
            node_type=node_type,
            facts=[call],
        )


class LangChainAdapter(FrameworkAdapter):
    framework_id = "langchain"
    name = "LangChain"
    fingerprints = (
        (
            "dependency",
            ("langchain", "langchain-core", "langchain-community", "langchain-openai"),
            0.5,
        ),
        ("import", ("langchain", "langchain_core", "langchain_community", "langchain_openai"), 0.4),
        ("decorator", ("tool",), 0.25),
        ("base", ("BaseTool", "Tool"), 0.25),
        ("call", ("Tool", "AgentExecutor", "bind_tools"), 0.25),
    )

    def _build_graph(self, index, candidate, evidence) -> GraphFragment:
        facts: list[EvidencedFact] = [
            *index.imports,
            *index.decorators,
            *index.class_bases,
            *index.calls,
            *index.capabilities,
        ]
        builder = FragmentBuilder(self, candidate, _graph_evidence(self, evidence, facts))
        tools: dict[str, str] = {}
        for decorator in index.decorators:
            if _tail(decorator.decorator) == "tool":
                tools[_tail(decorator.symbol)] = builder.add_node(
                    module=decorator.module,
                    identity=decorator.symbol,
                    name=decorator.symbol,
                    node_type="tool",
                    facts=[decorator],
                    risk_level="medium",
                )
        for base in index.class_bases:
            if _tail(base.base) in {"BaseTool", "Tool"}:
                tools[_tail(base.class_name)] = builder.add_node(
                    module=base.module,
                    identity=base.class_name,
                    name=base.class_name,
                    node_type="tool",
                    facts=[base],
                    risk_level="medium",
                )
        for item in index.imports:
            imported_name = item.imported_name or _tail(item.imported_module)
            if any(token in imported_name.lower() for token in ("prompt", "messageplaceholder")):
                builder.add_node(
                    module=item.module,
                    identity=imported_name,
                    name=imported_name,
                    node_type="prompt",
                    facts=[item],
                )
            elif any(token in imported_name.lower() for token in ("memory", "history")):
                builder.add_node(
                    module=item.module,
                    identity=imported_name,
                    name=imported_name,
                    node_type="memory",
                    facts=[item],
                    risk_level="medium",
                )
            elif any(token in imported_name.lower() for token in ("retriever", "retrieval", "vectorstore")):
                builder.add_node(
                    module=item.module,
                    identity=imported_name,
                    name=imported_name,
                    node_type="rag",
                    facts=[item],
                    risk_level="medium",
                )
            elif imported_name.startswith(("Chat", "OpenAI", "Anthropic", "Bedrock", "Ollama")):
                builder.add_node(
                    module=item.module,
                    identity=imported_name,
                    name=imported_name,
                    node_type="llm",
                    facts=[item],
                )
        for call in index.calls:
            method = _tail(call.callee)
            if method == "Tool":
                name = _argument(call, 0) or f"tool@{call.line}"
                tools[_tail(name)] = builder.add_node(
                    module=call.module,
                    identity=name,
                    name=name,
                    node_type="tool",
                    facts=[call],
                    risk_level="medium",
                )
            elif method == "bind_tools":
                model_name = call.callee.rsplit(".", 1)[0]
                llm = builder.add_node(
                    module=call.module,
                    identity=model_name,
                    name=model_name,
                    node_type="llm",
                    facts=[call],
                )
                for tool_name in _container_items(_argument(call, 0)):
                    tool = tools.get(_tail(tool_name)) or builder.add_node(
                        module=call.module,
                        identity=tool_name,
                        name=tool_name,
                        node_type="tool",
                        facts=[call],
                        risk_level="medium",
                    )
                    builder.add_edge(llm, tool, "invokes", [call])
            elif method == "AgentExecutor":
                agent = builder.add_node(
                    module=call.module,
                    identity=call.caller,
                    name=call.caller,
                    node_type="agent",
                    facts=[call],
                )
                for tool_name in _container_items(_keyword(call, "tools") or _argument(call, 1)):
                    tool = tools.get(_tail(tool_name)) or builder.add_node(
                        module=call.module,
                        identity=tool_name,
                        name=tool_name,
                        node_type="tool",
                        facts=[call],
                        risk_level="medium",
                    )
                    builder.add_edge(agent, tool, "invokes", [call])
            elif method in {"as_retriever", "get_relevant_documents", "invoke"} and "retriev" in call.callee.lower():
                rag = builder.add_node(
                    module=call.module,
                    identity=call.callee.rsplit(".", 1)[0],
                    name=call.callee.rsplit(".", 1)[0],
                    node_type="rag",
                    facts=[call],
                    risk_level="medium",
                )
                builder.add_edge(_owner_node(builder, call), rag, "retrieves", [call])
        return builder.build()


class OpenManusAdapter(FrameworkAdapter):
    framework_id = "openmanus"
    name = "OpenManus"
    fingerprints = (
        ("dependency", ("openmanus",), 0.55),
        ("module", ("app.agent", "app.tool", "app.flow", "app.mcp"), 0.3),
        ("import", ("app.agent", "app.tool", "app.flow", "app.mcp"), 0.35),
        (
            "base",
            ("BaseAgent", "ReActAgent", "ToolCallAgent", "BaseTool", "PlanningFlow"),
            0.3,
        ),
        ("call", ("ToolCollection", "PlanningFlow", "AskHuman", "MCPClients"), 0.25),
    )

    def _build_graph(self, index, candidate, evidence) -> GraphFragment:
        facts: list[EvidencedFact] = [*index.class_bases, *index.calls, *index.imports, *index.capabilities]
        builder = FragmentBuilder(self, candidate, _graph_evidence(self, evidence, facts))
        for base in index.class_bases:
            base_name = _tail(base.base)
            if "Agent" in base_name:
                node_type = "agent" if _tail(base.class_name) in {"Manus", "Agent"} else "sub_agent"
                builder.add_node(
                    module=base.module,
                    identity=base.class_name,
                    name=base.class_name,
                    node_type=node_type,
                    facts=[base],
                )
            elif base_name == "BaseTool":
                risk = "high" if any(token in base.class_name.lower() for token in ("bash", "browser", "file", "python")) else "medium"
                builder.add_node(
                    module=base.module,
                    identity=base.class_name,
                    name=base.class_name,
                    node_type="tool",
                    facts=[base],
                    risk_level=risk,
                )
        for call in index.calls:
            method = _tail(call.callee)
            if method == "ToolCollection":
                owner = _owner_node(builder, call)
                for tool_name in call.positional_arguments:
                    if tool_name is None:
                        continue
                    tool_type = "approval" if _tail(tool_name) == "AskHuman" else "mcp" if "MCP" in tool_name else "tool"
                    risk = "high" if tool_type in {"tool", "mcp"} else "low"
                    tool = builder.add_node(
                        module=call.module,
                        identity=tool_name,
                        name=tool_name,
                        node_type=tool_type,
                        facts=[call],
                        risk_level=risk,
                    )
                    builder.add_edge(owner, tool, "invokes", [call])
            elif method == "AskHuman":
                approval = builder.add_node(
                    module=call.module,
                    identity=f"AskHuman@{call.line}",
                    name="AskHuman",
                    node_type="approval",
                    facts=[call],
                )
                builder.add_edge(_owner_node(builder, call), approval, "controls", [call])
            elif method in {"MCPClients", "FastMCP", "ClientSession"}:
                mcp = builder.add_node(
                    module=call.module,
                    identity=call.callee,
                    name=call.callee,
                    node_type="mcp",
                    facts=[call],
                    risk_level="high",
                )
                builder.add_edge(_owner_node(builder, call), mcp, "invokes", [call])
            elif method == "PlanningFlow":
                flow = builder.add_node(
                    module=call.module,
                    identity="PlanningFlow",
                    name="PlanningFlow",
                    node_type="router",
                    facts=[call],
                )
                builder.add_edge(_owner_node(builder, call), flow, "routes_to", [call])
        for capability in index.capabilities:
            if capability.capability == "model":
                llm = builder.add_node(
                    module=capability.module or "openmanus",
                    identity=capability.provider,
                    name=capability.provider,
                    node_type="llm",
                    facts=[capability],
                )
                if capability.symbol:
                    owner = builder.add_node(
                        module=capability.module or "openmanus",
                        identity=capability.symbol,
                        name=capability.symbol,
                        node_type="agent",
                        facts=[capability],
                    )
                    builder.add_edge(owner, llm, "calls", [capability])
        return builder.build()


class BasicFingerprintAdapter(FrameworkAdapter):
    node_type = "agent"
    risk_level = "low"

    def _build_graph(self, index, candidate, evidence) -> GraphFragment:
        matching_calls = [
            call
            for call in index.calls
            if any(
                token.lower() in call.callee.lower()
                for kind, tokens, _ in self.fingerprints
                if kind == "call"
                for token in tokens
            )
        ]
        builder = FragmentBuilder(self, candidate, _graph_evidence(self, evidence, matching_calls))
        for call in matching_calls:
            builder.add_node(
                module=call.module,
                identity=call.callee,
                name=call.callee,
                node_type=self.node_type,  # type: ignore[arg-type]
                facts=[call],
                risk_level=self.risk_level,  # type: ignore[arg-type]
            )
        builder.limitation(
            "framework_adapter_shallow",
            f"{self.name} is fingerprinted, but only candidate framework nodes are reconstructed",
            matching_calls,
        )
        return builder.build()


class CrewAIAdapter(BasicFingerprintAdapter):
    framework_id = "crewai"
    name = "CrewAI"
    fingerprints = (
        ("dependency", ("crewai",), 0.55),
        ("import", ("crewai",), 0.4),
        ("call", ("Crew", "Agent", "Task"), 0.2),
    )


class AutoGenAdapter(BasicFingerprintAdapter):
    framework_id = "autogen"
    name = "AutoGen"
    fingerprints = (
        ("dependency", ("autogen", "pyautogen", "autogen-agentchat"), 0.55),
        ("import", ("autogen", "autogen_agentchat"), 0.4),
        ("call", ("AssistantAgent", "UserProxyAgent", "GroupChat"), 0.2),
    )


class MCPAdapter(BasicFingerprintAdapter):
    framework_id = "mcp"
    name = "MCP"
    node_type = "mcp"
    risk_level = "high"
    fingerprints = (
        ("dependency", ("mcp",), 0.55),
        ("import", ("mcp",), 0.4),
        ("call", ("FastMCP", "ClientSession", "stdio_client", "sse_client"), 0.25),
    )


class CustomFrameworkAdapter(FrameworkAdapter):
    framework_id = "custom"
    name = "Custom Python"
    threshold = 0.0

    def detect(self, index: StaticFactIndex):
        facts: list[EvidencedFact] = [
            *index.entrypoints,
            *index.class_bases,
            *index.symbols,
            *index.modules,
            *index.limitations,
        ]
        evidence = _framework_evidence(self.framework_id, (fact.evidence for fact in facts))
        if not evidence:
            evidence = (
                index_evidence(index, self.framework_id, "No supported framework fingerprint was present"),
            )
        candidate = FrameworkCandidate(
            framework_id=self.framework_id,
            name=self.name,
            confidence=0.5,
            evidence_refs=tuple(item.evidence_id for item in evidence),
            signals=("fallback",),
            selected=True,
        )
        return candidate, evidence

    def _build_graph(self, index, candidate, evidence) -> GraphFragment:
        facts: list[EvidencedFact] = [*index.entrypoints, *index.class_bases]
        builder = FragmentBuilder(self, candidate, _graph_evidence(self, evidence, facts))
        for entrypoint in index.entrypoints:
            identity = entrypoint.module or entrypoint.name
            builder.add_node(
                module=entrypoint.module or "<image>",
                identity=f"entry:{identity}",
                name=entrypoint.name,
                node_type="entrypoint",
                facts=[entrypoint],
            )
        for base in index.class_bases:
            if "agent" in base.base.lower() or "agent" in base.class_name.lower():
                builder.add_node(
                    module=base.module,
                    identity=base.class_name,
                    name=base.class_name,
                    node_type="agent",
                    facts=[base],
                )
        builder.limitation(
            "unsupported_framework",
            "No supported framework reached its detection threshold; custom Python fallback applied",
            facts,
        )
        return builder.build()


DEFAULT_ADAPTERS = (
    LangGraphAdapter(),
    LangChainAdapter(),
    OpenManusAdapter(),
    CrewAIAdapter(),
    AutoGenAdapter(),
    MCPAdapter(),
)


__all__ = [
    "AutoGenAdapter",
    "BasicFingerprintAdapter",
    "CrewAIAdapter",
    "CustomFrameworkAdapter",
    "DEFAULT_ADAPTERS",
    "LangChainAdapter",
    "LangGraphAdapter",
    "MCPAdapter",
    "OpenManusAdapter",
]
