from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from redsentinel.core.image_profile_graph import (
    AnalysisLimitation,
    ControlType,
    ProfileCapability,
    ProfileEdge,
    ProfileNode,
    ProfilePermission,
    ProfileRiskPath,
    ProfileRiskLevel,
    SecurityControl,
)
from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence
from redsentinel.profiling.dataflow.catalog import (
    AUTH_DECORATOR_KEYWORDS,
    CONTROL_CALLS,
    HTTP_DECORATORS,
    NORMALIZATION_CALLS,
    SINK_RULES,
    SOURCE_CALLS,
    SOURCE_PARAMETER_KEYWORDS,
    SinkRule,
)
from redsentinel.profiling.dataflow.models import (
    DataflowAnalysisResult,
    DataflowSink,
    DataflowSource,
    SinkType,
    SourceType,
    UnresolvedFlow,
    WeakControlFact,
)
from redsentinel.profiling.static_facts import StaticFactIndex


@dataclass(frozen=True)
class _FileContext:
    module: str
    image_path: str
    path: Path
    content_sha256: str
    layer_digest: str | None


@dataclass(frozen=True)
class _Function:
    module: str
    qualified_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: _FileContext
    decorators: tuple[str, ...]

    @property
    def parameters(self) -> tuple[str, ...]:
        args = [*self.node.args.posonlyargs, *self.node.args.args, *self.node.args.kwonlyargs]
        if self.node.args.vararg:
            args.append(self.node.args.vararg)
        if self.node.args.kwarg:
            args.append(self.node.args.kwarg)
        return tuple(item.arg for item in args if item.arg not in {"self", "cls"})


@dataclass(frozen=True)
class _Event:
    event_id: str
    kind: str
    name: str
    module: str
    symbol: str
    expression: str
    line: int
    evidence_id: str
    node_type: str
    source_type: SourceType | None = None
    sink_type: SinkType | None = None
    control_type: ControlType | None = None
    node_module: str | None = None
    node_identity: str | None = None


@dataclass(frozen=True)
class _Trace:
    source: _Event
    hops: tuple[_Event, ...] = ()
    controls: tuple[_Event, ...] = ()
    weak_controls: tuple[_Event, ...] = ()

    def with_hop(self, event: _Event) -> _Trace:
        if self.hops and self.hops[-1].event_id == event.event_id:
            return self
        return replace(self, hops=(*self.hops, event))

    def with_control(self, event: _Event) -> _Trace:
        if any(item.event_id == event.event_id for item in self.controls):
            return self
        return replace(self, controls=(*self.controls, event))

    def with_weak_control(self, event: _Event) -> _Trace:
        if any(item.event_id == event.event_id for item in self.weak_controls):
            return self
        return replace(self, weak_controls=(*self.weak_controls, event))


@dataclass
class _State:
    env: dict[str, list[_Trace]] = field(default_factory=dict)
    active_controls: tuple[_Event, ...] = ()
    active_weak_controls: tuple[_Event, ...] = ()

    def clone(self) -> _State:
        return _State(
            env={name: list(traces) for name, traces in self.env.items()},
            active_controls=self.active_controls,
            active_weak_controls=self.active_weak_controls,
        )


@dataclass(frozen=True)
class _Finding:
    trace: _Trace
    sink: _Event
    rule: SinkRule


class _Analyzer:
    def __init__(self, index: StaticFactIndex, rootfs: Path, max_call_depth: int) -> None:
        self.index = index
        self.rootfs = rootfs.resolve()
        self.max_call_depth = max_call_depth
        self.functions: dict[str, _Function] = {}
        self.simple_functions: dict[str, list[_Function]] = {}
        self.import_aliases = self._build_import_aliases()
        self.evidence: dict[str, ProfileEvidence] = {}
        self.sources: dict[str, _Event] = {}
        self.sinks: dict[str, tuple[_Event, SinkRule]] = {}
        self.controls: dict[str, _Event] = {}
        self.weak_controls: dict[str, _Event] = {}
        self.findings: list[_Finding] = []
        self.unresolved: dict[str, UnresolvedFlow] = {}
        self.limitations: dict[str, AnalysisLimitation] = {}

    def _build_import_aliases(self) -> dict[str, dict[str, str]]:
        aliases: dict[str, dict[str, str]] = {}
        for item in self.index.imports:
            if item.imported_name:
                local = item.alias or item.imported_name
                canonical = f"{item.imported_module.lstrip('.')}.{item.imported_name}".strip(".")
            else:
                local = item.alias or item.imported_module.split(".", 1)[0]
                canonical = item.imported_module
            aliases.setdefault(item.module, {})[local] = canonical
        return aliases

    def run(self) -> DataflowAnalysisResult:
        self._load_indexed_sources()
        for function in sorted(
            self.functions.values(), key=lambda item: (item.module, item.node.lineno, item.qualified_name)
        ):
            self._analyze_function(function, {}, depth=0, stack=())
        self._add_index_limitations()
        return self._build_result()

    def _load_indexed_sources(self) -> None:
        modules = sorted(
            (item for item in self.index.modules if item.source_kind in {"project", "site_package"}),
            key=lambda item: (item.image_path, item.module),
        )
        for module_fact in modules:
            image_path = module_fact.evidence.locator.image_path or f"/{module_fact.image_path}"
            candidate = self._safe_image_path(image_path)
            if candidate is None or not candidate.is_file():
                self._record_unresolved(
                    reason="source_unavailable",
                    module=module_fact.module,
                    symbol=None,
                    evidence=module_fact.evidence,
                )
                continue
            content = candidate.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if digest != module_fact.evidence.content_sha256:
                self._record_unresolved(
                    reason="source_changed",
                    module=module_fact.module,
                    symbol=None,
                    evidence=module_fact.evidence,
                )
                continue
            try:
                tree = ast.parse(content.decode("utf-8"), filename=image_path)
            except (SyntaxError, UnicodeDecodeError):
                self._record_unresolved(
                    reason="parse_error",
                    module=module_fact.module,
                    symbol=None,
                    evidence=module_fact.evidence,
                )
                continue
            file_context = _FileContext(
                module=module_fact.module,
                image_path=image_path,
                path=candidate,
                content_sha256=digest,
                layer_digest=module_fact.evidence.layer_digest,
            )
            self._index_functions(tree, file_context)

    def _safe_image_path(self, image_path: str) -> Path | None:
        candidate = (self.rootfs / image_path.lstrip("/")).resolve()
        try:
            candidate.relative_to(self.rootfs)
        except ValueError:
            return None
        return candidate

    def _index_functions(self, tree: ast.AST, file_context: _FileContext) -> None:
        def walk(body: list[ast.stmt], scope: tuple[str, ...] = ()) -> None:
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualified = ".".join((*scope, node.name))
                    function = _Function(
                        module=file_context.module,
                        qualified_name=qualified,
                        node=node,
                        file=file_context,
                        decorators=tuple(filter(None, (_expression_name(item) for item in node.decorator_list))),
                    )
                    key = f"{file_context.module}:{qualified}"
                    self.functions[key] = function
                    self.simple_functions.setdefault(node.name, []).append(function)
                    walk(node.body, (*scope, node.name))
                elif isinstance(node, ast.ClassDef):
                    walk(node.body, (*scope, node.name))

        walk(getattr(tree, "body", []))

    def _analyze_function(
        self,
        function: _Function,
        bindings: dict[str, list[_Trace]],
        *,
        depth: int,
        stack: tuple[str, ...],
    ) -> list[_Trace]:
        key = f"{function.module}:{function.qualified_name}"
        if key in stack:
            return [trace for traces in bindings.values() for trace in traces]
        state = _State(env={name: list(traces) for name, traces in bindings.items()})
        for parameter in function.parameters:
            if parameter in state.env:
                continue
            source_type = _parameter_source_type(function, parameter)
            if source_type is None:
                continue
            event = self._event(
                function,
                function.node,
                kind="source",
                name=f"{source_type} input {parameter}",
                expression=parameter,
                node_type="external_input",
                source_type=source_type,
            )
            self.sources[event.event_id] = event
            state.env[parameter] = [_Trace(source=event)]
        decorator_controls = self._decorator_controls(function)
        state.active_controls = decorator_controls
        returns: list[_Trace] = []
        self._execute_block(function, function.node.body, state, returns, depth=depth, stack=(*stack, key))
        return _dedupe_traces(returns)

    def _execute_block(
        self,
        function: _Function,
        statements: list[ast.stmt],
        state: _State,
        returns: list[_Trace],
        *,
        depth: int,
        stack: tuple[str, ...],
    ) -> None:
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = statement.value
                traces = self._eval(function, value, state, depth=depth, stack=stack) if value is not None else []
                target = (
                    statement.target if isinstance(statement, (ast.AnnAssign, ast.NamedExpr)) else statement.targets
                )
                for name in _assignment_names(target):
                    state.env[name] = traces
            elif isinstance(statement, ast.AugAssign):
                traces = [
                    *self._eval(function, statement.target, state, depth=depth, stack=stack),
                    *self._eval(function, statement.value, state, depth=depth, stack=stack),
                ]
                for name in _assignment_names(statement.target):
                    state.env[name] = _dedupe_traces(traces)
            elif isinstance(statement, ast.Expr):
                traces = self._eval(function, statement.value, state, depth=depth, stack=stack)
                control = self._control_event(function, statement.value)
                if control is not None:
                    self.controls[control.event_id] = control
                    state.active_controls = _append_event(state.active_controls, control)
                    if traces:
                        self._apply_to_matching_env(state, traces, control, weak=False)
                weak = self._weak_control_event(function, statement.value)
                if weak is not None:
                    self.weak_controls[weak.event_id] = weak
                    state.active_weak_controls = _append_event(state.active_weak_controls, weak)
            elif isinstance(statement, ast.If):
                test_traces = self._eval(function, statement.test, state, depth=depth, stack=stack)
                branch = state.clone()
                for trace in test_traces:
                    for inherited in trace.controls:
                        branch.active_controls = _append_event(branch.active_controls, inherited)
                    for inherited in trace.weak_controls:
                        branch.active_weak_controls = _append_event(branch.active_weak_controls, inherited)
                control = self._condition_control(function, statement.test)
                if control is not None:
                    if control.control_type is None:
                        self.weak_controls[control.event_id] = control
                        branch.active_weak_controls = _append_event(branch.active_weak_controls, control)
                    else:
                        self.controls[control.event_id] = control
                        branch.active_controls = _append_event(branch.active_controls, control)
                self._execute_block(function, statement.body, branch, returns, depth=depth, stack=stack)
                alternate = state.clone()
                self._execute_block(function, statement.orelse, alternate, returns, depth=depth, stack=stack)
                state.env = _merge_env(branch.env, alternate.env)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                iterable = self._eval(function, statement.iter, state, depth=depth, stack=stack)
                loop_state = state.clone()
                for name in _assignment_names(statement.target):
                    loop_state.env[name] = iterable
                self._execute_block(function, statement.body, loop_state, returns, depth=depth, stack=stack)
                state.env = _merge_env(state.env, loop_state.env)
                self._execute_block(function, statement.orelse, state, returns, depth=depth, stack=stack)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    traces = self._eval(function, item.context_expr, state, depth=depth, stack=stack)
                    if item.optional_vars:
                        for name in _assignment_names(item.optional_vars):
                            state.env[name] = traces
                self._execute_block(function, statement.body, state, returns, depth=depth, stack=stack)
            elif isinstance(statement, ast.Try):
                branches: list[_State] = []
                for body in [statement.body, *(handler.body for handler in statement.handlers), statement.orelse]:
                    branch = state.clone()
                    self._execute_block(function, body, branch, returns, depth=depth, stack=stack)
                    branches.append(branch)
                for branch in branches:
                    state.env = _merge_env(state.env, branch.env)
                self._execute_block(function, statement.finalbody, state, returns, depth=depth, stack=stack)
            elif isinstance(statement, ast.Return):
                if statement.value is not None:
                    returns.extend(self._eval(function, statement.value, state, depth=depth, stack=stack))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            else:
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self._eval(function, child, state, depth=depth, stack=stack)

    def _eval(
        self,
        function: _Function,
        expression: ast.expr,
        state: _State,
        *,
        depth: int,
        stack: tuple[str, ...],
    ) -> list[_Trace]:
        if isinstance(expression, ast.Name):
            return self._with_active_controls(state.env.get(expression.id, []), state)
        if isinstance(expression, ast.Call):
            return self._eval_call(function, expression, state, depth=depth, stack=stack)
        traces: list[_Trace] = []
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                traces.extend(self._eval(function, child, state, depth=depth, stack=stack))
        return _dedupe_traces(self._with_active_controls(traces, state))

    def _eval_call(
        self,
        function: _Function,
        call: ast.Call,
        state: _State,
        *,
        depth: int,
        stack: tuple[str, ...],
    ) -> list[_Trace]:
        raw_callee = _expression_name(call.func) or "<dynamic>"
        callee = self._canonical_callee(function.module, raw_callee)
        argument_traces: list[_Trace] = []
        for argument in [*call.args, *(keyword.value for keyword in call.keywords)]:
            argument_traces.extend(self._eval(function, argument, state, depth=depth, stack=stack))
        if isinstance(call.func, ast.Attribute):
            argument_traces.extend(self._eval(function, call.func.value, state, depth=depth, stack=stack))
        argument_traces = _dedupe_traces(self._with_active_controls(argument_traces, state))

        sink_rule = _sink_rule(callee)
        if sink_rule is not None:
            sink = self._event(
                function,
                call,
                kind="sink",
                name=f"{sink_rule.sink_type} sink {callee}",
                expression=callee,
                node_type=sink_rule.node_type,
                sink_type=sink_rule.sink_type,
            )
            self.sinks[sink.event_id] = (sink, sink_rule)
            for trace in argument_traces:
                self.findings.append(_Finding(trace=trace, sink=sink, rule=sink_rule))

        control = self._control_event(function, call)
        if control is not None:
            self.controls[control.event_id] = control
            argument_traces = [trace.with_control(control) for trace in argument_traces]
        weak = self._weak_control_event(function, call)
        if weak is not None:
            self.weak_controls[weak.event_id] = weak
            argument_traces = [trace.with_weak_control(weak) for trace in argument_traces]

        local = self._resolve_local_function(callee)
        if local is not None and argument_traces:
            if depth >= self.max_call_depth:
                for trace in argument_traces:
                    self._record_unresolved(
                        reason="call_depth_exceeded",
                        module=function.module,
                        symbol=function.qualified_name,
                        evidence=self.evidence[trace.source.evidence_id],
                        source_type=trace.source.source_type,
                    )
                return argument_traces
            hop = self._event(
                function,
                call,
                kind="function",
                name=f"call {local.qualified_name}",
                expression=callee,
                node_type="agent",
                node_module=local.module,
                node_identity=local.qualified_name,
            )
            positional = [self._eval(function, argument, state, depth=depth, stack=stack) for argument in call.args]
            keyword = {
                item.arg: self._eval(function, item.value, state, depth=depth, stack=stack)
                for item in call.keywords
                if item.arg
            }
            bindings: dict[str, list[_Trace]] = {}
            for position, parameter in enumerate(local.parameters):
                traces = positional[position] if position < len(positional) else keyword.get(parameter, [])
                bindings[parameter] = [trace.with_hop(hop) for trace in traces]
            returned = self._analyze_function(local, bindings, depth=depth + 1, stack=stack)
            if returned:
                return returned

        source_type = _source_call_type(callee)
        if source_type is not None:
            source = self._event(
                function,
                call,
                kind="source",
                name=f"{source_type} source {callee}",
                expression=callee,
                node_type="external_input",
                source_type=source_type,
            )
            self.sources[source.event_id] = source
            return [_Trace(source=source)]
        return argument_traces

    def _resolve_local_function(self, callee: str) -> _Function | None:
        name = callee.rsplit(".", 1)[-1]
        candidates = self.simple_functions.get(name, [])
        if len(candidates) != 1:
            return None
        candidate = candidates[0]
        if "." not in callee:
            return candidate
        qualifier = callee.rsplit(".", 1)[0]
        if qualifier in {"self", "cls"}:
            return candidate
        module_matches = candidate.module == qualifier or candidate.module.endswith(f".{qualifier}")
        owner = candidate.qualified_name.rsplit(".", 1)[0] if "." in candidate.qualified_name else ""
        return candidate if module_matches or owner == qualifier else None

    def _canonical_callee(self, module: str, callee: str) -> str:
        head, separator, tail = callee.partition(".")
        canonical = self.import_aliases.get(module, {}).get(head)
        if canonical is None:
            return callee
        return f"{canonical}.{tail}" if separator else canonical

    def _decorator_controls(self, function: _Function) -> tuple[_Event, ...]:
        controls: list[_Event] = []
        for decorator in function.decorators:
            if any(keyword in decorator.lower() for keyword in AUTH_DECORATOR_KEYWORDS):
                event = self._event(
                    function,
                    function.node,
                    kind="control",
                    name=f"authorization decorator {decorator}",
                    expression=decorator,
                    node_type="guard",
                    control_type="authorization",
                )
                self.controls[event.event_id] = event
                controls.append(event)
        return tuple(controls)

    def _condition_control(self, function: _Function, expression: ast.expr) -> _Event | None:
        if isinstance(expression, (ast.Compare, ast.BoolOp)):
            names = " ".join(_expression_names(expression)).lower()
            if isinstance(expression, ast.Compare) and any(
                isinstance(op, (ast.In, ast.NotIn)) for op in expression.ops
            ):
                return self._event(
                    function,
                    expression,
                    kind="control",
                    name="allowlist membership check",
                    expression=names or "membership check",
                    node_type="guard",
                    control_type="allowlist",
                )
            if any(keyword in names for keyword in ("authorized", "permission", "is_admin", "role")):
                return self._event(
                    function,
                    expression,
                    kind="control",
                    name="authorization condition",
                    expression=names,
                    node_type="guard",
                    control_type="authorization",
                )
        for node in ast.walk(expression):
            if isinstance(node, ast.Call):
                control = self._control_event(function, node)
                if control is not None:
                    return control
                weak = self._weak_control_event(function, node)
                if weak is not None:
                    return weak
        return None

    def _control_event(self, function: _Function, expression: ast.expr) -> _Event | None:
        if not isinstance(expression, ast.Call):
            return None
        callee = _expression_name(expression.func) or ""
        for control_type, names in CONTROL_CALLS.items():
            if _matches(callee, names):
                node_type = "approval" if control_type == "human_approval" else "guard"
                return self._event(
                    function,
                    expression,
                    kind="control",
                    name=f"{control_type} control {callee}",
                    expression=callee,
                    node_type=node_type,
                    control_type=control_type,
                )
        return None

    def _weak_control_event(self, function: _Function, expression: ast.expr) -> _Event | None:
        if not isinstance(expression, ast.Call):
            return None
        callee = _expression_name(expression.func) or ""
        if not _matches(callee, NORMALIZATION_CALLS):
            return None
        return self._event(
            function,
            expression,
            kind="weak_control",
            name=f"normalization-only transform {callee}",
            expression=callee,
            node_type="guard",
        )

    def _apply_to_matching_env(self, state: _State, traces: list[_Trace], event: _Event, *, weak: bool) -> None:
        source_ids = {trace.source.event_id for trace in traces}
        for name, values in state.env.items():
            if any(trace.source.event_id in source_ids for trace in values):
                state.env[name] = [
                    trace.with_weak_control(event) if weak else trace.with_control(event) for trace in values
                ]

    def _with_active_controls(self, traces: Iterable[_Trace], state: _State) -> list[_Trace]:
        output: list[_Trace] = []
        for trace in traces:
            current = trace
            for control in state.active_controls:
                current = current.with_control(control)
            for weak in state.active_weak_controls:
                current = current.with_weak_control(weak)
            output.append(current)
        return output

    def _event(
        self,
        function: _Function,
        node: ast.AST,
        *,
        kind: str,
        name: str,
        expression: str,
        node_type: str,
        source_type: SourceType | None = None,
        sink_type: SinkType | None = None,
        control_type: ControlType | None = None,
        node_module: str | None = None,
        node_identity: str | None = None,
    ) -> _Event:
        line = getattr(node, "lineno", function.node.lineno)
        end_line = getattr(node, "end_lineno", line)
        event_id = _stable_id(kind, function.module, function.qualified_name, expression, line)
        evidence_id = _stable_id("evidence", event_id)
        self.evidence.setdefault(
            evidence_id,
            ProfileEvidence(
                evidence_id=evidence_id,
                artifact_digest=self.index.artifact_digest,
                layer_digest=function.file.layer_digest,
                locator=EvidenceLocator(
                    image_path=function.file.image_path,
                    python_module=function.module,
                    symbol=function.qualified_name,
                    line_start=line,
                    line_end=end_line,
                ),
                extractor="python_dataflow_ast",
                method="static",
                content_sha256=function.file.content_sha256,
                summary=name,
            ),
        )
        return _Event(
            event_id=event_id,
            kind=kind,
            name=name,
            module=function.module,
            symbol=function.qualified_name,
            expression=expression,
            line=line,
            evidence_id=evidence_id,
            node_type=node_type,
            source_type=source_type,
            sink_type=sink_type,
            control_type=control_type,
            node_module=node_module,
            node_identity=node_identity,
        )

    def _record_unresolved(
        self,
        *,
        reason: str,
        module: str | None,
        symbol: str | None,
        evidence: ProfileEvidence,
        source_type: SourceType | None = None,
        sink_type: SinkType | None = None,
    ) -> None:
        self.evidence[evidence.evidence_id] = evidence
        unresolved_id = _stable_id("unresolved", reason, module, symbol, source_type, sink_type)
        self.unresolved[unresolved_id] = UnresolvedFlow(
            unresolved_id=unresolved_id,
            reason=reason,
            module=module,
            symbol=symbol,
            source_type=source_type,
            sink_type=sink_type,
            evidence_refs=[evidence.evidence_id],
            confidence=0.35,
            verification_status="inferred",
        )

    def _add_index_limitations(self) -> None:
        for limitation in self.index.limitations:
            evidence = limitation.evidence
            self.evidence[evidence.evidence_id] = evidence
            self.limitations[limitation.code] = AnalysisLimitation(
                code=limitation.code,
                message=limitation.message,
                evidence_refs=[evidence.evidence_id],
            )
        if self.unresolved:
            refs = sorted({ref for item in self.unresolved.values() for ref in item.evidence_refs})
            self.limitations["dataflow_unresolved"] = AnalysisLimitation(
                code="dataflow_unresolved",
                message="Some dataflow relationships could not be resolved from the available source.",
                evidence_refs=refs,
            )

    def _build_result(self) -> DataflowAnalysisResult:
        nodes: dict[str, ProfileNode] = {}
        edges: dict[str, ProfileEdge] = {}
        capabilities: dict[str, ProfileCapability] = {}
        permissions: dict[str, ProfilePermission] = {}
        controls: dict[str, SecurityControl] = {}
        weak_controls: dict[str, WeakControlFact] = {}
        source_facts: dict[str, DataflowSource] = {}
        sink_facts: dict[str, DataflowSink] = {}
        paths: dict[str, Any] = {}

        for source in self.sources.values():
            node_id = _node_id(source)
            nodes[node_id] = _profile_node(source, node_id=node_id, risk_level="medium")
            source_facts[source.event_id] = DataflowSource(
                source_id=source.event_id,
                source_type=source.source_type,
                node_id=node_id,
                module=source.module,
                symbol=source.symbol,
                expression=source.expression,
                evidence_refs=[source.evidence_id],
                confidence=0.9,
                verification_status="supported",
            )
        for sink, rule in self.sinks.values():
            node_id = _node_id(sink)
            capability_id = _stable_id("capability", sink.event_id)
            permission_ids = []
            if rule.permission_type is not None:
                permission_id = _stable_id("permission", sink.event_id, rule.permission_type)
                permission_ids.append(permission_id)
                permissions[permission_id] = ProfilePermission(
                    permission_id=permission_id,
                    permission_type=rule.permission_type,
                    operations=[rule.operation],
                    scope=sink.expression,
                    node_ids=[node_id],
                    capability_ids=[capability_id],
                    risk_level=rule.risk_level,
                    evidence_refs=[sink.evidence_id],
                    confidence=0.9,
                    verification_status="supported",
                )
            capabilities[capability_id] = ProfileCapability(
                capability_id=capability_id,
                name=f"{rule.sink_type} capability",
                operation=rule.operation,
                node_ids=[node_id],
                risk_level=rule.risk_level,
                evidence_refs=[sink.evidence_id],
                confidence=0.9,
                verification_status="supported",
            )
            nodes[node_id] = _profile_node(
                sink,
                node_id=node_id,
                risk_level=rule.risk_level,
                capability_ids=[capability_id],
                permission_ids=permission_ids,
            )
            sink_facts[sink.event_id] = DataflowSink(
                sink_id=sink.event_id,
                sink_type=rule.sink_type,
                node_id=node_id,
                module=sink.module,
                symbol=sink.symbol,
                expression=sink.expression,
                capability_id=capability_id,
                permission_ids=permission_ids,
                evidence_refs=[sink.evidence_id],
                confidence=0.9,
                verification_status="supported",
            )

        for event in self.controls.values():
            node_id = _node_id(event)
            control_id = _stable_id("control", event.event_id)
            nodes[node_id] = _profile_node(event, node_id=node_id, risk_level="low", control_ids=[control_id])
            controls[control_id] = SecurityControl(
                control_id=control_id,
                control_type=event.control_type,
                name=event.name,
                node_ids=[node_id],
                description=f"AST-recognized {event.control_type} on the dataflow path.",
                evidence_refs=[event.evidence_id],
                confidence=0.85,
                verification_status="supported",
            )
        for event in self.weak_controls.values():
            node_id = _node_id(event)
            nodes[node_id] = _profile_node(event, node_id=node_id, risk_level="low")
            weak_id = _stable_id("weak-control", event.event_id)
            weak_controls[weak_id] = WeakControlFact(
                weak_control_id=weak_id,
                name=event.name,
                node_id=node_id,
                description="Normalization changes representation but does not establish trust or authorization.",
                evidence_refs=[event.evidence_id],
                confidence=0.85,
                verification_status="supported",
            )

        for finding in self.findings:
            path = self._build_path(
                finding,
                nodes=nodes,
                edges=edges,
                capabilities=capabilities,
                permissions=permissions,
                controls=controls,
            )
            paths[path.path_id] = path

        return DataflowAnalysisResult(
            artifact_digest=self.index.artifact_digest,
            source_recovery=self.index.source_recovery,
            max_call_depth=self.max_call_depth,
            sources=sorted(source_facts.values(), key=lambda item: item.source_id),
            sinks=sorted(sink_facts.values(), key=lambda item: item.sink_id),
            nodes=sorted(nodes.values(), key=lambda item: item.node_id),
            edges=sorted(edges.values(), key=lambda item: item.edge_id),
            capabilities=sorted(capabilities.values(), key=lambda item: item.capability_id),
            permissions=sorted(permissions.values(), key=lambda item: item.permission_id),
            controls=sorted(controls.values(), key=lambda item: item.control_id),
            weak_controls=sorted(weak_controls.values(), key=lambda item: item.weak_control_id),
            risk_paths=sorted(paths.values(), key=lambda item: item.path_id),
            unresolved_flows=sorted(self.unresolved.values(), key=lambda item: item.unresolved_id),
            evidence=sorted(self.evidence.values(), key=lambda item: item.evidence_id),
            limitations=sorted(self.limitations.values(), key=lambda item: item.code),
        )

    def _build_path(
        self,
        finding: _Finding,
        *,
        nodes: dict[str, ProfileNode],
        edges: dict[str, ProfileEdge],
        capabilities: dict[str, ProfileCapability],
        permissions: dict[str, ProfilePermission],
        controls: dict[str, SecurityControl],
    ) -> Any:
        events = [
            finding.trace.source,
            *finding.trace.hops,
            *finding.trace.controls,
            *finding.trace.weak_controls,
            finding.sink,
        ]
        events = _dedupe_adjacent_events(events)
        node_ids: list[str] = []
        edge_ids: list[str] = []
        for event in events:
            node_id = _node_id(event)
            node_ids.append(node_id)
            if node_id not in nodes:
                nodes[node_id] = _profile_node(event, node_id=node_id, risk_level="medium")
        for left, right in zip(events, events[1:], strict=False):
            source_id = _node_id(left)
            target_id = _node_id(right)
            edge_type = (
                "controls"
                if right.kind in {"control", "weak_control"}
                else ("writes" if right.sink_type in {"file", "database", "memory", "credential"} else "sends_to")
            )
            edge_id = _stable_id("edge", source_id, target_id, edge_type)
            evidence_refs = _unique([left.evidence_id, right.evidence_id])
            edges[edge_id] = ProfileEdge(
                edge_id=edge_id,
                edge_type=edge_type,
                source_node_id=source_id,
                target_node_id=target_id,
                condition=right.name if right.kind in {"control", "weak_control"} else None,
                evidence_refs=evidence_refs,
                confidence=0.85,
                verification_status="supported",
            )
            edge_ids.append(edge_id)

        sink_node_id = _node_id(finding.sink)
        capability_id = _stable_id("capability", finding.sink.event_id)
        permission_ids = [item.permission_id for item in permissions.values() if sink_node_id in item.node_ids]
        control_ids = [
            _stable_id("control", event.event_id)
            for event in finding.trace.controls
            if _stable_id("control", event.event_id) in controls
        ]
        threats = _threats(
            finding.trace.source.source_type,
            finding.rule.sink_type,
            finding.sink.expression,
        )
        gaps = _control_gaps(
            finding.rule.sink_type,
            {event.control_type for event in finding.trace.controls if event.control_type},
            bool(finding.trace.weak_controls),
        )
        evidence_refs = _unique([event.evidence_id for event in events])
        risk_level = _controlled_risk(finding.rule.risk_level, bool(control_ids))
        path_id = _stable_id("risk-path", *node_ids, *threats)
        return ProfileRiskPath(
            path_id=path_id,
            source_node_id=node_ids[0],
            sink_node_id=node_ids[-1],
            node_ids=node_ids,
            edge_ids=edge_ids,
            capability_ids=[capability_id] if capability_id in capabilities else [],
            permission_ids=permission_ids,
            control_ids=control_ids,
            applicable_threats=threats,
            control_gaps=gaps,
            risk_level=risk_level,
            evidence_refs=evidence_refs,
            confidence=max(0.65, round(0.94 - 0.04 * len(finding.trace.hops), 2)),
            verification_status="supported",
        )


def analyze_dataflow(
    index: StaticFactIndex,
    rootfs: str | Path,
    *,
    max_call_depth: int = 3,
) -> DataflowAnalysisResult:
    """Analyze evidence-bound Python sources without executing project code."""

    if not 1 <= max_call_depth <= 3:
        raise ValueError("max_call_depth must be between 1 and 3")
    root = Path(rootfs)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("rootfs must be a real directory")
    return _Analyzer(index, root, max_call_depth).run()


def analyze_dataflows(
    index: StaticFactIndex,
    rootfs: str | Path,
    *,
    max_call_depth: int = 3,
) -> DataflowAnalysisResult:
    """Plural alias retained for callers that model multiple risk paths."""

    return analyze_dataflow(index, rootfs, max_call_depth=max_call_depth)


def _parameter_source_type(function: _Function, parameter: str) -> SourceType | None:
    lowered = parameter.lower()
    if any(_matches(decorator, HTTP_DECORATORS) for decorator in function.decorators):
        return "http"
    if any("click." in decorator.lower() for decorator in function.decorators):
        return "cli"
    if any(token in " ".join(function.decorators).lower() for token in ("message", "event", "handler")):
        if any(token in lowered for token in ("message", "event", "text", "content")):
            return "message"
    for source_type, keywords in SOURCE_PARAMETER_KEYWORDS.items():
        if any(
            lowered == keyword or lowered.startswith(f"{keyword}_") or lowered.endswith(f"_{keyword}")
            for keyword in keywords
        ):
            return source_type
    function_name = function.qualified_name.rsplit(".", 1)[-1].lower()
    if function_name in {"main", "cli"}:
        return "cli"
    return None


def _source_call_type(callee: str) -> SourceType | None:
    for source_type, names in SOURCE_CALLS.items():
        if _matches(callee, names):
            return source_type
    return None


def _sink_rule(callee: str) -> SinkRule | None:
    matched = next(
        (rule for rule in SINK_RULES if _matches(callee, rule.names)),
        None,
    )
    if matched is not None:
        return matched
    if ".tools." in callee.casefold():
        return next(rule for rule in SINK_RULES if rule.sink_type == "tool")
    return None


def _matches(name: str, candidates: Iterable[str]) -> bool:
    lowered = name.lower()
    return any(lowered == candidate.lower() or lowered.endswith(f".{candidate.lower()}") for candidate in candidates)


def _expression_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expression_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _expression_name(node.func)
    if isinstance(node, ast.Subscript):
        return _expression_name(node.value)
    return None


def _expression_names(node: ast.AST) -> list[str]:
    return [item.id for item in ast.walk(node) if isinstance(item, ast.Name)]


def _assignment_names(target: ast.AST | list[ast.expr]) -> list[str]:
    targets = target if isinstance(target, list) else [target]
    output: list[str] = []
    for item in targets:
        if isinstance(item, ast.Name):
            output.append(item.id)
        elif isinstance(item, (ast.Tuple, ast.List)):
            output.extend(_assignment_names(list(item.elts)))
    return output


def _merge_env(left: dict[str, list[_Trace]], right: dict[str, list[_Trace]]) -> dict[str, list[_Trace]]:
    return {name: _dedupe_traces([*left.get(name, []), *right.get(name, [])]) for name in left.keys() | right.keys()}


def _dedupe_traces(traces: Iterable[_Trace]) -> list[_Trace]:
    output: list[_Trace] = []
    seen: set[tuple[Any, ...]] = set()
    for trace in traces:
        key = (
            trace.source.event_id,
            tuple(item.event_id for item in trace.hops),
            tuple(item.event_id for item in trace.controls),
            tuple(item.event_id for item in trace.weak_controls),
        )
        if key not in seen:
            seen.add(key)
            output.append(trace)
    return output


def _append_event(events: tuple[_Event, ...], event: _Event) -> tuple[_Event, ...]:
    return events if any(item.event_id == event.event_id for item in events) else (*events, event)


def _dedupe_adjacent_events(events: list[_Event]) -> list[_Event]:
    output: list[_Event] = []
    for event in events:
        if not output or _node_id(output[-1]) != _node_id(event):
            output.append(event)
    return output


def _node_id(event: _Event) -> str:
    if event.node_module is not None and event.node_identity is not None:
        return _stable_id("node", event.node_module, event.node_identity)
    return _stable_id("node", event.event_id)


def _stable_id(prefix: str, *parts: object) -> str:
    payload = "\x1f".join(str(part) for part in parts)
    return f"{prefix}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:20]}"


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _profile_node(
    event: _Event,
    *,
    node_id: str,
    risk_level: ProfileRiskLevel,
    capability_ids: list[str] | None = None,
    permission_ids: list[str] | None = None,
    control_ids: list[str] | None = None,
) -> ProfileNode:
    return ProfileNode(
        node_id=node_id,
        node_type=event.node_type,
        name=event.name,
        capability_ids=capability_ids or [],
        permission_ids=permission_ids or [],
        control_ids=control_ids or [],
        risk_level=risk_level,
        evidence_refs=[event.evidence_id],
        confidence=0.9 if event.kind != "function" else 0.85,
        verification_status="supported",
    )


def _threats(source_type: SourceType | None, sink_type: SinkType, expression: str) -> list[str]:
    if sink_type == "llm_prompt":
        if source_type in {"retrieval", "tool_result", "memory", "network"}:
            return ["indirect_prompt_injection"]
        return ["direct_prompt_injection"]
    if sink_type == "memory":
        if "vector" in expression.lower() or "knowledge" in expression.lower():
            return ["rag_poisoning"]
        return ["memory_poisoning"]
    mapping: dict[SinkType, str] = {
        "shell": "command_injection",
        "file": "unsafe_file_access",
        "browser": "browser_action_injection",
        "api": "server_side_request_forgery",
        "database": "query_injection",
        "credential": "credential_tampering",
        "tool": "tool_argument_injection",
        "llm_prompt": "direct_prompt_injection",
        "memory": "memory_poisoning",
    }
    return [mapping[sink_type]]


def _control_gaps(
    sink_type: SinkType,
    controls: set[ControlType],
    has_weak_control: bool,
) -> list[str]:
    expected: dict[SinkType, tuple[ControlType, ...]] = {
        "llm_prompt": ("input_guard",),
        "shell": ("allowlist", "parameter_validation", "human_approval"),
        "file": ("parameter_validation", "authorization"),
        "browser": ("allowlist", "authorization"),
        "api": ("allowlist", "authorization"),
        "database": ("parameter_validation", "authorization"),
        "memory": ("input_guard", "authorization"),
        "credential": ("authorization", "human_approval"),
        "tool": ("parameter_validation", "authorization"),
    }
    gaps = [f"missing_{control}" for control in expected[sink_type] if control not in controls]
    if has_weak_control:
        gaps.append("normalization_only_does_not_establish_trust")
    return gaps


def _controlled_risk(risk: ProfileRiskLevel, has_control: bool) -> ProfileRiskLevel:
    if not has_control:
        return risk
    return {
        "critical": "high",
        "high": "medium",
        "medium": "low",
        "low": "low",
    }[risk]


__all__ = ["analyze_dataflow", "analyze_dataflows"]
