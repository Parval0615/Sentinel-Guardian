from __future__ import annotations

import ast
import configparser
import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from redsentinel.core.profile_evidence import EvidenceLocator, ProfileEvidence
from redsentinel.profiling.image.models import FileRecord, ParsedImageArtifact, SanitizedImageConfig
from redsentinel.profiling.static_facts.models import (
    CallFact,
    CapabilityFact,
    ClassBaseFact,
    ConfigFact,
    DecoratorFact,
    DependencyFact,
    EntrypointFact,
    ImportFact,
    ModuleFact,
    StaticAnalysisLimitation,
    StaticFactIndex,
    SymbolFact,
)


_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|passwd|pwd|credential|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PYTHON_EXTENSION_RE = re.compile(r"(?:\.cpython-[^.]+|\.abi3)?\.(?:so|pyd)$")
_LOCK_NAMES = {"poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "pylock.toml", "requirements.lock"}
_PROJECT_FILES = {"pyproject.toml", "setup.py", "setup.cfg"}
_METADATA_FILES = {"METADATA", "PKG-INFO"}
_ENTRY_POINT_FILES = {"entry_points.txt"}
_SOURCE_ROOT_NAMES = {"app", "code", "opt", "src", "workspace"}

_CAPABILITY_CALLS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("shell", ("subprocess.run", "subprocess.call", "subprocess.Popen", "os.system", "os.popen"), "execute"),
    (
        "file",
        (
            "open",
            "Path.open",
            "Path.read_text",
            "Path.read_bytes",
            "Path.write_text",
            "Path.write_bytes",
            "Path.unlink",
            "shutil.copy",
            "shutil.move",
            "shutil.rmtree",
        ),
        "filesystem",
    ),
    (
        "external_api",
        (
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.request",
            "urllib.request.urlopen",
            "aiohttp.ClientSession",
        ),
        "request",
    ),
    (
        "database",
        (
            "sqlite3.connect",
            "sqlalchemy.create_engine",
            "create_engine",
            "psycopg.connect",
            "psycopg2.connect",
            "pymongo.MongoClient",
            "redis.Redis",
            "redis.from_url",
            "chromadb.Client",
            "Chroma",
            "FAISS",
        ),
        "connect",
    ),
    (
        "browser",
        (
            "playwright.sync_api.sync_playwright",
            "playwright.async_api.async_playwright",
            "sync_playwright",
            "async_playwright",
            "selenium.webdriver",
            "webdriver.Chrome",
            "Browser",
        ),
        "automate",
    ),
    (
        "mcp",
        ("FastMCP", "ClientSession", "stdio_client", "sse_client", "mcp.run", "mcp.connect"),
        "protocol",
    ),
    (
        "model",
        (
            "ChatOpenAI",
            "OpenAI",
            "AsyncOpenAI",
            "ChatAnthropic",
            "Anthropic",
            "ChatGoogleGenerativeAI",
            "ChatBedrock",
            "Bedrock",
            "Ollama",
            "litellm.completion",
        ),
        "inference",
    ),
)
_CAPABILITY_IMPORTS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("model", ("openai", "anthropic", "litellm", "transformers", "langchain_openai"), "client"),
    ("database", ("sqlalchemy", "sqlite3", "psycopg", "psycopg2", "pymongo", "redis", "chromadb"), "client"),
    ("mcp", ("mcp",), "protocol"),
    ("external_api", ("requests", "httpx", "aiohttp", "urllib.request"), "client"),
    ("shell", ("subprocess",), "execute"),
    ("file", ("pathlib", "shutil"), "filesystem"),
    ("browser", ("playwright", "selenium"), "automate"),
)


@dataclass(frozen=True)
class StaticExtractionLimits:
    max_files: int = 20_000
    max_file_size: int = 4 * 1024 * 1024
    max_total_read_size: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_files <= 0 or self.max_file_size <= 0 or self.max_total_read_size <= 0:
            raise ValueError("static extraction limits must be greater than zero")


@dataclass(frozen=True)
class _ArtifactContext:
    rootfs: Path
    artifact_digest: str
    config: SanitizedImageConfig | None
    records: Mapping[str, FileRecord]


@dataclass(frozen=True)
class _Candidate:
    path: Path
    relative: str
    size: int
    sha256: str
    layer_digest: str | None


class _FactFactory:
    def __init__(self, artifact_digest: str) -> None:
        self.artifact_digest = artifact_digest

    @staticmethod
    def _stable_id(prefix: str, *parts: object) -> str:
        payload = "\x1f".join(str(part) for part in parts)
        return f"{prefix}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:20]}"

    def evidence(
        self,
        candidate: _Candidate | None,
        *,
        extractor: str,
        summary: str,
        line_start: int | None = None,
        line_end: int | None = None,
        python_module: str | None = None,
        symbol: str | None = None,
        config_key: str | None = None,
        metadata_key: str | None = None,
        content: bytes | None = None,
    ) -> ProfileEvidence:
        image_path = f"/{candidate.relative}" if candidate is not None else None
        digest = candidate.sha256 if candidate is not None else hashlib.sha256(content or b"").hexdigest()
        locator = EvidenceLocator(
            image_path=image_path,
            python_module=python_module,
            symbol=symbol,
            line_start=line_start,
            line_end=line_end,
            config_key=config_key,
            package_metadata_key=metadata_key,
        )
        identity = (
            image_path,
            python_module,
            symbol,
            line_start,
            line_end,
            config_key,
            metadata_key,
            extractor,
            summary,
        )
        return ProfileEvidence(
            evidence_id=self._stable_id("evidence", *identity),
            artifact_digest=self.artifact_digest,
            layer_digest=candidate.layer_digest if candidate is not None else None,
            locator=locator,
            extractor=extractor,
            method="image_config" if candidate is None else (
                "package_metadata" if extractor.startswith(("dist_info", "requirements", "pyproject", "setup", "lock"))
                else "static"
            ),
            content_sha256=digest,
            summary=summary[:500],
        )

    def fact_id(self, kind: str, *parts: object) -> str:
        return self._stable_id(kind, *parts)


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, module: str, candidate: _Candidate, factory: _FactFactory) -> None:
        self.module = module
        self.candidate = candidate
        self.factory = factory
        self.scope: list[str] = []
        self.imports: list[ImportFact] = []
        self.symbols: list[SymbolFact] = []
        self.calls: list[CallFact] = []
        self.decorators: list[DecoratorFact] = []
        self.class_bases: list[ClassBaseFact] = []
        self.configuration: list[ConfigFact] = []
        self.capabilities: list[CapabilityFact] = []

    @property
    def current_symbol(self) -> str:
        return ".".join(self.scope) if self.scope else "<module>"

    def _evidence(self, *, summary: str, node: ast.AST, symbol: str | None = None) -> ProfileEvidence:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        return self.factory.evidence(
            self.candidate,
            extractor="python_ast",
            summary=summary,
            line_start=start,
            line_end=end,
            python_module=self.module,
            symbol=symbol,
        )

    def _visit_symbol(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, kind: str) -> None:
        qualified = ".".join((*self.scope, node.name))
        evidence = self._evidence(summary=f"{kind} symbol {qualified}", node=node, symbol=qualified)
        self.symbols.append(
            SymbolFact(
                fact_id=self.factory.fact_id("symbol", self.module, qualified, kind),
                evidence=evidence,
                module=self.module,
                qualified_name=qualified,
                symbol_kind=kind,
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
            )
        )
        for decorator in node.decorator_list:
            name = _expression_name(decorator)
            if name:
                self.decorators.append(
                    DecoratorFact(
                        fact_id=self.factory.fact_id("decorator", self.module, qualified, name, decorator.lineno),
                        evidence=self._evidence(
                            summary=f"decorator {name} on {qualified}",
                            node=decorator,
                            symbol=qualified,
                        ),
                        module=self.module,
                        symbol=qualified,
                        decorator=name,
                        line=decorator.lineno,
                    )
                )
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                name = _expression_name(base)
                if name:
                    self.class_bases.append(
                        ClassBaseFact(
                            fact_id=self.factory.fact_id("class-base", self.module, qualified, name, base.lineno),
                            evidence=self._evidence(
                                summary=f"class base {name} on {qualified}",
                                node=base,
                                symbol=qualified,
                            ),
                            module=self.module,
                            class_name=qualified,
                            base=name,
                            line=base.lineno,
                        )
                    )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_symbol(node, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_symbol(node, "async_function")

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_symbol(node, "class")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._add_import(node, alias.name, None, alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        prefix = "." * node.level
        imported_module = f"{prefix}{node.module or ''}"
        for alias in node.names:
            self._add_import(node, imported_module, alias.name, alias.asname)
        self.generic_visit(node)

    def _add_import(
        self,
        node: ast.Import | ast.ImportFrom,
        imported_module: str,
        imported_name: str | None,
        alias: str | None,
    ) -> None:
        display = f"{imported_module}.{imported_name}" if imported_name else imported_module
        evidence = self._evidence(summary=f"import {display}", node=node, symbol=self.current_symbol)
        self.imports.append(
            ImportFact(
                fact_id=self.factory.fact_id(
                    "import", self.module, imported_module, imported_name, alias, node.lineno
                ),
                evidence=evidence,
                module=self.module,
                imported_module=imported_module,
                imported_name=imported_name,
                alias=alias,
                line=node.lineno,
            )
        )
        provider = display.lstrip(".")
        for capability, prefixes, operation in _CAPABILITY_IMPORTS:
            if any(provider == prefix or provider.startswith(f"{prefix}.") for prefix in prefixes):
                self._add_capability(node, capability, provider, operation, evidence)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _expression_name(node.func)
        if callee:
            caller = self.current_symbol
            evidence = self._evidence(
                summary=f"call {callee} from {caller}",
                node=node,
                symbol=caller,
            )
            self.calls.append(
                CallFact(
                    fact_id=self.factory.fact_id("call", self.module, caller, callee, node.lineno),
                    evidence=evidence,
                    module=self.module,
                    caller=caller,
                    callee=callee,
                    line=node.lineno,
                    positional_arguments=_framework_positional_arguments(callee, node),
                    keyword_arguments=_framework_keyword_arguments(callee, node),
                )
            )
            for capability, names, operation in _CAPABILITY_CALLS:
                if any(callee == name or callee.endswith(f".{name}") for name in names):
                    self._add_capability(node, capability, callee, operation, evidence)
            env_key = _environment_key(node)
            if env_key:
                self._add_config(node, "environment", env_key, "presence", _is_sensitive_key(env_key))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        target = _expression_name(node.value)
        if target in {"os.environ", "environ"}:
            key = _string_constant(node.slice)
            if key:
                self._add_config(node, "environment", key, "presence", _is_sensitive_key(key))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant):
            value_type = type(node.value.value).__name__
            for target in node.targets:
                name = _assignment_name(target)
                if name and _looks_like_config_name(name):
                    self._add_config(node, "constant", name, value_type, _is_sensitive_key(name))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.value, ast.Constant):
            name = _assignment_name(node.target)
            if name and _looks_like_config_name(name):
                self._add_config(
                    node,
                    "constant",
                    name,
                    type(node.value.value).__name__,
                    _is_sensitive_key(name),
                )
        self.generic_visit(node)

    def _add_config(
        self,
        node: ast.AST,
        category: str,
        key: str,
        value_type: str,
        sensitive: bool,
    ) -> None:
        evidence = self._evidence(
            summary=f"{category} configuration key {key}; value omitted",
            node=node,
            symbol=self.current_symbol,
        )
        self.configuration.append(
            ConfigFact(
                fact_id=self.factory.fact_id("config", self.module, category, key, getattr(node, "lineno", 1)),
                evidence=evidence,
                category=category,
                key=key,
                value_type=value_type,
                is_sensitive=sensitive,
            )
        )

    def _add_capability(
        self,
        node: ast.AST,
        capability: str,
        provider: str,
        operation: str,
        evidence: ProfileEvidence,
    ) -> None:
        self.capabilities.append(
            CapabilityFact(
                fact_id=self.factory.fact_id(
                    "capability", self.module, self.current_symbol, capability, provider, getattr(node, "lineno", 1)
                ),
                evidence=evidence,
                capability=capability,
                provider=provider,
                operation=operation,
                module=self.module,
                symbol=self.current_symbol,
            )
        )


def extract_static_facts(
    image_or_rootfs: ParsedImageArtifact | str | os.PathLike[str],
    *,
    artifact_digest: str | None = None,
    config: SanitizedImageConfig | None = None,
    limits: StaticExtractionLimits | None = None,
) -> StaticFactIndex:
    """Extract deterministic, redacted Python facts without executing image content."""

    effective_limits = limits or StaticExtractionLimits()
    context = _build_context(image_or_rootfs, artifact_digest=artifact_digest, config=config)
    candidates = _collect_candidates(context, effective_limits)
    if artifact_digest is None and not isinstance(image_or_rootfs, ParsedImageArtifact):
        context = _ArtifactContext(
            rootfs=context.rootfs,
            artifact_digest=_rootfs_digest(candidates),
            config=context.config,
            records=context.records,
        )
    factory = _FactFactory(context.artifact_digest)

    modules: list[ModuleFact] = []
    symbols: list[SymbolFact] = []
    imports: list[ImportFact] = []
    calls: list[CallFact] = []
    decorators: list[DecoratorFact] = []
    class_bases: list[ClassBaseFact] = []
    dependencies: list[DependencyFact] = []
    entrypoints: list[EntrypointFact] = []
    configuration: list[ConfigFact] = []
    capabilities: list[CapabilityFact] = []
    limitations: list[StaticAnalysisLimitation] = []
    source_modules: set[str] = set()
    compiled_modules: set[str] = set()
    omitted_source_kinds: dict[str, _Candidate] = {}
    syntax_errors = 0
    skipped_sources = 0
    metadata_present = False

    if context.config is not None:
        image_entrypoints, image_config = _image_config_facts(context.config, factory)
        entrypoints.extend(image_entrypoints)
        configuration.extend(image_config)

    for candidate in candidates:
        path = PurePosixPath(candidate.relative)
        name = path.name
        lower_name = name.lower()
        if (
            candidate.size > effective_limits.max_file_size
            and (lower_name.endswith(".py") or _is_metadata_file(path))
        ):
            limitations.append(
                _limitation(
                    factory,
                    candidate,
                    code="file_too_large",
                    message=f"Skipped oversized static-analysis input /{candidate.relative}.",
                )
            )
            if lower_name.endswith(".py") and _source_kind(path, context.config) == "project":
                skipped_sources += 1
            continue

        if lower_name.endswith(".py"):
            module = _module_name(path, context.config)
            source_kind = _source_kind(path, context.config)
            module_fact = _module_fact(factory, candidate, module, source_kind, name == "__init__.py")
            modules.append(module_fact)
            if source_kind != "project":
                omitted_source_kinds.setdefault(source_kind, candidate)
                continue
            source_modules.add(module)
            if name == "__main__.py":
                entrypoints.append(_main_entrypoint(factory, candidate, module))
            try:
                text = candidate.path.read_text(encoding="utf-8")
                tree = ast.parse(text, filename=f"/{candidate.relative}")
            except (UnicodeDecodeError, OSError) as exc:
                skipped_sources += 1
                limitations.append(
                    _limitation(
                        factory,
                        candidate,
                        code="unreadable_file",
                        message=f"Could not parse text from /{candidate.relative}: {type(exc).__name__}.",
                    )
                )
                continue
            except SyntaxError as exc:
                syntax_errors += 1
                line = exc.lineno or 1
                limitations.append(
                    _limitation(
                        factory,
                        candidate,
                        code="syntax_error",
                        message=f"Syntax error in /{candidate.relative} at line {line}; file-level facts retained.",
                        line=line,
                        module=module,
                    )
                )
                continue
            visitor = _PythonVisitor(module, candidate, factory)
            visitor.visit(tree)
            symbols.extend(visitor.symbols)
            imports.extend(visitor.imports)
            calls.extend(visitor.calls)
            decorators.extend(visitor.decorators)
            class_bases.extend(visitor.class_bases)
            configuration.extend(visitor.configuration)
            capabilities.extend(visitor.capabilities)
            if name == "setup.py":
                setup_dependencies, setup_entrypoints = _parse_setup_py(tree, candidate, factory)
                dependencies.extend(setup_dependencies)
                entrypoints.extend(setup_entrypoints)
                metadata_present = True
            continue

        if lower_name.endswith((".pyc", ".pyo")) or _PYTHON_EXTENSION_RE.search(lower_name):
            module = _module_name(path, context.config)
            if _source_kind(path, context.config) == "project":
                compiled_modules.add(module)
            kind = "bytecode" if lower_name.endswith((".pyc", ".pyo")) else "extension"
            modules.append(_module_fact(factory, candidate, module, kind, False))
            continue

        if name in _METADATA_FILES and ".dist-info" in candidate.relative:
            metadata_present = True
            dependencies.extend(_parse_dist_metadata(candidate, factory))
        elif name in _ENTRY_POINT_FILES and ".dist-info" in candidate.relative:
            metadata_present = True
            entrypoints.extend(_parse_entry_points(candidate, factory, "console_script"))
        elif lower_name.startswith("requirements") and lower_name.endswith((".txt", ".in")):
            metadata_present = True
            dependencies.extend(_parse_requirements(candidate, factory))
        elif name == "pyproject.toml":
            metadata_present = True
            deps, entries, configs = _parse_pyproject(candidate, factory)
            dependencies.extend(deps)
            entrypoints.extend(entries)
            configuration.extend(configs)
        elif name == "setup.cfg":
            metadata_present = True
            deps, entries = _parse_setup_cfg(candidate, factory)
            dependencies.extend(deps)
            entrypoints.extend(entries)
        elif name in _LOCK_NAMES:
            metadata_present = True
            dependencies.extend(_parse_lock(candidate, factory))

    for source_kind, candidate in sorted(omitted_source_kinds.items()):
        code = (
            "dependency_source_omitted"
            if source_kind == "site_package"
            else "runtime_source_omitted"
        )
        limitations.append(
            _limitation(
                factory,
                candidate,
                code=code,
                message=(
                    f"{source_kind} modules were inventoried without deep AST analysis; "
                    "project source and package metadata remain authoritative."
                ),
            )
        )

    source_recovery = _source_recovery(
        source_modules=source_modules,
        compiled_modules=compiled_modules,
        syntax_errors=syntax_errors,
        skipped_sources=skipped_sources,
        metadata_present=metadata_present,
    )
    if source_recovery in {"partial", "metadata_only", "bytecode_only", "none"}:
        evidence_candidate = next(iter(candidates), None)
        code = "source_partial" if source_recovery == "partial" else "source_missing"
        limitations.append(
            _limitation(
                factory,
                evidence_candidate,
                code=code,
                message=f"Python source recovery is {source_recovery}.",
                config_key="source_recovery" if evidence_candidate is None else None,
            )
        )

    return StaticFactIndex(
        artifact_digest=context.artifact_digest,
        source_recovery=source_recovery,
        modules=_dedupe(modules),
        symbols=_dedupe(symbols),
        imports=_dedupe(imports),
        calls=_dedupe(calls),
        decorators=_dedupe(decorators),
        class_bases=_dedupe(class_bases),
        dependencies=_dedupe(dependencies),
        entrypoints=_dedupe(entrypoints),
        configuration=_dedupe(configuration),
        capabilities=_dedupe(capabilities),
        limitations=_dedupe(limitations),
    )


def _build_context(
    image_or_rootfs: ParsedImageArtifact | str | os.PathLike[str],
    *,
    artifact_digest: str | None,
    config: SanitizedImageConfig | None,
) -> _ArtifactContext:
    if isinstance(image_or_rootfs, ParsedImageArtifact):
        return _ArtifactContext(
            rootfs=image_or_rootfs.rootfs_path.resolve(),
            artifact_digest=image_or_rootfs.image_digest,
            config=image_or_rootfs.config,
            records={record.path: record for record in image_or_rootfs.files},
        )
    rootfs = Path(image_or_rootfs)
    if rootfs.is_symlink() or not rootfs.is_dir():
        raise ValueError("rootfs must be a real directory")
    digest = artifact_digest or f"sha256:{'0' * 64}"
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("artifact_digest must be a sha256 digest")
    return _ArtifactContext(rootfs=rootfs.resolve(), artifact_digest=digest, config=config, records={})


def _collect_candidates(context: _ArtifactContext, limits: StaticExtractionLimits) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    total_read_size = 0
    root = context.rootfs
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names[:] = sorted(
            name for name in directory_names if not (Path(directory) / name).is_symlink()
        )
        for name in sorted(file_names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            pure_path = PurePosixPath(relative)
            if not _is_relevant_file(pure_path):
                continue
            if len(candidates) >= limits.max_files:
                raise ValueError("static extraction exceeds the maximum relevant file count")
            size = path.stat().st_size
            if (
                name.lower().endswith(".py")
                and _source_kind(pure_path, context.config) == "project"
            ) or _is_metadata_file(pure_path):
                total_read_size += min(size, limits.max_file_size)
            if total_read_size > limits.max_total_read_size:
                raise ValueError("static extraction exceeds the maximum total read size")
            record = context.records.get(relative)
            digest = record.sha256 if record and record.sha256 else _sha256_file(path)
            candidates.append(
                _Candidate(
                    path=path,
                    relative=relative,
                    size=size,
                    sha256=digest,
                    layer_digest=record.layer_digest if record else None,
                )
            )
    return candidates


def _is_relevant_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        lower.endswith((".py", ".pyc", ".pyo", ".pyd"))
        or bool(_PYTHON_EXTENSION_RE.search(lower))
        or name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _is_metadata_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _is_metadata_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _is_metadata_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _is_metadata_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _is_metadata_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _is_metadata_file(path: PurePosixPath) -> bool:
    name = path.name
    lower = name.lower()
    return (
        name in _METADATA_FILES
        or name in _ENTRY_POINT_FILES
        or name in _PROJECT_FILES
        or name in _LOCK_NAMES
        or (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rootfs_digest(candidates: Sequence[_Candidate]) -> str:
    digest = hashlib.sha256()
    for candidate in candidates:
        digest.update(candidate.relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(candidate.sha256.encode("ascii"))
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _module_name(path: PurePosixPath, config: SanitizedImageConfig | None) -> str:
    parts = list(path.parts)
    if "site-packages" in parts:
        parts = parts[parts.index("site-packages") + 1 :]
    elif "dist-packages" in parts:
        parts = parts[parts.index("dist-packages") + 1 :]
    else:
        working_parts = [part for part in PurePosixPath(config.working_dir).parts if part != "/"] if config else []
        if working_parts and parts[: len(working_parts)] == working_parts:
            parts = parts[len(working_parts) :]
        elif parts and parts[0] in _SOURCE_ROOT_NAMES:
            parts = parts[1:]
    if "__pycache__" in parts:
        parts.remove("__pycache__")
    filename = parts[-1]
    filename = re.sub(r"\.cpython-[^.]+(?=\.pyc$)", "", filename)
    filename = re.sub(r"(?:\.abi3|\.cpython-[^.]+)?\.(?:so|pyd)$", "", filename)
    filename = re.sub(r"\.(?:py|pyc|pyo)$", "", filename)
    parts[-1] = filename
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__root__"


def _source_kind(
    path: PurePosixPath,
    config: SanitizedImageConfig | None = None,
) -> str:
    parts = set(path.parts)
    if {"site-packages", "dist-packages"} & parts:
        return "site_package"
    if any(re.fullmatch(r"python\d+(?:\.\d+)*", part) for part in path.parts):
        return "runtime"
    working_parts = (
        tuple(part for part in PurePosixPath(config.working_dir).parts if part != "/")
        if config
        else ()
    )
    if working_parts:
        return "project" if path.parts[: len(working_parts)] == working_parts else "runtime"
    return "project"


def _module_fact(
    factory: _FactFactory,
    candidate: _Candidate,
    module: str,
    source_kind: str,
    is_package: bool,
) -> ModuleFact:
    return ModuleFact(
        fact_id=factory.fact_id("module", module, candidate.relative, source_kind),
        evidence=factory.evidence(
            candidate,
            extractor="python_inventory",
            summary=f"Python {source_kind} module {module}",
            python_module=module,
        ),
        module=module,
        image_path=f"/{candidate.relative}",
        source_kind=source_kind,
        is_package=is_package,
    )


def _main_entrypoint(factory: _FactFactory, candidate: _Candidate, module: str) -> EntrypointFact:
    target_module = module.removesuffix(".__main__")
    return EntrypointFact(
        fact_id=factory.fact_id("entrypoint", "module", target_module, candidate.relative),
        evidence=factory.evidence(
            candidate,
            extractor="python_inventory",
            summary=f"Python __main__ entrypoint for {target_module}",
            python_module=module,
        ),
        kind="module",
        name=target_module,
        module=target_module,
    )


def _image_config_facts(
    config: SanitizedImageConfig,
    factory: _FactFactory,
) -> tuple[list[EntrypointFact], list[ConfigFact]]:
    command = _sanitize_command((*config.entrypoint, *config.cmd))
    payload = json.dumps(
        {
            "command": command,
            "working_dir": config.working_dir,
            "env_keys": config.env_keys,
        },
        sort_keys=True,
    ).encode("utf-8")
    entries: list[EntrypointFact] = []
    if command:
        module = None
        symbol = None
        if "-m" in command:
            index = command.index("-m")
            if index + 1 < len(command):
                module = command[index + 1]
        elif any(item.endswith(".py") for item in command):
            script = next(item for item in command if item.endswith(".py"))
            module = PurePosixPath(script).stem
        entries.append(
            EntrypointFact(
                fact_id=factory.fact_id("entrypoint", "image", *command),
                evidence=factory.evidence(
                    None,
                    extractor="image_config",
                    summary="Image Entrypoint/Cmd; arguments retained, environment values omitted",
                    config_key="Entrypoint,Cmd",
                    content=payload,
                ),
                kind="image",
                name="image-command",
                module=module,
                symbol=symbol,
                command=command,
            )
        )
    configs = [
        ConfigFact(
            fact_id=factory.fact_id("config", "environment", key),
            evidence=factory.evidence(
                None,
                extractor="image_config",
                summary=f"Image environment key {key}; value omitted",
                config_key=f"Env.{key}",
                content=payload,
            ),
            category="environment",
            key=key,
            value_type="presence",
            is_sensitive=_is_sensitive_key(key),
        )
        for key in config.env_keys
    ]
    return entries, configs


def _parse_requirements(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    facts: list[DependencyFact] = []
    for line_number, line in enumerate(_read_lines(candidate), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        requirement = stripped.split(";", 1)[0].strip()
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if not match:
            continue
        name = match.group(1)
        version = _version_spec(requirement[len(name) :])
        facts.append(
            _dependency_fact(factory, candidate, name, version, "requirements", line_number, f"line:{line_number}")
        )
    return facts


def _parse_plain_lock(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    facts: list[DependencyFact] = []
    for line_number, line in enumerate(_read_lines(candidate), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        requirement = stripped.split(";", 1)[0].split(" --hash=", 1)[0].strip()
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match:
            name = match.group(1)
            facts.append(
                _dependency_fact(
                    factory,
                    candidate,
                    name,
                    _version_spec(requirement[len(name) :]),
                    "lock",
                    line_number,
                    f"line:{line_number}",
                )
            )
    return facts


def _parse_plain_lock(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    facts: list[DependencyFact] = []
    for line_number, line in enumerate(_read_lines(candidate), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        requirement = stripped.split(";", 1)[0].split(" --hash=", 1)[0].strip()
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match:
            name = match.group(1)
            facts.append(
                _dependency_fact(
                    factory,
                    candidate,
                    name,
                    _version_spec(requirement[len(name) :]),
                    "lock",
                    line_number,
                    f"line:{line_number}",
                )
            )
    return facts


def _parse_plain_lock(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    facts: list[DependencyFact] = []
    for line_number, line in enumerate(_read_lines(candidate), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        requirement = stripped.split(";", 1)[0].split(" --hash=", 1)[0].strip()
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match:
            name = match.group(1)
            facts.append(
                _dependency_fact(
                    factory,
                    candidate,
                    name,
                    _version_spec(requirement[len(name) :]),
                    "lock",
                    line_number,
                    f"line:{line_number}",
                )
            )
    return facts


def _parse_plain_lock(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    facts: list[DependencyFact] = []
    for line_number, line in enumerate(_read_lines(candidate), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        requirement = stripped.split(";", 1)[0].split(" --hash=", 1)[0].strip()
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match:
            name = match.group(1)
            facts.append(
                _dependency_fact(
                    factory,
                    candidate,
                    name,
                    _version_spec(requirement[len(name) :]),
                    "lock",
                    line_number,
                    f"line:{line_number}",
                )
            )
    return facts


def _parse_dist_metadata(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    try:
        message = Parser().parsestr(candidate.path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return []
    facts: list[DependencyFact] = []
    package_name = message.get("Name")
    if package_name:
        facts.append(
            _dependency_fact(
                factory,
                candidate,
                package_name,
                message.get("Version"),
                "dist_info",
                None,
                "Name,Version",
            )
        )
    for index, requirement in enumerate(message.get_all("Requires-Dist", [])):
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match:
            name = match.group(1)
            facts.append(
                _dependency_fact(
                    factory,
                    candidate,
                    name,
                    _version_spec(requirement[len(name) :].split(";", 1)[0]),
                    "dist_info",
                    None,
                    f"Requires-Dist:{index}",
                )
            )
    return facts


def _parse_pyproject(
    candidate: _Candidate,
    factory: _FactFactory,
) -> tuple[list[DependencyFact], list[EntrypointFact], list[ConfigFact]]:
    try:
        with candidate.path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError):
        return [], [], []
    dependencies: list[DependencyFact] = []
    project = document.get("project", {})
    for index, requirement in enumerate(project.get("dependencies", []) if isinstance(project, dict) else []):
        if not isinstance(requirement, str):
            continue
        match = _REQUIREMENT_NAME_RE.match(requirement)
        if match:
            name = match.group(1)
            dependencies.append(
                _dependency_fact(
                    factory,
                    candidate,
                    name,
                    _version_spec(requirement[len(name) :]),
                    "pyproject",
                    None,
                    f"project.dependencies.{index}",
                )
            )
    poetry = document.get("tool", {}).get("poetry", {}) if isinstance(document.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        for name, value in poetry.get("dependencies", {}).items():
            if name.lower() == "python":
                continue
            version = value if isinstance(value, str) else value.get("version") if isinstance(value, dict) else None
            dependencies.append(
                _dependency_fact(factory, candidate, name, version, "pyproject", None, f"tool.poetry.dependencies.{name}")
            )
    entries: list[EntrypointFact] = []
    scripts = project.get("scripts", {}) if isinstance(project, dict) else {}
    poetry_scripts = poetry.get("scripts", {}) if isinstance(poetry, dict) else {}
    for group_name, group in (("project.scripts", scripts), ("tool.poetry.scripts", poetry_scripts)):
        if not isinstance(group, dict):
            continue
        for name, target in group.items():
            if isinstance(target, str):
                entries.append(_named_entrypoint(factory, candidate, name, target, "project_script", group_name))
    configs = [
        ConfigFact(
            fact_id=factory.fact_id("config", "project", key, candidate.relative),
            evidence=factory.evidence(
                candidate,
                extractor="pyproject_metadata",
                summary=f"Project configuration section {key}; values omitted",
                metadata_key=key,
            ),
            category="project",
            key=key,
            value_type="section",
            is_sensitive=False,
        )
        for key in sorted(document)
    ]
    return dependencies, entries, configs


def _parse_setup_cfg(
    candidate: _Candidate,
    factory: _FactFactory,
) -> tuple[list[DependencyFact], list[EntrypointFact]]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(candidate.path, encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        return [], []
    dependencies: list[DependencyFact] = []
    if parser.has_option("options", "install_requires"):
        for index, requirement in enumerate(parser.get("options", "install_requires").splitlines()):
            match = _REQUIREMENT_NAME_RE.match(requirement)
            if match:
                name = match.group(1)
                dependencies.append(
                    _dependency_fact(
                        factory,
                        candidate,
                        name,
                        _version_spec(requirement[len(name) :]),
                        "setup",
                        None,
                        f"options.install_requires.{index}",
                    )
                )
    entries: list[EntrypointFact] = []
    section = "options.entry_points"
    if parser.has_option(section, "console_scripts"):
        for line in parser.get(section, "console_scripts").splitlines():
            if "=" in line:
                name, target = (part.strip() for part in line.split("=", 1))
                entries.append(_named_entrypoint(factory, candidate, name, target, "project_script", section))
    return dependencies, entries


def _parse_setup_py(
    tree: ast.AST,
    candidate: _Candidate,
    factory: _FactFactory,
) -> tuple[list[DependencyFact], list[EntrypointFact]]:
    dependencies: list[DependencyFact] = []
    entries: list[EntrypointFact] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _expression_name(node.func) not in {"setup", "setuptools.setup"}:
            continue
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        for index, requirement in enumerate(_literal_strings(keywords.get("install_requires"))):
            match = _REQUIREMENT_NAME_RE.match(requirement)
            if match:
                name = match.group(1)
                dependencies.append(
                    _dependency_fact(
                        factory,
                        candidate,
                        name,
                        _version_spec(requirement[len(name) :]),
                        "setup",
                        node.lineno,
                        f"install_requires.{index}",
                    )
                )
        entry_points = _literal_mapping(keywords.get("entry_points"))
        for line in entry_points.get("console_scripts", []):
            if "=" in line:
                name, target = (part.strip() for part in line.split("=", 1))
                entries.append(_named_entrypoint(factory, candidate, name, target, "project_script", "entry_points"))
    return dependencies, entries


def _parse_entry_points(
    candidate: _Candidate,
    factory: _FactFactory,
    kind: str,
) -> list[EntrypointFact]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(candidate.path, encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        return []
    if not parser.has_section("console_scripts"):
        return []
    return [
        _named_entrypoint(factory, candidate, name, target, kind, f"console_scripts.{name}")
        for name, target in parser.items("console_scripts")
    ]


def _parse_lock(candidate: _Candidate, factory: _FactFactory) -> list[DependencyFact]:
    if candidate.path.name == "Pipfile.lock":
        try:
            document = json.loads(candidate.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return []
        facts: list[DependencyFact] = []
        for section in ("default", "develop"):
            values = document.get(section, {})
            if not isinstance(values, dict):
                continue
            for name, details in values.items():
                version = details.get("version") if isinstance(details, dict) else None
                facts.append(_dependency_fact(factory, candidate, name, version, "lock", None, f"{section}.{name}"))
        return facts
    try:
        with candidate.path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError):
        return _parse_plain_lock(candidate, factory)
    packages = document.get("package", document.get("packages", []))
    if isinstance(packages, dict):
        packages = packages.get("packages", packages.get("dependencies", []))
    facts = []
    if isinstance(packages, list):
        for index, package in enumerate(packages):
            if isinstance(package, dict) and isinstance(package.get("name"), str):
                facts.append(
                    _dependency_fact(
                        factory,
                        candidate,
                        package["name"],
                        package.get("version") if isinstance(package.get("version"), str) else None,
                        "lock",
                        None,
                        f"package.{index}",
                    )
                )
    return facts


def _dependency_fact(
    factory: _FactFactory,
    candidate: _Candidate,
    name: str,
    version: str | None,
    source: str,
    line: int | None,
    metadata_key: str,
) -> DependencyFact:
    clean_version = version.strip() if isinstance(version, str) and version.strip() else None
    evidence = factory.evidence(
        candidate,
        extractor=f"{source}_metadata",
        summary=f"Dependency {name} declared by {source}",
        line_start=line,
        line_end=line,
        metadata_key=metadata_key if line is None else None,
    )
    return DependencyFact(
        fact_id=factory.fact_id("dependency", candidate.relative, name.lower(), clean_version, source, metadata_key),
        evidence=evidence,
        name=name,
        version=clean_version,
        source=source,
    )


def _named_entrypoint(
    factory: _FactFactory,
    candidate: _Candidate,
    name: str,
    target: str,
    kind: str,
    metadata_key: str,
) -> EntrypointFact:
    module, separator, symbol = target.partition(":")
    return EntrypointFact(
        fact_id=factory.fact_id("entrypoint", kind, name, module, symbol, candidate.relative),
        evidence=factory.evidence(
            candidate,
            extractor="dist_info_entrypoint" if kind == "console_script" else "project_entrypoint",
            summary=f"{kind} {name} targets {module}{':' + symbol if separator else ''}",
            metadata_key=metadata_key,
        ),
        kind=kind,
        name=name,
        module=module.strip() or None,
        symbol=symbol.strip() or None,
    )


def _limitation(
    factory: _FactFactory,
    candidate: _Candidate | None,
    *,
    code: str,
    message: str,
    line: int | None = None,
    module: str | None = None,
    config_key: str | None = None,
) -> StaticAnalysisLimitation:
    return StaticAnalysisLimitation(
        fact_id=factory.fact_id("limitation", code, candidate.relative if candidate else "", line, message),
        evidence=factory.evidence(
            candidate,
            extractor="static_inventory" if candidate is None else "python_ast",
            summary=message,
            line_start=line,
            line_end=line,
            python_module=module,
            config_key=config_key,
            content=code.encode("ascii"),
        ),
        code=code,
        message=message,
    )


def _source_recovery(
    *,
    source_modules: set[str],
    compiled_modules: set[str],
    syntax_errors: int,
    skipped_sources: int,
    metadata_present: bool,
) -> str:
    if source_modules:
        missing_source = any(module not in source_modules for module in compiled_modules)
        return "partial" if syntax_errors or skipped_sources or missing_source else "complete"
    if syntax_errors or skipped_sources:
        return "partial"
    if compiled_modules:
        return "bytecode_only"
    if metadata_present:
        return "metadata_only"
    return "none"


def _sanitize_command(command: tuple[str, ...]) -> tuple[str, ...]:
    sanitized: list[str] = []
    redact_next = False
    for item in command:
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        if item.startswith("-"):
            option, separator, _ = item.partition("=")
            key = option.lstrip("-")
            if _is_sensitive_key(key):
                if separator:
                    sanitized.append(f"{option}=[REDACTED]")
                else:
                    sanitized.append(item)
                    redact_next = True
                continue
        sanitized.append(item)
    return tuple(sanitized)


def _expression_name(node: ast.AST | None) -> str | None:
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


_FRAMEWORK_STRUCTURAL_CALLS = {
    "AgentExecutor",
    "AskHuman",
    "BaseTool",
    "ChatPromptTemplate",
    "MCPClients",
    "MessagesPlaceholder",
    "PlanningFlow",
    "PromptTemplate",
    "StateGraph",
    "Tool",
    "ToolCollection",
    "add_conditional_edges",
    "add_edge",
    "add_node",
    "bind_tools",
    "compile",
    "set_conditional_entry_point",
    "set_entry_point",
}
_STRUCTURAL_VALUE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,79}$")


def _is_framework_structural_call(callee: str) -> bool:
    return callee.rsplit(".", 1)[-1] in _FRAMEWORK_STRUCTURAL_CALLS


def _structural_argument(node: ast.AST) -> str | None:
    name = _expression_name(node)
    if name is not None:
        return name
    value = _string_constant(node)
    if value is not None and _STRUCTURAL_VALUE_RE.fullmatch(value):
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_structural_argument(item) for item in node.elts]
        if items and all(item is not None for item in items):
            return f"[{','.join(item for item in items if item is not None)}]"
    if isinstance(node, ast.Dict):
        items = [(_structural_argument(key), _structural_argument(value)) for key, value in zip(node.keys, node.values)]
        if items and all(key is not None and value is not None for key, value in items):
            return "{" + ",".join(f"{key}:{value}" for key, value in items) + "}"
    return None


def _framework_positional_arguments(callee: str, node: ast.Call) -> tuple[str | None, ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(_structural_argument(argument) for argument in node.args)


def _framework_keyword_arguments(callee: str, node: ast.Call) -> tuple[tuple[str, str | None], ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(
        (keyword.arg, _structural_argument(keyword.value))
        for keyword in node.keywords
        if keyword.arg is not None
    )


_FRAMEWORK_STRUCTURAL_CALLS = {
    "AgentExecutor",
    "AskHuman",
    "BaseTool",
    "ChatPromptTemplate",
    "MCPClients",
    "MessagesPlaceholder",
    "PlanningFlow",
    "PromptTemplate",
    "StateGraph",
    "Tool",
    "ToolCollection",
    "add_conditional_edges",
    "add_edge",
    "add_node",
    "bind_tools",
    "compile",
    "set_conditional_entry_point",
    "set_entry_point",
}
_STRUCTURAL_VALUE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,79}$")


def _is_framework_structural_call(callee: str) -> bool:
    return callee.rsplit(".", 1)[-1] in _FRAMEWORK_STRUCTURAL_CALLS


def _structural_argument(node: ast.AST) -> str | None:
    name = _expression_name(node)
    if name is not None:
        return name
    value = _string_constant(node)
    if value is not None and _STRUCTURAL_VALUE_RE.fullmatch(value):
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_structural_argument(item) for item in node.elts]
        if items and all(item is not None for item in items):
            return f"[{','.join(item for item in items if item is not None)}]"
    if isinstance(node, ast.Dict):
        items = [(_structural_argument(key), _structural_argument(value)) for key, value in zip(node.keys, node.values)]
        if items and all(key is not None and value is not None for key, value in items):
            return "{" + ",".join(f"{key}:{value}" for key, value in items) + "}"
    return None


def _framework_positional_arguments(callee: str, node: ast.Call) -> tuple[str | None, ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(_structural_argument(argument) for argument in node.args)


def _framework_keyword_arguments(callee: str, node: ast.Call) -> tuple[tuple[str, str | None], ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(
        (keyword.arg, _structural_argument(keyword.value))
        for keyword in node.keywords
        if keyword.arg is not None
    )


_FRAMEWORK_STRUCTURAL_CALLS = {
    "AgentExecutor",
    "AskHuman",
    "BaseTool",
    "ChatPromptTemplate",
    "MCPClients",
    "MessagesPlaceholder",
    "PlanningFlow",
    "PromptTemplate",
    "StateGraph",
    "Tool",
    "ToolCollection",
    "add_conditional_edges",
    "add_edge",
    "add_node",
    "bind_tools",
    "compile",
    "set_conditional_entry_point",
    "set_entry_point",
}
_STRUCTURAL_VALUE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,79}$")


def _is_framework_structural_call(callee: str) -> bool:
    return callee.rsplit(".", 1)[-1] in _FRAMEWORK_STRUCTURAL_CALLS


def _structural_argument(node: ast.AST) -> str | None:
    name = _expression_name(node)
    if name is not None:
        return name
    value = _string_constant(node)
    if value is not None and _STRUCTURAL_VALUE_RE.fullmatch(value):
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_structural_argument(item) for item in node.elts]
        if items and all(item is not None for item in items):
            return f"[{','.join(item for item in items if item is not None)}]"
    if isinstance(node, ast.Dict):
        items = [(_structural_argument(key), _structural_argument(value)) for key, value in zip(node.keys, node.values)]
        if items and all(key is not None and value is not None for key, value in items):
            return "{" + ",".join(f"{key}:{value}" for key, value in items) + "}"
    return None


def _framework_positional_arguments(callee: str, node: ast.Call) -> tuple[str | None, ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(_structural_argument(argument) for argument in node.args)


def _framework_keyword_arguments(callee: str, node: ast.Call) -> tuple[tuple[str, str | None], ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(
        (keyword.arg, _structural_argument(keyword.value))
        for keyword in node.keywords
        if keyword.arg is not None
    )


_FRAMEWORK_STRUCTURAL_CALLS = {
    "AgentExecutor",
    "AskHuman",
    "BaseTool",
    "ChatPromptTemplate",
    "MCPClients",
    "MessagesPlaceholder",
    "PlanningFlow",
    "PromptTemplate",
    "StateGraph",
    "Tool",
    "ToolCollection",
    "add_conditional_edges",
    "add_edge",
    "add_node",
    "bind_tools",
    "compile",
    "set_conditional_entry_point",
    "set_entry_point",
}
_STRUCTURAL_VALUE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,79}$")


def _is_framework_structural_call(callee: str) -> bool:
    return callee.rsplit(".", 1)[-1] in _FRAMEWORK_STRUCTURAL_CALLS


def _structural_argument(node: ast.AST) -> str | None:
    name = _expression_name(node)
    if name is not None:
        return name
    value = _string_constant(node)
    if value is not None and _STRUCTURAL_VALUE_RE.fullmatch(value):
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_structural_argument(item) for item in node.elts]
        if items and all(item is not None for item in items):
            return f"[{','.join(item for item in items if item is not None)}]"
    if isinstance(node, ast.Dict):
        items = [(_structural_argument(key), _structural_argument(value)) for key, value in zip(node.keys, node.values)]
        if items and all(key is not None and value is not None for key, value in items):
            return "{" + ",".join(f"{key}:{value}" for key, value in items) + "}"
    return None


def _framework_positional_arguments(callee: str, node: ast.Call) -> tuple[str | None, ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(_structural_argument(argument) for argument in node.args)


def _framework_keyword_arguments(callee: str, node: ast.Call) -> tuple[tuple[str, str | None], ...]:
    if not _is_framework_structural_call(callee):
        return ()
    return tuple(
        (keyword.arg, _structural_argument(keyword.value))
        for keyword in node.keywords
        if keyword.arg is not None
    )


def _assignment_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _expression_name(node)
    return None


def _string_constant(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _environment_key(node: ast.Call) -> str | None:
    callee = _expression_name(node.func)
    if callee not in {"os.getenv", "os.environ.get", "environ.get"} or not node.args:
        return None
    return _string_constant(node.args[0])


def _literal_strings(node: ast.AST | None) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    return [value for item in node.elts if (value := _string_constant(item)) is not None]


def _literal_mapping(node: ast.AST | None) -> dict[str, list[str]]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, list[str]] = {}
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        key = _string_constant(key_node) if key_node is not None else None
        if key:
            result[key] = _literal_strings(value_node)
    return result


def _version_spec(value: str) -> str | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.startswith("["):
        closing = cleaned.find("]")
        cleaned = cleaned[closing + 1 :] if closing >= 0 else ""
    cleaned = cleaned.strip()
    return cleaned or None


def _read_lines(candidate: _Candidate) -> list[str]:
    try:
        return candidate.path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(key))


def _looks_like_config_name(name: str) -> bool:
    leaf = name.rsplit(".", 1)[-1]
    return leaf.isupper() or _is_sensitive_key(leaf) or leaf.lower().endswith(("_url", "_host", "_path"))


def _dedupe(items: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for item in items:
        if item.fact_id not in seen:
            seen.add(item.fact_id)
            result.append(item)
    return sorted(result, key=lambda item: item.fact_id)
