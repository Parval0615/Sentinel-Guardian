from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from redsentinel.core.profile_evidence import ProfileEvidence


SourceRecovery = Literal["complete", "partial", "metadata_only", "bytecode_only", "none"]
SourceKind = Literal["project", "site_package", "runtime", "bytecode", "extension"]
SymbolKind = Literal["function", "async_function", "class"]
EntrypointKind = Literal["image", "module", "console_script", "project_script"]
CapabilityKind = Literal["model", "database", "mcp", "external_api", "shell", "file", "browser"]


class StaticFactModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidencedFact(StaticFactModel):
    fact_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    evidence: ProfileEvidence


class ModuleFact(EvidencedFact):
    module: str = Field(min_length=1)
    image_path: str = Field(min_length=1)
    source_kind: SourceKind
    is_package: bool = False


class SymbolFact(EvidencedFact):
    module: str = Field(min_length=1)
    qualified_name: str = Field(min_length=1)
    symbol_kind: SymbolKind
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)


class ImportFact(EvidencedFact):
    module: str = Field(min_length=1)
    imported_module: str = Field(min_length=1)
    imported_name: str | None = Field(default=None, min_length=1)
    alias: str | None = Field(default=None, min_length=1)
    line: int = Field(ge=1)


class CallFact(EvidencedFact):
    module: str = Field(min_length=1)
    caller: str = Field(min_length=1)
    callee: str = Field(min_length=1)
    line: int = Field(ge=1)
    positional_arguments: tuple[str | None, ...] = ()
    keyword_arguments: tuple[tuple[str, str | None], ...] = ()
    positional_arguments: tuple[str | None, ...] = ()
    keyword_arguments: tuple[tuple[str, str | None], ...] = ()
    positional_arguments: tuple[str | None, ...] = ()
    keyword_arguments: tuple[tuple[str, str | None], ...] = ()
    positional_arguments: tuple[str | None, ...] = ()
    keyword_arguments: tuple[tuple[str, str | None], ...] = ()


class DecoratorFact(EvidencedFact):
    module: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    decorator: str = Field(min_length=1)
    line: int = Field(ge=1)


class ClassBaseFact(EvidencedFact):
    module: str = Field(min_length=1)
    class_name: str = Field(min_length=1)
    base: str = Field(min_length=1)
    line: int = Field(ge=1)


class DependencyFact(EvidencedFact):
    name: str = Field(min_length=1)
    version: str | None = Field(default=None, min_length=1)
    source: Literal[
        "requirements",
        "pyproject",
        "setup",
        "lock",
        "dist_info",
    ]


class EntrypointFact(EvidencedFact):
    kind: EntrypointKind
    name: str = Field(min_length=1)
    module: str | None = Field(default=None, min_length=1)
    symbol: str | None = Field(default=None, min_length=1)
    command: tuple[str, ...] = ()


class ConfigFact(EvidencedFact):
    category: Literal["environment", "constant", "project"]
    key: str = Field(min_length=1)
    value_type: str = Field(min_length=1)
    is_sensitive: bool = False


class CapabilityFact(EvidencedFact):
    capability: CapabilityKind
    provider: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    module: str | None = Field(default=None, min_length=1)
    symbol: str | None = Field(default=None, min_length=1)


class StaticAnalysisLimitation(EvidencedFact):
    code: Literal[
        "syntax_error",
        "unreadable_file",
        "file_too_large",
        "source_missing",
        "source_partial",
        "dependency_source_omitted",
        "runtime_source_omitted",
    ]
    message: str = Field(min_length=1)


class StaticFactIndex(StaticFactModel):
    schema_version: Literal["static-fact-index-v0.1"] = "static-fact-index-v0.1"
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_recovery: SourceRecovery
    modules: list[ModuleFact] = Field(default_factory=list)
    symbols: list[SymbolFact] = Field(default_factory=list)
    imports: list[ImportFact] = Field(default_factory=list)
    calls: list[CallFact] = Field(default_factory=list)
    decorators: list[DecoratorFact] = Field(default_factory=list)
    class_bases: list[ClassBaseFact] = Field(default_factory=list)
    dependencies: list[DependencyFact] = Field(default_factory=list)
    entrypoints: list[EntrypointFact] = Field(default_factory=list)
    configuration: list[ConfigFact] = Field(default_factory=list)
    capabilities: list[CapabilityFact] = Field(default_factory=list)
    limitations: list[StaticAnalysisLimitation] = Field(default_factory=list)

    @field_validator(
        "modules",
        "symbols",
        "imports",
        "calls",
        "decorators",
        "class_bases",
        "dependencies",
        "entrypoints",
        "configuration",
        "capabilities",
        "limitations",
    )
    @classmethod
    def fact_ids_must_be_unique_per_collection(cls, values: list[EvidencedFact]) -> list[EvidencedFact]:
        ids = [item.fact_id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("fact ids must be unique")
        return values

    def all_evidence(self) -> list[ProfileEvidence]:
        collections = (
            self.modules,
            self.symbols,
            self.imports,
            self.calls,
            self.decorators,
            self.class_bases,
            self.dependencies,
            self.entrypoints,
            self.configuration,
            self.capabilities,
            self.limitations,
        )
        return [fact.evidence for collection in collections for fact in collection]




    @model_validator(mode="after")
    def evidence_must_match_artifact(self) -> StaticFactIndex:
        if any(evidence.artifact_digest != self.artifact_digest for evidence in self.all_evidence()):
            raise ValueError("all static fact evidence must bind to the index artifact digest")
        return self
