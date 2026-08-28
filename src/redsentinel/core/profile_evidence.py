from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


EvidenceMethod = Literal["image_config", "package_metadata", "static", "framework", "semantic", "dynamic"]
EvidenceTrustLevel = Literal["static", "attested", "observed"]


class EvidenceLocator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    image_path: str | None = Field(default=None, min_length=1)
    python_module: str | None = Field(default=None, min_length=1)
    symbol: str | None = Field(default=None, min_length=1)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    package_metadata_key: str | None = Field(default=None, min_length=1)
    config_key: str | None = Field(default=None, min_length=1)
    event_id: str | None = Field(default=None, min_length=1)

    @field_validator("image_path")
    @classmethod
    def image_path_must_be_normalized(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if "\\" in value or ".." in PurePosixPath(value).parts:
            raise ValueError("evidence image path must be normalized and cannot traverse")
        normalized = str(PurePosixPath(value))
        if normalized != value:
            raise ValueError("evidence image path must be normalized")
        return value

    @model_validator(mode="after")
    def validate_location(self) -> EvidenceLocator:
        if (self.line_start is None) != (self.line_end is None):
            raise ValueError("evidence line range requires both line_start and line_end")
        if self.line_start is not None and self.line_end is not None and self.line_end < self.line_start:
            raise ValueError("evidence line_end must not precede line_start")
        if not any((self.image_path, self.package_metadata_key, self.config_key, self.event_id)):
            raise ValueError("evidence locator requires an image, package, config, or event location")
        return self


class ProfileEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    layer_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    locator: EvidenceLocator
    extractor: str = Field(min_length=1)
    method: EvidenceMethod
    trust_level: EvidenceTrustLevel
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    summary: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def infer_legacy_trust_level(cls, value: object) -> object:
        if isinstance(value, dict) and "trust_level" not in value:
            payload = dict(value)
            payload["trust_level"] = "attested" if payload.get("method") == "dynamic" else "static"
            return payload
        return value

    @model_validator(mode="after")
    def validate_trust_level(self) -> ProfileEvidence:
        if self.method == "dynamic" and self.trust_level == "static":
            raise ValueError("dynamic evidence cannot use static trust")
        if self.method != "dynamic" and self.trust_level != "static":
            raise ValueError("non-dynamic evidence must use static trust")
        return self


__all__ = [
    "EvidenceLocator",
    "EvidenceMethod",
    "EvidenceTrustLevel",
    "ProfileEvidence",
]
