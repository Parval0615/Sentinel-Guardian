from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


ImageArtifactType = Literal["docker_archive", "oci_layout"]
FileType = Literal["file", "directory", "symlink", "hardlink"]


class ImageArtifactError(ValueError):
    """Raised when an image artifact is malformed, unsafe, or exceeds a limit."""


@dataclass(frozen=True)
class ImageExtractionLimits:
    max_layers: int = 128
    max_files: int = 100_000
    max_single_file_size: int = 512 * 1024 * 1024
    max_total_extracted_size: int = 4 * 1024 * 1024 * 1024
    max_path_depth: int = 64
    max_metadata_size: int = 16 * 1024 * 1024
    max_layer_archive_size: int = 2 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


@dataclass(frozen=True)
class SanitizedImageConfig:
    entrypoint: tuple[str, ...] = ()
    cmd: tuple[str, ...] = ()
    working_dir: str = "/"
    platform: str = "unknown/unknown"
    created: str | None = None
    env_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class FileRecord:
    path: str
    file_type: FileType
    size: int
    layer_digest: str
    sha256: str | None = None
    link_target: str | None = None


@dataclass(frozen=True)
class LayerRecord:
    digest: str
    size: int
    file_count: int
    whiteouts: tuple[str, ...] = ()
    opaque_directories: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedImageArtifact:
    image_type: ImageArtifactType
    image_digest: str
    config: SanitizedImageConfig
    layers: tuple[LayerRecord, ...]
    files: tuple[FileRecord, ...]
    rootfs_path: Path
    _owned_paths: tuple[Path, ...] = field(default=(), repr=False, compare=False)
