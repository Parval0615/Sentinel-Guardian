"""Dependency policy for the research-oriented package layout."""

from __future__ import annotations


LAYER_ORDER = (
    "core",
    "profiling",
    "attacks",
    "defenses",
    "runtime",
    "evaluation",
    "evolution",
    "research",
    "reporting",
    "adapters",
    "application",
    "apps",
    "cli",
    "migration",
)

ALLOWED_INTERNAL_DEPENDENCIES: dict[str, frozenset[str]] = {
    "core": frozenset(),
    "profiling": frozenset({"core"}),
    "attacks": frozenset({"application", "core", "defenses", "profiling", "runtime"}),
    "defenses": frozenset({"application", "attacks", "core", "evaluation"}),
    "runtime": frozenset({"attacks", "core"}),
    "evaluation": frozenset(
        {"application", "attacks", "core", "defenses", "reporting", "runtime"}
    ),
    "evolution": frozenset({"core", "attacks", "defenses", "evaluation", "runtime"}),
    "research": frozenset({"core", "attacks", "defenses", "evaluation", "evolution", "runtime"}),
    "reporting": frozenset({"application", "core", "evaluation", "evolution"}),
    "adapters": frozenset({"application", "core", "defenses", "runtime"}),
    "application": frozenset(
        {"core", "profiling", "attacks", "defenses", "runtime", "evaluation", "research", "reporting", "adapters"}
    ),
    "apps": frozenset({"application", "defenses"}),
    "cli": frozenset(
        {
            "application",
            "core",
            "profiling",
            "attacks",
            "defenses",
            "runtime",
            "evaluation",
            "evolution",
            "research",
            "reporting",
        }
    ),
    "migration": frozenset({"core", "research"}),
}


def package_layer(module_name: str) -> str | None:
    parts = module_name.split(".")
    if len(parts) < 2 or parts[0] != "redsentinel":
        return None
    return parts[1]


def is_allowed_internal_dependency(importer: str, imported: str) -> bool:
    importer_layer = package_layer(importer)
    imported_layer = package_layer(imported)
    if importer_layer is None or imported_layer is None:
        return True
    if importer_layer == imported_layer:
        return True
    return imported_layer in ALLOWED_INTERNAL_DEPENDENCIES.get(importer_layer, frozenset())


__all__ = [
    "ALLOWED_INTERNAL_DEPENDENCIES",
    "LAYER_ORDER",
    "is_allowed_internal_dependency",
    "package_layer",
]
