"""CLI for the competition P1 model matrix."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from redsentinel.application.engine.competition_matrix import (
    CompetitionMatrixRunner,
    OpenManusCellExecutor,
    load_competition_matrix,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = REPO_ROOT / "configs" / "experiments" / "competition-p1-model-matrix-v1.yaml"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the 2-model x 3-seed x 4-scenario OpenManus matrix."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-root", type=Path, default=Path("artifacts/competition-p1"))
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args(None if argv is None else list(argv))

    matrix = load_competition_matrix(args.config)
    executor = OpenManusCellExecutor(args.output_root / matrix.matrix_id / "product")
    summary = CompetitionMatrixRunner(args.output_root, executor).run(
        matrix,
        resume=not args.no_resume,
    )
    print(f"MATRIX_ID={summary.matrix_id}")
    print(f"EXPECTED_CELLS={summary.expected_cells}")
    print(f"COMPLETED_CELLS={summary.completed_cells}")
    print(f"SKIPPED_CELLS={summary.skipped_cells}")
    print(f"FAILED_CELLS={summary.failed_cells}")
    print(f"RESUMED_CELLS={summary.resumed_cells}")
    print(f"EVIDENCE_INDEX={summary.evidence_index_ref}")
    return 0 if summary.completed_cells == summary.expected_cells else 2


def cli_boundary(argv: Sequence[str] | None = None) -> int:
    try:
        return main(argv)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR={exc}", file=sys.stderr)
        return 1


__all__ = ["DEFAULT_CONFIG", "cli_boundary", "main"]


if __name__ == "__main__":
    raise SystemExit(cli_boundary())


if __name__ == "__main__":
    raise SystemExit(cli_boundary())


if __name__ == "__main__":
    raise SystemExit(cli_boundary())


if __name__ == "__main__":
    raise SystemExit(cli_boundary())
