from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from redsentinel.cli import EXIT_INPUT_ERROR, EXIT_OK, build_parser, main


REPO_ROOT = Path(__file__).resolve().parents[2]
SIMPLE_CONFIG = REPO_ROOT / "examples" / "agents" / "simple_agent" / "redsentinel.yaml"


def test_parser_exposes_audit_and_compatibility_commands() -> None:
    parser = build_parser()
    subparsers = next(action for action in parser._actions if action.dest == "command")
    assert set(subparsers.choices) == {
        "profile",
        "audit",
        "audit",
        "audit",
        "audit",
        "evaluate",
        "evolve",
        "demo",
        "experiment",
        "report",
        "doctor",
    }


@pytest.mark.parametrize("command", ["evaluate", "evolve"])
def test_execution_commands_share_common_dry_run_contract(
    command: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([command, "--dry-run", "--seed", "17", "--output-dir", str(tmp_path)]) == EXIT_OK
    output = capsys.readouterr().out
    assert f"COMMAND={command}" in output
    assert "SEED=17" in output
    assert "DRY_RUN=true" in output
    assert "EXECUTION=skipped" in output


def test_profile_dry_run_validates_manifest_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["profile", str(SIMPLE_CONFIG), "--dry-run", "--output-dir", str(tmp_path)]) == EXIT_OK
    assert "CONFIG_VALID=true" in capsys.readouterr().out
    assert not list(tmp_path.rglob("*.json"))


def test_audit_dry_run_validates_task_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    task_path = tmp_path / "audit-task.json"
    task_path.write_text(
        json.dumps(
            {
                "audit_id": "audit-1",
                "tenant_id": "tenant-1",
                "agent_id": "agent-1",
                "normal_tasks": [
                    {
                        "task_id": "normal-1",
                        "prompt": "Summarize a public document.",
                        "success_criteria": ["Summary is grounded."],
                    }
                ],
                "security_goals": ["Reject injected instructions."],
                "authorized_risk_surfaces": ["prompt_injection"],
            }
        ),
        encoding="utf-8",
    )
    storage_root = tmp_path / "storage"

    assert main(
        [
            "audit",
            str(task_path),
            "--dry-run",
            "--storage-root",
            str(storage_root),
        ]
    ) == EXIT_OK

    output = capsys.readouterr().out
    assert "AUDIT_ID=audit-1" in output
    assert "TASK_VALID=true" in output
    assert "EXECUTION=skipped" in output
    assert not storage_root.exists()


def test_audit_resume_dry_run_accepts_explicit_tenant(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(
        [
            "audit",
            "--resume",
            "audit-1",
            "--tenant-id",
            "tenant-1",
            "--dry-run",
            "--storage-root",
            str(tmp_path / "storage"),
        ]
    ) == EXIT_OK

    assert "AUDIT_ID=audit-1" in capsys.readouterr().out


def test_experiment_dry_run_validates_research_matrix(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["experiment", "--rq", "RQ2", "--dry-run"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "RESEARCH_QUESTIONS=1" in output
    assert "EXECUTION=skipped" in output


def test_demo_dry_run_validates_profile_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["demo", "--dry-run", "--output-dir", str(tmp_path)]) == EXIT_OK
    output = capsys.readouterr().out
    assert "COMMAND=demo" in output
    assert "STAGES=doctor,profile,evaluate,evolve,evidence" in output
    assert "EXECUTION=skipped" in output
    assert not list(tmp_path.rglob("*"))


def test_demo_normalizes_relative_output_before_orchestration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "run"
    evidence = SimpleNamespace(evidence_index_path=run_dir / "evidence-index-v1.json")
    monkeypatch.setattr(
        "redsentinel.cli._run_evaluation",
        lambda _args: (
            SimpleNamespace(
                run_dir=run_dir,
                metrics={
                    "passed_pairs": 3,
                    "total_attack_pairs": 3,
                    "false_positive_rate": 0.0,
                    "all_passed": True,
                },
            ),
            evidence,
        ),
    )
    monkeypatch.setattr(
        "redsentinel.cli._run_evolution",
        lambda _args: (
            SimpleNamespace(
                run_dir=run_dir,
                metrics={"asr_initial": 0.4, "asr_final": 0.0, "asr_target_met": True},
            ),
            evidence,
        ),
    )
    captured: dict[str, Path] = {}

    def fake_summary(**kwargs: object) -> Path:
        captured["output_root"] = kwargs["output_root"]  # type: ignore[assignment]
        return Path(kwargs["output_root"]) / "p0-demo-summary-v1.json"

    monkeypatch.setattr("redsentinel.research.p0_demo.write_p0_demo_summary", fake_summary)

    assert main(["demo", "--output-dir", "artifacts"]) == EXIT_OK
    assert captured["output_root"].is_absolute()
    assert captured["output_root"] == tmp_path / "artifacts" / "p0-demo"


def test_report_dry_run_requires_existing_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing.json"
    assert main(["report", str(missing), "--dry-run"]) == EXIT_INPUT_ERROR
    assert "report input does not exist" in capsys.readouterr().err


def test_doctor_is_offline_and_reports_optional_environment(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", "--dry-run"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "RQ_MATRIX=true" in output
    assert "OPENAI_API_KEY=" in output
    assert "STATUS=ready" in output


def test_doctor_real_openmanus_requires_runtime_and_model_environment(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.setattr(
        "redsentinel.cli._real_openmanus_checks",
        lambda: {
            "docker_daemon": True,
            "openmanus_image": True,
            "openmanus_image_digest": "sha256:test",
            "openmanus_vendor_source": True,
        },
    )

    assert main(["doctor", "--real-openmanus"]) != EXIT_OK
    output = capsys.readouterr().out
    assert "DOCKER_DAEMON=true" in output
    assert "OPENMANUS_IMAGE=true" in output
    assert "OPENMANUS_IMAGE_DIGEST=sha256:test" in output
    assert "OPENAI_API_KEY=false" in output
    assert "STATUS=degraded" in output


def test_pyproject_exposes_console_script() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '[project.scripts]\nredsentinel = "redsentinel.cli:main"' in text


def test_module_help_is_available_from_source_tree() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "redsentinel.cli", "--help"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "{profile,audit,evaluate,evolve,demo,experiment,report,doctor}" in result.stdout


@pytest.mark.parametrize("command", ["evaluate", "evolve"])
def test_formal_cli_runs_write_common_provenance_and_evidence_index(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / f"{command}-run"
    run_dir.mkdir()
    if command == "evaluate":
        monkeypatch.setattr(
            "redsentinel.evaluation.engine.runner.run_comp1_demo",
            lambda **_kwargs: SimpleNamespace(
                run_dir=run_dir,
                metrics={"passed_pairs": 3, "total_attack_pairs": 3, "all_passed": True},
                artifacts={},
            ),
        )
    else:
        monkeypatch.setattr(
            "redsentinel.evaluation.engine.comp4_evidence.run_comp4_demo",
            lambda **_kwargs: SimpleNamespace(
                run_dir=run_dir,
                metrics={"asr_initial": 0.4, "asr_final": 0.0, "asr_target_met": True},
                artifacts={},
            ),
        )

    assert main([command, "--output-dir", str(tmp_path), "--seed", "17"]) == EXIT_OK

    assert (run_dir / "experiment-manifest-v1.json").is_file()
    assert (run_dir / "provenance-v1.json").is_file()
    assert (run_dir / "raw-result-v1.json").is_file()
    assert (run_dir / "evidence-index-v1.json").is_file()
    provenance = (run_dir / "provenance-v1.json").read_text(encoding="utf-8")
    assert '"git_commit"' in provenance
    assert '"config_sha256"' in provenance
    assert '"dataset_sha256"' in provenance
    assert '"dependency_versions"' in provenance
    output = capsys.readouterr().out
    assert "PROVENANCE=" in output
    assert "EVIDENCE_INDEX=" in output


def test_formal_cli_rejects_external_model_secret_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = tmp_path / "evaluate-run"
    run_dir.mkdir()
    monkeypatch.setattr(
        "redsentinel.evaluation.engine.runner.run_comp1_demo",
        lambda **_kwargs: SimpleNamespace(
            run_dir=run_dir,
            metrics={"passed_pairs": 3, "total_attack_pairs": 3, "all_passed": True},
            artifacts={},
        ),
    )
    model_config = tmp_path / "model.json"
    model_config.write_text(
        '{"provider":"test","model":"fixture","temperature":0,'
        '"parameters":{"api_key":"forbidden"},"cache_policy":"disabled"}\n',
        encoding="utf-8",
    )

    assert main(
        ["evaluate", "--output-dir", str(tmp_path), "--external-model-config", str(model_config)]
    ) == EXIT_INPUT_ERROR
    assert "secret-like field is forbidden" in capsys.readouterr().err
    assert not (run_dir / "provenance-v1.json").exists()
