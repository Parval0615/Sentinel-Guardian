"""Unified command-line interface for RedSentinel research workflows."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from redsentinel.application.audit_contracts import AuditTask
from redsentinel.application import ProductApplicationService
from redsentinel.core.models import ExperimentManifest
from redsentinel.profiling import build_agent_security_profile, load_agent_config, validate_agent_config
from redsentinel.research.analysis import analyze_files, write_analysis_artifacts
from redsentinel.research.catalog import DEFAULT_RQ_MATRIX_PATH, list_rq_experiment_matrix
from redsentinel.research.provenance import persist_run_evidence

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_ENVIRONMENT_ERROR = 3
EXIT_EXECUTION_ERROR = 4

CommandHandler = Callable[[argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    """Build the stable research CLI parser without executing a command."""
    parser = argparse.ArgumentParser(
        prog="redsentinel",
        description="Agent security evaluation and co-evolution research framework.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    profile = _command_parser(subparsers, "profile", "Validate an agent manifest and generate its profile.")
    profile.add_argument("config", type=Path)
    profile.add_argument("--output", type=Path)
    profile.set_defaults(handler=_profile)

    audit = _command_parser(
        subparsers,
        "audit",
        "Run or resume an autonomous pre-deployment security audit.",
        allow_external_model=False,
    )
    audit.add_argument("task", nargs="?", type=Path, help="Path to an audit-task-v0.1 JSON file.")
    audit.add_argument("--resume", metavar="AUDIT_ID")
    audit.add_argument("--tenant-id", default="private_tenant")
    audit.add_argument("--storage-root", type=Path, default=Path("runs/product"))
    audit.set_defaults(handler=_audit, external_model_config=None)

    evaluate = _command_parser(subparsers, "evaluate", "Run the deterministic single-round evaluation smoke.")
    evaluate.set_defaults(handler=_evaluate)

    evolve = _command_parser(subparsers, "evolve", "Run the deterministic co-evolution evidence smoke.")
    evolve.set_defaults(handler=_evolve)

    demo = _command_parser(
        subparsers,
        "demo",
        "Run the complete deterministic P0 interview demo.",
        allow_external_model=False,
    )
    demo.add_argument(
        "--profile-config",
        type=Path,
        default=_repo_root() / "examples" / "agents" / "simple_agent" / "redsentinel.yaml",
    )
    demo.set_defaults(handler=_demo, external_model_config=None)

    experiment = _command_parser(subparsers, "experiment", "Inspect the validated RQ1-RQ5 experiment matrix.")
    experiment.add_argument("--rq", choices=["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"])
    experiment.add_argument("--config", type=Path, default=DEFAULT_RQ_MATRIX_PATH)
    experiment.add_argument("--format", choices=["json", "yaml"], default="json")
    experiment.set_defaults(handler=_experiment)

    report = _command_parser(subparsers, "report", "Aggregate experiment JSON and generate paper artifacts.")
    report.add_argument("inputs", nargs="+", type=Path)
    report.add_argument("--svg", action="store_true", help="Use the standard-library SVG renderer.")
    report.set_defaults(handler=_report)

    doctor = _command_parser(subparsers, "doctor", "Inspect local research runtime prerequisites.")
    doctor.add_argument(
        "--real-openmanus",
        action="store_true",
        help="Require Docker, the pinned OpenManus image, vendored source, and model environment.",
    )
    doctor.set_defaults(handler=_doctor)
    return parser


def _command_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    *,
    allow_external_model: bool = True,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(name, help=help_text)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true")
    if allow_external_model:
        parser.add_argument(
            "--external-model-config",
            type=Path,
            help="JSON provenance metadata: provider, model, temperature, parameters, cache_policy.",
        )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one CLI command and return a stable process exit code.

    Command artifacts are written only by the selected handler. Expected input
    and environment failures are converted to documented non-zero exit codes.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
        force=True,
    )
    try:
        return int(args.handler(args))
    except (ValueError, OSError) as exc:
        print(f"ERROR={exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except ModuleNotFoundError as exc:
        print(f"ERROR=missing optional dependency: {exc.name}", file=sys.stderr)
        return EXIT_ENVIRONMENT_ERROR
    except Exception as exc:  # CLI boundary converts unexpected failures into a stable exit contract.
        logging.getLogger(__name__).exception("command failed")
        print(f"ERROR={type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_EXECUTION_ERROR


def _profile(args: argparse.Namespace) -> int:
    config = load_agent_config(args.config)
    validate_agent_config(config, config_path=args.config)
    output = args.output or args.output_dir / "profiles" / f"{config.agent.name}.json"
    if args.dry_run:
        _print_common(args, mode="profile", output=output)
        print("CONFIG_VALID=true")
        return EXIT_OK
    profile = build_agent_security_profile(config)
    _write_json(output, profile.model_dump(mode="json"))
    _print_common(args, mode="profile", output=output)
    print(f"NODES={len(profile.nodes)}")
    return EXIT_OK


def _audit(args: argparse.Namespace) -> int:
    if args.resume:
        if args.task is not None:
            raise ValueError("task path cannot be combined with --resume")
        if args.dry_run:
            _print_common(args, mode="audit-resume", output=args.storage_root)
            print(f"AUDIT_ID={args.resume}")
            print("EXECUTION=skipped")
            return EXIT_OK
        application = ProductApplicationService(storage_root=args.storage_root)
        run = application.resume_audit(args.resume, tenant_id=args.tenant_id)
    else:
        if args.task is None:
            raise ValueError("audit task path is required unless --resume is used")
        if not args.task.is_file():
            raise ValueError(f"audit task does not exist: {args.task}")
        task = AuditTask.model_validate_json(args.task.read_text(encoding="utf-8"))
        if args.dry_run:
            output = args.storage_root / task.tenant_id / "audits" / task.audit_id
            _print_common(args, mode="audit", output=output)
            print(f"AUDIT_ID={task.audit_id}")
            print(f"AGENT_ID={task.agent_id}")
            print("TASK_VALID=true")
            print("EXECUTION=skipped")
            return EXIT_OK
        application = ProductApplicationService(storage_root=args.storage_root)
        application.create_audit(task)
        run = application.run_audit(task.audit_id, tenant_id=task.tenant_id)

    _print_common(args, mode="audit", output=application.storage.audit_dir(run.tenant_id, run.audit_id))
    status = application.get_audit_status(run.audit_id, tenant_id=run.tenant_id)
    print(f"AUDIT_ID={run.audit_id}")
    print(f"STATE={run.state}")
    print(f"PROGRESS={status.progress_percent:.1f}%")
    print(f"DURATION_MS={status.total_duration_ms}")
    if status.evidence_index_ref:
        print(f"EVIDENCE_INDEX={status.evidence_index_ref}")
    if run.decision_ref:
        decision = application.get_audit_decision(run.audit_id, tenant_id=run.tenant_id)
        print(f"DECISION={decision.decision}")
        print(f"DECISION_PATH={run.decision_ref}")
    if run.error:
        print(f"ERROR={run.error}", file=sys.stderr)
    return EXIT_EXECUTION_ERROR if run.state == "failed" else EXIT_OK


def _evaluate(args: argparse.Namespace) -> int:
    output_root = args.output_dir / "evaluations"
    if args.dry_run:
        _print_common(args, mode="evaluate", output=output_root)
        print("EXECUTION=skipped")
        return EXIT_OK
    result, evidence = _run_evaluation(args)
    _print_common(args, mode="evaluate", output=result.run_dir)
    print(f"PROVENANCE={evidence.provenance_path}")
    print(f"EVIDENCE_INDEX={evidence.evidence_index_path}")
    print(f"PASSED={result.metrics['passed_pairs']}/{result.metrics['total_attack_pairs']}")
    return EXIT_OK if result.metrics["all_passed"] else EXIT_EXECUTION_ERROR


def _run_evaluation(args: argparse.Namespace) -> tuple[Any, Any]:
    from redsentinel.evaluation.engine.runner import run_comp1_demo

    result = run_comp1_demo(repo_root=_repo_root(), runs_root=args.output_dir / "evaluations")
    manifest = _cli_manifest(
        args,
        command="evaluate",
        experiment_id=f"evaluate-{Path(result.run_dir).name}",
        dataset_refs=["redsentinel-attack-cases", "redsentinel-trajectory-fixtures"],
        metric_names=["asr", "fpr", "coverage"],
    )
    evidence = persist_run_evidence(
        manifest,
        experiment_dir=result.run_dir,
        raw_result={
            "schema_version": "cli-evaluation-result-v1",
            "metrics": _json_safe(result.metrics),
            "artifacts": _json_safe(result.artifacts),
        },
        repo_root=_repo_root(),
    )
    return result, evidence


def _evolve(args: argparse.Namespace) -> int:
    output_root = args.output_dir / "evolution"
    if args.dry_run:
        _print_common(args, mode="evolve", output=output_root)
        print("EXECUTION=skipped")
        return EXIT_OK
    result, evidence = _run_evolution(args)
    _print_common(args, mode="evolve", output=result.run_dir)
    print(f"PROVENANCE={evidence.provenance_path}")
    print(f"EVIDENCE_INDEX={evidence.evidence_index_path}")
    print(f"ASR_INITIAL={result.metrics['asr_initial']:.6f}")
    print(f"ASR_FINAL={result.metrics['asr_final']:.6f}")
    return EXIT_OK if result.metrics["asr_target_met"] else EXIT_EXECUTION_ERROR


def _run_evolution(args: argparse.Namespace) -> tuple[Any, Any]:
    from redsentinel.evaluation.engine.comp4_evidence import run_comp4_demo

    result = run_comp4_demo(
        repo_root=_repo_root(),
        runs_root=args.output_dir / "evolution",
        force_offline=True,
    )
    manifest = _cli_manifest(
        args,
        command="evolve",
        experiment_id=f"evolve-{Path(result.run_dir).name}",
        dataset_refs=["redsentinel-attack-cases", "redsentinel-benign-cases"],
        metric_names=["asr", "fpr", "business_success_rate", "overhead"],
    )
    evidence = persist_run_evidence(
        manifest,
        experiment_dir=result.run_dir,
        raw_result={
            "schema_version": "cli-evolution-result-v1",
            "metrics": _json_safe(result.metrics),
            "artifacts": _json_safe(result.artifacts),
        },
        repo_root=_repo_root(),
    )
    return result, evidence


def _demo(args: argparse.Namespace) -> int:
    if args.external_model_config is not None:
        raise ValueError("P0 demo is offline-only; external model configuration is not accepted")

    config = load_agent_config(args.profile_config)
    validate_agent_config(config, config_path=args.profile_config)
    output_root = (args.output_dir / "p0-demo").resolve()
    if args.dry_run:
        _print_common(args, mode="demo", output=output_root)
        print("STAGES=doctor,profile,evaluate,evolve,evidence")
        print("EXECUTION=skipped")
        return EXIT_OK

    checks = _doctor_checks()
    profile = build_agent_security_profile(config)
    profile_path = output_root / "profiles" / f"{config.agent.name}.json"
    _write_json(profile_path, profile.model_dump(mode="json"))

    demo_args = argparse.Namespace(**vars(args))
    demo_args.output_dir = output_root
    evaluation, evaluation_evidence = _run_evaluation(demo_args)
    evolution, evolution_evidence = _run_evolution(demo_args)

    from redsentinel.research.p0_demo import write_p0_demo_summary

    summary_path = write_p0_demo_summary(
        output_root=output_root,
        seed=args.seed,
        doctor_checks=checks,
        profile_path=profile_path,
        evaluation_dir=Path(evaluation.run_dir),
        evaluation_evidence_index=Path(evaluation_evidence.evidence_index_path),
        evolution_dir=Path(evolution.run_dir),
        evolution_evidence_index=Path(evolution_evidence.evidence_index_path),
    )
    _print_common(args, mode="demo", output=output_root)
    print("EXECUTION_MODE=offline_fixture")
    print(f"PROFILE={profile_path}")
    print(f"EVALUATION_EVIDENCE={evaluation_evidence.evidence_index_path}")
    print(f"EVOLUTION_EVIDENCE={evolution_evidence.evidence_index_path}")
    print(f"SUMMARY={summary_path}")
    print(f"PAIRED_CASES={evaluation.metrics['passed_pairs']}/{evaluation.metrics['total_attack_pairs']}")
    print(f"FPR={evaluation.metrics['false_positive_rate']:.6f}")
    print(f"ASR_INITIAL={evolution.metrics['asr_initial']:.6f}")
    print(f"ASR_FINAL={evolution.metrics['asr_final']:.6f}")
    print("BUSINESS_SUCCESS_RATE=not_evaluated")
    print("OVERHEAD=not_evaluated")
    passed = evaluation.metrics["all_passed"] and evolution.metrics["asr_target_met"]
    return EXIT_OK if passed else EXIT_EXECUTION_ERROR


def _experiment(args: argparse.Namespace) -> int:
    payload = list_rq_experiment_matrix(rq_id=args.rq, path=args.config)
    _print_common(args, mode="experiment", output=args.output_dir)
    if args.dry_run:
        print(f"RESEARCH_QUESTIONS={1 if args.rq else 5}")
        print("EXECUTION=skipped")
        return EXIT_OK
    if args.format == "yaml":
        import yaml

        print(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False).rstrip())
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return EXIT_OK


def _report(args: argparse.Namespace) -> int:
    output = args.output_dir / "reports"
    for path in args.inputs:
        if not path.is_file():
            raise ValueError(f"report input does not exist: {path}")
    if args.dry_run:
        _print_common(args, mode="report", output=output)
        print(f"INPUTS={len(args.inputs)}")
        print("EXECUTION=skipped")
        return EXIT_OK
    artifacts = write_analysis_artifacts(
        analyze_files(args.inputs),
        output,
        prefer_matplotlib=not args.svg,
    )
    _print_common(args, mode="report", output=output)
    for name, path in sorted(artifacts.items()):
        print(f"{name.upper()}={path}")
    return EXIT_OK


def _doctor(args: argparse.Namespace) -> int:
    checks = _doctor_checks()
    if args.real_openmanus:
        checks.update(_real_openmanus_checks())
    _print_common(args, mode="doctor", output=args.output_dir)
    for name, value in checks.items():
        print(f"{name.upper()}={str(value).lower() if isinstance(value, bool) else value}")
    required = ["rq_matrix"]
    if args.real_openmanus:
        required.extend(
            [
                "docker_daemon",
                "openmanus_image",
                "openmanus_vendor_source",
                "openai_api_key",
                "openai_base_url",
                "openai_model",
            ]
        )
    ready = all(checks[name] is True for name in required)
    print("STATUS=ready" if ready else "STATUS=degraded")
    return EXIT_OK if ready else EXIT_ENVIRONMENT_ERROR


def _doctor_checks() -> dict[str, str | bool]:
    return {
        "python": sys.version.split()[0],
        "docker_cli": shutil.which("docker") is not None,
        "openai_api_key": bool(os.environ.get("OPENAI_API_KEY")),
        "openai_base_url": bool(os.environ.get("OPENAI_BASE_URL")),
        "openai_model": bool(os.environ.get("OPENAI_MODEL")),
        "rq_matrix": DEFAULT_RQ_MATRIX_PATH.is_file(),
    }


def _real_openmanus_checks() -> dict[str, str | bool]:
    image = "redsentinel/openmanus-real:local"
    docker_daemon = _command_succeeds(["docker", "version"])
    image_available = docker_daemon and _command_succeeds(["docker", "image", "inspect", image])
    digest = "unavailable"
    if image_available:
        completed = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            digest = completed.stdout.strip()
    vendor = _repo_root() / "third_party" / "OpenManus" / "upstream"
    vendor_ready = all(
        path.is_file()
        for path in (
            vendor / "main.py",
            vendor / "app" / "agent" / "toolcall.py",
            vendor / "requirements.txt",
        )
    )
    return {
        "docker_daemon": docker_daemon,
        "openmanus_image": image_available,
        "openmanus_image_digest": digest,
        "openmanus_vendor_source": vendor_ready,
    }


def _command_succeeds(command: list[str]) -> bool:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _print_common(args: argparse.Namespace, *, mode: str, output: Path) -> None:
    print(f"COMMAND={mode}")
    print(f"SEED={args.seed}")
    print(f"DRY_RUN={str(args.dry_run).lower()}")
    print(f"OUTPUT_DIR={output}")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _cli_manifest(
    args: argparse.Namespace,
    *,
    command: str,
    experiment_id: str,
    dataset_refs: list[str],
    metric_names: list[str],
) -> ExperimentManifest:
    metadata: dict[str, Any] = {"entrypoint": f"redsentinel {command}"}
    if args.external_model_config is not None:
        metadata["external_model"] = json.loads(args.external_model_config.read_text(encoding="utf-8"))
    return ExperimentManifest(
        experiment_id=experiment_id,
        research_question=f"Compatibility {command} run through the unified audit CLI.",
        agent_profile_ref="builtin:deterministic-offline-fixture",
        dataset_refs=dataset_refs,
        attack_strategy={"name": command},
        defense_strategy={"name": command},
        metric_names=metric_names,
        seeds=[args.seed],
        repetitions=1,
        budget={"max_rounds": 7.0 if command == "evolve" else 1.0},
        execution_mode="external_model" if "external_model" in metadata else "offline_fixture",
        metadata=metadata,
    )


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


if __name__ == "__main__":
    raise SystemExit(main())
