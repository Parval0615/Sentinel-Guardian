# Public API Documentation Policy

RedSentinel documents a deliberately small stable research API. The executable
allowlist is [`public-api.json`](public-api.json); contract tests import every
listed symbol and require a non-empty docstring.

The allowlist covers:

- versioned research contracts;
- experiment, co-evolution, analysis, and provenance entry points;
- application services used by the optional API;
- profiling, attack-data, adapter, reporting, migration, and CLI entry points.

## Image-backed Agent profile API

The desktop product accepts tenant-owned Docker archives through the upload API
and can also discover assets from `RED_SENTINEL_AGENT_ROOT` (the packaged
launcher sets this to the `agents/` directory beside the `.app`). All routes
below require a bearer token:

| Method | Path | Result |
|---|---|---|
| `POST` | `/v1/agents/import-image` | Persist a Docker archive, derive its identity, register the Agent, and queue profile generation |
| `GET` | `/v1/agents` | Refresh and list valid directory-backed Agents |
| `GET` | `/v1/agents/index-errors` | List isolated descriptor/image indexing errors |
| `POST` | `/v1/agents/{agent_id}/profiles` | Queue or reuse an image- and configuration-bound eight-stage analysis |
| `GET` | `/v1/agents/{agent_id}/profiles/{analysis_id}/status` | Read stage status, timestamps, checkpoints, and errors |
| `GET` | `/v1/agents/{agent_id}/profiles/latest` | Read the latest published `agent-profile-v0.2` |
| `GET` | `/v1/agents/{agent_id}/profiles/{profile_id}` | Read a specific immutable profile version |
| `POST` | `/v1/agents/{agent_id}/profiles/{analysis_id}/retry` | Retry from the first failed stage |

Static analysis reads the Docker archive or OCI layout without executing it.
Missing AI configuration skips `semantic_enrich`. An unavailable trusted local
runtime image fails `dynamic_verify`, but `finalize` still publishes a
`partial` profile. Informational limitations remain visible without blocking a
complete result; missing source, graph evidence, framework coverage, dynamic
corroboration, or other evidence-affecting limitations do block completeness.

`analysis.status=completed` and `completeness.conclusion=complete` are emitted
only when all required stages and coverage gates pass. The completeness object
reports static source recovery, framework coverage, graph evidence coverage,
dynamic corroboration coverage, dynamic behavior coverage, unresolved
limitation count, and blocking limitation codes. Container-provided events are
always `attested`; only an independent Sentinel-controlled host observer may
provide `observed` evidence. `analysis.configuration_digest` binds
profile-affecting descriptor settings to the profile version.

Publishing also persists an `attack-profile-v0.1` handoff. It excludes source
text and sensitive runtime configuration, and the planner converts its eligible
risk paths into AttackSpec records. Audit create and resume operations for
image-backed Agents validate the complete `image_digest`, `profile_id`, and
`profile_sha256` binding; partial bindings and version drift are rejected.
Profile publication upgrades an automatically detected OpenManus image to the
`openmanus` adapter. Other uploaded Docker assets use the Sentinel-managed SDK
experiment runner unless a dedicated runtime adapter is connected.

## OpenManus white-box audit loop

The competition workflow uses the published static image profile as the
authoritative attack-surface inventory. Dynamic profile completeness is not a
precondition for starting an audit. Each planned attack records the predicted
profile node and path, while execution records whether the attack succeeded and
the actual failed or blocking node.

`POST /v1/audits?prepare_only=true` freezes the profile and generates a
validated attack plan, then stops in `attack_review`. The user reviews each
scenario, risk surface, predicted node/path, and evidence requirement before
calling `POST /v1/audits/{audit_id}/execute?background=true`. The workflow then
runs the baseline attack set, derives and installs targeted sandbox defenses,
and reruns the set under guard. The next-round endpoint supports the same
`prepare_only=true` review gate after mutating payloads from prior results. The
workspace `round` object exposes the prediction, attack outcome, failed node,
mounted guards, and trajectory reference for every scenario.

The desktop UI configures separate `target`, `attack`, and `defense` model
slots. `POST /v1/runtime/models/{role}/test` performs a real
OpenAI-compatible JSON completion and retains the configuration only in the
current App process. `GET /v1/runtime/models/status` returns redacted readiness
state. OpenManus audit creation is rejected until all three slots have passed
their latest connection test. API keys are never returned, written into the
audit task, or included in report evidence. Runtime slots are tenant-scoped;
model calls execute inside the matching tenant context.

`GET /v1/runtime/audit-preflight/{agent_id}` returns the authoritative
execution gate for the current tenant. OpenManus checks cover registration,
published static profile, Docker daemon, runtime image, and all three model
roles. `/execute` and `/resume` repeat this check server-side before starting
an audit thread.

If the desktop process stops during execution, startup marks the active stage
as interrupted while preserving completed checkpoints. The client can call
`POST /v1/audits/{audit_id}/resume?background=true` after runtime preflight.
An `attack_review` run cannot use this route and must be explicitly approved
through `/execute`.

Generate explicitly partial offline artifacts without Docker:

```bash
python3 scripts/generate_task15_artifacts.py --mode partial
```

Generate and verify Docker-backed attested artifacts:

```bash
python3 scripts/verify_task13_e2e.py
```

Verify existing Docker-backed artifacts without running Docker:

```bash
python3 scripts/verify_task13_e2e.py --existing
```

Docker-backed artifacts include a manifest binding `completeness`, `image_digest`,
`config_digest`, `profile_id`, `profile_sha256`, and every bundle file hash.
Missing or inconsistent evidence fails verification.

Constants, `Literal` aliases, implementation helpers, optional backend classes,
and legacy compatibility re-exports are excluded. Exclusion means they are not
stability promises; it does not mean they may bypass normal code review.

Run the gate with:

```bash
python -m pytest -q tests/contract/test_public_api_documentation.py
```

When adding a stable public class or function, add it to the allowlist and write
a docstring that states its input/output role, determinism, and material side
effects. Do not add narrative docstrings to trivial aliases merely to increase a
coverage percentage.
