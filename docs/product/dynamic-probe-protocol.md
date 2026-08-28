# Dynamic Probe Protocol v0.1

An image profile may claim successful dynamic verification only when its configured
Python module exports:

```python
def redsentinel_profile_probe(request: dict[str, object]) -> dict[str, object]:
    ...
```

The callable may also be asynchronous.

Modules must declare the behavior surface that the scenarios are expected to
exercise:

```python
REDSENTINEL_PROBE_TARGETS = [
    {"name": "example_agent", "node_type": "agent"},
    {"name": "search", "node_type": "tool"},
    {"name": "Input Guard", "node_type": "guard"},
]
```

Supported target types are `agent`, `tool`, `mcp`, and `guard`. Target
declarations and behavior returned by `redsentinel_profile_probe` are
image-provided attestations. They are recorded with `trust_level: attested` and
cannot independently verify a static claim or satisfy the completion gate.

Modules may replace the two default smoke scenarios with 1 to 32 deterministic
local scenarios:

```python
REDSENTINEL_PROBE_SCENARIOS = [
    {
        "scenario_id": "search",
        "input": {"message": "Search for one product"},
    }
]
```

Scenario identifiers must be unique. The runner supplies the request schema
version and rejects malformed scenario declarations.

## Request

The probe runner invokes the callable with isolated normal and adversarial smoke
scenarios:

```json
{
  "schema_version": "dynamic-probe-request-v0.1",
  "scenario_id": "normal-smoke",
  "input": {
    "message": "Inspect one normal request without external network access."
  }
}
```

The image runs without network access, added Linux capabilities, host credentials,
or writable root filesystem. Probe implementations must use deterministic local
fixtures and must not require production secrets.

## Response

```json
{
  "schema_version": "dynamic-probe-response-v0.1",
  "status": "completed",
  "agent_name": "example_agent",
  "output_type": "AgentResult",
  "blocked": false,
  "tool_calls": [
    {"name": "search", "allowed": true}
  ],
  "guard_decisions": [
    {"name": "Input Guard", "decision": "allow"}
  ]
}
```

`agent_name` is required. `tool_calls` and `guard_decisions` must be arrays when
present. Output content, tool arguments, credentials, and environment values must
not be returned.

## Completion Rules

Every evidence item carries one of these trust levels:

- `static`: extracted from image configuration, packages, source, or framework
  metadata.
- `attested`: declared or returned by code inside the analyzed image.
- `observed`: independently observed by a Sentinel-controlled adapter or probe.

Import and registration events are observed inventory evidence only; they verify
that a component exists, not that its behavior executed. Dynamic behavior
verification requires all of these runner-generated event types:

- `invocation_started`
- `agent_invoked`
- `output_observed`
- `invocation_completed`

Every critical Agent, tool, MCP, and guard claim must have a corresponding
`agent_invoked`, `tool_called`, or `guard_decision` event with
`trust_level: observed` before the profile can be classified as `complete`.
Self-reported events remain useful attestations but do not meet this requirement.
Generic dependency-level file and process sinks remain static risk evidence and
do not by themselves block the behavior verdict. Missing observed behavior,
failed calls, or incomplete critical coverage produce a published `partial`
profile.

The default Docker probe consumes output produced inside the analyzed container,
so all of its dynamic events are treated as `attested` regardless of a
`trust_level` value supplied by the image. `observed` events may only be supplied
by a Sentinel-controlled host observer that is outside the analyzed image's
process and output channels.
