# RedSentinel Frontend

## Overview

`frontend/index.html` 是 Sentinel-Guardian 竞赛审计工作区，包含公开首页、登录/注册
认证页和登录后可访问的 Agent 安全审计页面。它不负责计算审计指标；工作区展示结构化
`AgentSecurityReport` 和证据产物，并通过同源 `/v1/...` API 完成 Agent 接入、评测、
报告、日志和复测操作。

当前继续保留单文件实现以维持离线演示和既有交付兼容。审计编排和指标逻辑不得写入
该文件；后续只有在比赛交互继续扩展时，才按 `auth`、`api`、`report`、
`supervision` 四个边界拆分前端模块。

## Product Views

| View | Route / Anchor | Access | Behavior |
|---|---|---|---|
| 公开首页 | `/` / `#public-home` | 公开 | 展示产品价值、核心能力、使用流程、信任信息和“立即注册/登录使用/进入工作区”入口。 |
| 登录页 | `#login` | 公开 | 校验账号和密码，调用 `POST /v1/auth/login`，成功后进入工作区。 |
| 注册页 | `#register` | 公开 | 校验用户名、邮箱、密码、确认密码和协议确认，调用 `POST /v1/auth/register`，成功后进入工作区。 |
| 产品工作区 | `#product-workspace` | 需要 JWT | 未登录访问会跳转登录页；已登录后展示当前用户名和退出登录入口。 |
| 安全测试计划 | `#audit-plan` | 需要 JWT | 按 Audit ID 展示计划理由、优先级、预算、正常任务和停止条件。 |
| C5 审计工作区 | `#audit-workspace-c5` | 需要 JWT | 创建或选择审计，展示资产、评分、时间线、轨迹、风险复测、决策和证据。 |

## Authentication And Storage

- 前端只保存认证 token，不保存明文密码。
- token key 为 `redsentinel.auth.token`。
- 登录时勾选“记住登录状态”：token 写入 `localStorage`，浏览器重开后仍可恢复登录态。
- 登录时未勾选“记住登录状态”：token 写入 `sessionStorage`，浏览器会话结束后失效。
- 注册成功后直接进入登录态，当前实现按非记住登录处理，token 写入 `sessionStorage`。
- 前端启动时会用 `GET /v1/auth/me` 校验已保存 token；无效或过期会清理本地 token。
- 受保护工作区请求会携带 `Authorization: Bearer <token>`，包括 Agent 接入、审计创建与查询、dashboard summary、评测、报告、日志和 next-round。
- 退出登录会调用 `POST /v1/auth/logout`，随后清理 `localStorage` 和 `sessionStorage` 中的 token，并回到公开首页。
- API Key 只随 Agent 接入请求提交给后端，不写入浏览器存储。

## Data Contract

### AuditWorkspaceView → C5 Workspace Mapping

| Workspace Field | View Component |
|---|---|
| `task` / `profile` | 资产、授权风险面和 Benchmark |
| `plan` | 计划场景和风险节点 |
| `status.stages[]` | 阶段时间线、attempt、耗时和错误 |
| `baseline_report` / `guarded_report` | 场景攻击效果与复测状态 |
| `comparison` | Security Score 前后对比和风险变化 |
| `baseline_report.deterministic_metrics` / `guarded_report.deterministic_metrics` | ASR、DSR、FPR 对比条 |
| `traces[].events[]` | LLM、工具、文件、网络和 Guard 折叠轨迹与统一时间线 |
| `decision` | 四态上线结论、理由、限制和效用 |
| `evidence.artifacts[]` | 文件可用性、引用与 SHA-256 |

工作区主体通过 `GET /v1/audits/{audit_id}/workspace` 一次读取；审计选择器通过
`GET /v1/audits` 读取当前 JWT 租户列表。创建表单调用 `POST /v1/audits`，前端不接受
或持久化用户提交的 `tenant_id`。

轨迹文件只由后端在当前 JWT 租户目录内读取。工作区接收的是限长、敏感键脱敏的
`AuditScenarioTrace` 摘要；路径越界、文件缺失或 JSON 无效时返回 `available=false`，
前端不回退到 mock 轨迹。

轨迹文件只由后端在当前 JWT 租户目录内读取。工作区接收的是限长、敏感键脱敏的
`AuditScenarioTrace` 摘要；路径越界、文件缺失或 JSON 无效时返回 `available=false`，
前端不回退到 mock 轨迹。

轨迹文件只由后端在当前 JWT 租户目录内读取。工作区接收的是限长、敏感键脱敏的
`AuditScenarioTrace` 摘要；路径越界、文件缺失或 JSON 无效时返回 `available=false`，
前端不回退到 mock 轨迹。

轨迹文件只由后端在当前 JWT 租户目录内读取。工作区接收的是限长、敏感键脱敏的
`AuditScenarioTrace` 摘要；路径越界、文件缺失或 JSON 无效时返回 `available=false`，
前端不回退到 mock 轨迹。

### AgentSecurityReport → View Mapping

| Report Field | View Component |
|---|---|
| `tenant_id` | Header |
| `agent_id` | Header |
| `benchmark` | Header |
| `overall_score` | Metric Card |
| `risk_level` | Metric Card (color) |
| `attack_success_rate` | Metric Card |
| `false_positive_rate` | Metric Card |
| `findings[]` | Findings Table + Conclusion Card |
| `scenario_results[]` | Scenario Table |
| `guard_effectiveness` | Node Attribution |
| `business_impact` | Impact Section |
| `artifacts` | Evidence Section |

### SecurityEvent → Realtime Supervision Mapping

admin 登录态下，`loadSecurityEvents()` 优先携带 `Authorization` 读取同源 `GET /v1/monitor/events`，并支持 `agent_id`、`decision`、`session_id` 和 `limit` 查询参数；静态预览或 API 失败时回退读取 `data/mock_events.json`。

| SecurityEvent Field | Realtime Supervision Usage |
|---|---|
| `event_id` | HITL approve/reject action identity |
| `timestamp` | Event metadata time |
| `agent_id` | Event metadata and API filter |
| `session_id` | API filter/context |
| `call_type` | Event card title |
| `decision` | Decision badge and allow/deny/ask grouping |
| `status` | Status badge and pending action gating |
| `risk_score` | Risk badge and high-risk summary |
| `reason` | Event reason copy |
| `payload_summary` | Payload JSON preview |

### ScenarioResult → Table Mapping

| Field | Column |
|---|---|
| `scenario_id` | Scenario ID |
| `category` | Category |
| `severity` | Severity |
| `expected_decision` | Expected |
| `actual_decision` | Actual |
| `passed` | Status |
| `business_impact` | Impact |
| `trajectory_ref` | Evidence |

### Finding → Table Mapping

| Field | Column |
|---|---|
| `severity` | Severity |
| `scenario_id` | Scenario |
| `title` | Title |
| `business_impact` | Impact |
| `recommendation` | Recommendation |

### Node Attribution (Extended)

每个 `ScenarioResult` 可扩展包含节点归因数据：

```json
{
  "node_attribution": {
    "intercepted_node": "input_node",
    "intercepted_at_step": 2,
    "defense_type": "input_firewall",
    "attack_path": ["input_node", "llm_node", "tool_node"],
    "node_status": {
      "input_node": {"defense": "input_firewall", "status": "mounted"},
      "rag_retriever": {"defense": "doc_scanner", "status": "mounted"},
      "tool_node": {"defense": "tool_guard", "status": "mounted"},
      "memory_node": {"defense": "memory_guard", "status": "mounted"},
      "llm_node": {"defense": "goal_guard", "status": "mounted"},
      "output_node": {"defense": "output_filter", "status": "mounted"}
    }
  }
}
```

### Trajectory Data (Extended)

轨迹数据格式：

```json
{
  "trajectory": [
    {
      "step_index": 0,
      "timestamp": "2026-06-26T10:00:00Z",
      "step_type": "llm_inference",
      "model": "gpt-4",
      "input_messages": [...],
      "output_content": "...",
      "tool_call_intents": [...]
    },
    {
      "step_index": 1,
      "timestamp": "2026-06-26T10:00:05Z",
      "step_type": "tool_call",
      "call_id": "call_1",
      "name": "query_order",
      "arguments": {...},
      "response": {...}
    }
  ]
}
```

### ASR Convergence Data

多轮攻击收敛数据：

```json
{
  "asr_convergence": [
    {"round": 1, "asr": 0.44, "blocked": 4, "total": 9},
    {"round": 2, "asr": 0.33, "blocked": 6, "total": 9},
    {"round": 3, "asr": 0.22, "blocked": 7, "total": 9},
    {"round": 4, "asr": 0.11, "blocked": 8, "total": 9},
    {"round": 5, "asr": 0.0, "blocked": 9, "total": 9}
  ]
}
```

## Files

```
frontend/
├── data/
│   ├── mock_report.json          # Mock AgentSecurityReport
│   └── mock_comparison.json      # Mock AgentSecurityComparisonReport
├── tests/
│   └── test_report_rendering.py  # HTML generation tests
├── generator.py                  # Python HTML generator
├── index.html                    # Main dashboard template
└── README.md                     # This file
```

## Usage

启动完整产品前端时，用 Product API 托管 `index.html`，保证前端和 `/v1/...` API 同源：

```bash
PY=/Users/bytedance/.pyenv/versions/3.10.14/bin/python
export PYTHONPATH="src"
$PY -m pip install -e ".[product]"
$PY -m uvicorn redsentinel.application.engine.app:create_app --factory --host 127.0.0.1 --port 8000
```

打开 `http://127.0.0.1:8000/` 后可按“首页 → 注册/登录 → 产品工作区”的顺序访问。直接用 `file://` 打开 `index.html` 时，公开静态内容和 mock/fallback 报告可见，但认证和受保护 API 请求不会作为完整产品链路工作。

报告生成器仍可独立使用：

```bash
# Generate report from JSON
python -m frontend.generator --input data/mock_report.json --output report.html

# Open in browser
open report.html
```

## Technical Constraints

- **Single file product shell**: 首页、认证页、工作区 CSS/JS 均内嵌在 `index.html`，无前端构建步骤。
- **Same-origin API**: 完整产品体验依赖 Product API 托管页面并提供 `/v1/...` 接口。
- **Protected workspace**: 工作区入口和租户相关 API 依赖有效 JWT；公开首页、认证页和公开 benchmark 列表无需登录。
- **Safe client storage**: 浏览器只保存 token，不保存明文密码；API Key 不写入 `localStorage` 或 `sessionStorage`。
- **Report fallback**: 静态报告和 generator 输出仍应能在本地文件场景展示 mock/fallback 数据。
