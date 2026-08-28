# C2 安全测试计划页设计稿

## 页面目标

让用户在攻击执行前回答四个问题：

1. 为什么选择这些安全场景？
2. 实际测试哪些风险面和 Agent 节点？
3. 每项测试需要留下什么证据？
4. 预算耗尽或满足什么条件时停止？

页面只展示当前租户真实审计检查点中的 `AuditTask` 和 `AuditPlan`，接口失败时保持空状态。

## 信息架构

```text
页面标题与审计状态
├── Audit ID 查询
├── 计划摘要
│   ├── Profile
│   ├── 场景数量
│   ├── Runtime / Seed
│   └── Benchmark / Version
└── 双栏主体
    ├── 决策链
    │   └── 优先级、场景、理由、风险面、目标节点、预期证据
    └── Policy Envelope
        ├── Planner 来源与模型
        ├── Budget
        ├── Normal Tasks
        ├── Stop Conditions
        └── Fallback / Warning 披露
```

## 视觉方向

- 延续工作区暖灰、墨绿和纸张质感，不引入独立设计系统。
- 主内容使用纵向编号决策链，突出计划的执行顺序。
- 策略边界使用固定侧栏，避免预算和停止条件被场景详情淹没。
- `rule_fallback` 警告使用琥珀色披露块，不将回退计划伪装成 LLM 规划。
- 桌面端双栏；小于 900px 改为单栏；小于 560px 摘要和查询区纵向排列。

## 页面状态

| 状态 | 表现 |
|---|---|
| 未输入 Audit ID | 显示空状态和使用说明 |
| 加载中 | 状态胶囊显示 `loading` |
| 已加载 | 展示真实计划和检查点状态 |
| 计划不存在 | 显示接口错误，不生成 mock 场景 |
| 未登录 | 复用工作区登录拦截 |

## 数据接口

```http
GET /v1/audits/{audit_id}/plan
Authorization: Bearer <token>
```

响应为 `audit-plan-view-v0.1`：

```json
{
  "audit_id": "audit-...",
  "state": "baseline_execution",
  "task": {},
  "plan": {}
}
```

后端根据 JWT 用户绑定 tenant，不能通过 query 或请求体跨租户读取计划。

## 代码位置

- 页面、样式和交互：`frontend/index.html`
- 计划视图契约：`src/redsentinel/application/audit_contracts.py`
- API 路由：`src/redsentinel/application/engine/app.py`
- 前端回归测试：`frontend/tests/test_report_rendering.py`
- API 回归测试：`tests/regression/evaluation/audit/test_audit_api.py`
