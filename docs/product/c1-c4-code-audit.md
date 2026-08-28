# C1-C4 代码审计与整改记录

审计日期：2026-08-12

## 范围

- 审计任务与计划契约
- planner 与确定性策略校验
- baseline、加固、guarded、决策工作流
- JWT 租户绑定和文件持久化边界
- LLM JSON Gateway
- C4 企业知识助手案例

## 已整改

1. `allow_release` 现在要求计划场景与 baseline/guarded 结果完全一致。
2. 每个场景必须具备已声明且真实存在的 baseline/guarded trajectory。
3. 报告、trajectory 和 comparison 必须位于当前租户存储目录内。
4. evidence index 查询时重新校验文件存在性与 SHA-256，越界引用不再读取。
5. `max_model_calls=0` 时 planner 不再调用 LLM，并在计划 warnings 中披露回退原因。
6. LLM Gateway 拒绝 userinfo、query、fragment、无主机和非法端口 URL。
7. LLM Gateway 拒绝非正有限超时和非正 token 预算。
8. `AuditTask` 拒绝重复正常任务 ID、重复策略项和空白策略项。
9. `AuditPlan` 拒绝重复场景、优先级和正常任务 ID。
10. 普通文本不再默认误判为 Browser 调用，危险代码执行接入 `exec_guard`。

## 验证

```text
1038 passed, 2 deselected
Ruff passed
git diff --check passed
```

C4 定向结果保持：

```text
baseline ASR = 1.0
guarded ASR = 0.0
guarded clean utility = 1.0
```

## 剩余风险

- P1：同步文件状态机没有跨进程锁；同一审计被并发 resume 时可能重复执行阶段。
- P1：`max_runtime_seconds` 和 `max_cost_usd` 尚未形成执行期硬中断，只存在任务契约。
- P1：`normal_tasks` 当前进入计划展示，但 clean utility 仍来自 benchmark clean case，
  尚未为用户正常任务建立独立执行器和确定性 oracle。
- P2：当前环境未安装 `bandit` 和 `pip-audit`，本轮未覆盖第三方依赖漏洞扫描。
- P2：测试存在 `langchain-community` 和 Starlette `httpx` 兼容性弃用警告。

上述剩余项不应在竞赛材料中描述为已完成能力。
