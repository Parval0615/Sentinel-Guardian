# Sentinel-Guardian 参赛提交检查清单

## 产品口径

- [x] 对外名称统一为 Sentinel-Guardian。
- [x] 具体问题定义为“企业 Agent 上线前缺少自动化安全验收”。
- [x] 最终交付是四态上线决策与证据报告。
- [x] 攻击变异和防御优化只作为竞赛审计闭环内部能力。
- [x] 仓库不再维护独立研究、论文或求职路线。
- [x] 统一审计任务入口可以触发完整工作流。
- [x] 可视化展示结构化测试计划及其执行状态。
- [x] 报告页面展示允许上线、修复复测、禁止上线或人工审批。

## 演示案例

- [x] 企业知识助手可以完成公开资料总结等正常任务。
- [x] Agent 具备受控 Browser、文件和 Python 工具。
- [x] 至少演示提示注入、敏感文件读取、路径穿越和 SSRF。
- [x] 展示一次真实攻击效果和对应风险节点。
- [x] 展示局部 Guard 生成与安装。
- [x] 使用相同 case、模型、seed 和预算完成复测。
- [x] 证明正常业务任务在加固后仍成功。

## 证据边界

- [x] 离线 smoke 与真实 runtime 结果分开展示。
- [x] OpenManus W2 rerun10 标明单 Agent、单模型、单 seed。
- [x] 邮件场景标记 `not_applicable`，适用覆盖为 5/6。
- [x] 环境失败、模型拒答和 Guard 拦截分别统计。
- [x] 所有数字可以定位到 evidence bundle。
- [x] 当前全量测试结果已更新为 `1068 passed, 2 deselected`。
- [x] `1068 passed, 2 deselected` 已在当前工作树验证；不使用未验证的跨 Agent 效果数字。

## 复现

```bash
python -m pip install -e ".[all,dev]"
redsentinel doctor --dry-run
redsentinel demo --output-dir artifacts --seed 42
python -m pytest -q
python -m ruff check . --select F401,F841,F821,F811
```

- [ ] 新环境可以在 10 分钟内完成离线演示。
- [x] summary 中的 profile、report、provenance 和 evidence refs 均可打开。
- [x] 前端页面能够加载结构化报告。
- [x] 真实运行说明不包含 API key 或其他凭据。

## 提交材料

- [x] [`README.md`](../../README.md)
- [x] [`ROADMAP.md`](../../ROADMAP.md)
- [x] [`README.md`](./README.md)
- [x] [`final-report.md`](./final-report.md)
- [x] [`defense-script-8min.md`](./defense-script-8min.md)
- [x] [`reproducibility.md`](./reproducibility.md)
- [x] [`evidence-pack/`](./evidence-pack/)
- [ ] 3–5 分钟演示视频
- [x] 一页系统架构图：[`system-architecture.md`](./system-architecture.md)
- [x] 企业知识助手案例截图或录屏：[`evidence-pack/`](./evidence-pack/)
- [x] 最终测试与 secret scan 记录：[`final-verification.md`](./final-verification.md)

## 安全检查

- [x] 仅使用授权、本地或明确隔离的目标。
- [x] 不连接真实支付、真实企业数据或未授权系统。
- [x] artifact、日志和截图通过 secret scan。
- [x] 自动上线建议保留人工审批与责任边界说明。
