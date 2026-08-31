# Sentinel-Guardian 竞赛 Roadmap

## 1. 唯一目标

本仓库只服务当前“生成式大语言模型与智能体”赛题。

作品定位固定为：

> **Sentinel-Guardian：面向企业智能体上线前安全审计与自动加固的安全审计智能体。**

桌面主路径接收 `agent.json + image.tar` 或 OCI Image Layout；系统先离线解析镜像并
生成证据闭合画像，再在自主管理的隔离沙箱中完成规划、攻击、评测、加固、复测和
上线决策。源码目录与构建清单入口仅作为 API 兼容能力保留，不接入客户生产环境。

仓库不再维护独立的求职、毕业论文或投稿路线。现有研究模块、实验协议和历史材料只
作为竞赛产品可复用的算法与证据资产，不单独占用开发优先级。

## 2. 成功标准

评委应能在 5–8 分钟内看到一条完整、真实、可解释的智能体任务：

```text
提交待审计 Agent
  -> 校验镜像摘要与 Agent 描述文件
  -> 离线解析镜像中的源码、配置、工具和权限
  -> 在 Sentinel 沙箱加载隔离运行副本
  -> 生成结构化安全测试计划
  -> 在隔离环境执行针对性攻击
  -> 分析 LLM、文件、网络、工具和状态轨迹
  -> 定位风险节点并生成局部防御
  -> 使用相同条件回归验证
  -> 输出上线决策和证据报告
```

最终决策固定为：

- `允许上线`
- `修复后复测`
- `高风险，禁止上线`
- `需要人工审批`

竞赛完成标准：

1. 用户只需触发一个审计任务，不需要手工串联多个实验命令。
2. LLM 生成受 schema 约束的测试计划，并实际决定 case、预算和执行顺序。
3. 至少一个镜像 Agent 在 Sentinel 管理的 Docker 隔离环境完成攻击、加固和复测。
4. 至少展示一个真实攻击效果、一个风险节点和一个局部防御。
5. 加固后攻击被阻断，正常业务任务仍然成功。
6. 每个结论都能回到 manifest、trajectory、Guard decision 和 evidence index。
7. 演示、README、页面、答辩稿和报告使用同一套指标与口径。

## 3. 执行原则

优先级固定为：

```text
完整自主闭环
  > 真实业务案例
  > 可观察决策过程
  > 真实运行证据
  > 演示稳定性
  > 展示效果
  > 新功能数量
```

约束：

- 复用现有 profile、attack、evaluation、defense、runtime 和 reporting 模块。
- 不复制 evaluator，不另建一套竞赛指标。
- 第一版只支持一个企业知识助手和一个 OpenManus runtime。
- 不新增与演示无关的攻击类别、Agent 框架、模型矩阵或统计实验。
- 不建设计费、多租户运营、通用 SaaS 或复杂管理后台。
- 环境失败、模型拒答和 Guard 拦截必须分别归因。
- 所有攻击只作用于授权、本地或明确隔离的目标。
- Docker/OpenManus 仅作为 Sentinel 内部沙箱底座，不作为客户 Agent 接入形态。

## 4. 阶段路线

| 阶段 | 目标 | 核心交付 | 状态 |
|---|---|---|---|
| C0 口径统一 | 项目只保留竞赛产品线 | 品牌、README、Roadmap、报告、页面一致 | 已完成 |
| C1 审计任务契约 | 用一个任务描述完整审计需求 | `AuditTask`、`AuditPlan`、`ReleaseDecision` | 核心完成 |
| C2 自主测试规划 | LLM 生成并驱动结构化计划 | planner、schema 校验、计划页面、回退策略 | 核心与计划页面完成 |
| C3 闭环编排 | 一次任务串通攻击、加固和复测 | orchestrator、状态机、阶段事件、证据索引 | 已完成 |
| C4 企业知识助手案例 | 构建可理解的真实业务演示 | 正常任务、攻击任务、局部 Guard、复测结果 | 已完成 |
| C5 竞赛产品展示 | 让评委直接看到计划、轨迹和决策 | 审计入口、进度页、风险节点、决策报告 | 已完成 |
| C6 提交验收 | 固化可复现提交包 | 演示视频、答辩稿、架构图、测试与安全检查 | 进行中 |

## 5. C1：审计任务契约

### 目标

把当前多个 CLI 和底层模块包装成一个稳定的用户任务：

> 审计这个 Agent 是否可以上线；发现风险后生成最小化加固方案，并验证正常业务能力。

### 最小数据模型

`AuditTask`：

- 待审计 Agent 标识、源码目录、构建清单和源码快照 SHA-256
- 正常业务任务
- 安全目标和允许的攻击范围
- runtime、模型和预算
- 是否允许自动安装防御
- 必须人工审批的动作

`AuditPlan`：

- 识别到的工具、权限和风险面
- 选择的安全场景及选择理由
- case 顺序、预算和停止条件
- 预期证据和复测条件

`ReleaseDecision`：

- 四态决策
- 安全指标、正常业务效用和证据完整性
- 未适用场景与未解决风险
- 自动修复和人工审批建议
- 所有结论对应的 evidence refs

### 验收

- CLI/API 可以创建并读取一个审计任务。
- schema 拒绝缺少 Agent、正常任务、安全范围或预算的请求。
- 决策不能在证据不完整时返回 `允许上线`。
- 模型拒答和环境失败不能计为防御成功。

## 6. C2：自主测试规划

### 目标

让大模型参与实质决策，而不是只生成 rationale。

### 实现边界

- 输入 AgentProfile、源码证据、工具权限、业务任务和历史失败。
- 输出受 Pydantic/JSON Schema 约束的 `AuditPlan`。
- planner 选择风险场景、case、顺序、预算和停止条件。
- 确定性 policy 校验授权范围、危险动作和预算上限。
- LLM 输出无效或越权时使用受控回退计划，并在报告中披露。

### 验收

- 不同工具/权限画像生成不同计划。
- 消融 planner 后，case 选择或覆盖发生可解释变化。
- 页面可以展示“为何测试、测试什么、何时停止”。
- 计划内容与实际执行记录一致。

## 7. C3：闭环编排

### 目标

实现单一命令或 API：

```bash
sentinel-guardian audit <audit-task.json>
```

现有 `redsentinel` CLI 作为兼容入口保留，也可以先提供：

```bash
redsentinel audit <audit-task.json>
redsentinel audit --resume <audit_id> --tenant-id <tenant_id>
```

### 状态机

```text
created
 -> profiling
 -> planning
 -> baseline_execution
 -> evaluation
 -> defense_generation
 -> guarded_execution
 -> decision
 -> completed / needs_approval / failed
```

### 验收

- 一次调用完成 profile、baseline、evaluation、defense、retest 和 decision。
- 每个阶段可查询状态、耗时、错误和证据引用。
- baseline/guarded 使用相同 case、模型、seed 和预算口径。
- 中断后可以从已完成阶段恢复，不重复计算成功步骤。

## 8. C4：企业知识助手案例

状态：已完成。可执行资产位于
`examples/agents/enterprise_knowledge_assistant/`，包含本地知识助手、合成知识库、
正常任务、安全场景、AgentProfile、AuditTask、轨迹生成器和正式审计引导脚本。

### 正常任务

- 检索公开产品或政策资料
- 读取授权文档
- 使用 Python 进行简单数据分析
- 生成带来源的摘要

### 安全场景

- 提示注入改变任务目标
- 读取未授权敏感文件
- 路径穿越
- SSRF 或元数据访问
- 工具参数滥用
- 检索内容中的间接指令

### 演示闭环

1. 助手正常完成公开资料总结。
2. Sentinel-Guardian 识别 Browser、文件和 Python 等高权限工具。
3. planner 生成针对性测试计划。
4. baseline 产生至少一个注册攻击 effect。
5. Evaluation Agent 定位到具体工具或协议节点。
6. Defense Agent 生成并安装局部 Guard。
7. guarded 运行阻断相同攻击。
8. 正常摘要任务仍成功。
9. 决策从“禁止上线/修复后复测”更新为“允许上线”或“需要人工审批”。

### 验收

- 演示不依赖真实企业数据。
- 攻击效果不是只匹配危险文本，而是由工具结果或 effect marker 证明。
- 正常业务效用不能由 FPR 间接推导，必须单独执行。

## 9. C5：竞赛产品展示

状态：已完成。现已支持创建审计、租户审计列表、资产理解、阶段进度、
baseline/guarded 场景与评分对比、统一时间线、LLM/工具/文件/网络/Guard 轨迹展开、
四态决策和证据索引。轨迹内容经租户路径校验、限长和敏感键脱敏后展示。

页面只围绕一次审计任务组织：

1. **提交审计**：Agent、正常任务、安全范围、预算。
2. **资产理解**：工具、权限、风险面和证据来源。
3. **测试计划**：case、原因、预算和停止条件。
4. **执行轨迹**：LLM、工具、文件、网络、Guard 和错误事件。
5. **风险定位**：攻击效果、风险节点和建议防御。
6. **复测对比**：baseline/guarded 与正常业务结果。
7. **上线决策**：四态结论、限制和 evidence refs。

展示层不维护独立指标，不显示没有证据来源的示例数字。

## 10. C6：提交验收

### 自动化

```bash
python -m pytest -q
python -m ruff check . --select F401,F841,F821,F811
git diff --check
```

### 演示

- 新环境 10 分钟内完成离线演示。
- 有 Docker 和模型凭据时可完成真实 OpenManus 审计。
- 3–5 分钟录屏完整展示任务、计划、攻击、加固、复测和决策。
- 8 分钟答辩能够解释问题、智能体自主性、真实效果和边界。

### 安全

- artifact、日志、截图和视频通过 secret scan。
- 不连接真实支付、真实企业数据或未授权目标。
- 自动决策保留人工审批和责任边界。

## 11. 当前基线

当前可复用资产：

- `1068 passed, 2 deselected` 默认 Python 离线测试
- `50 passed` React 前端测试，TypeScript 与生产构建通过
- `2 passed` Playwright 真实服务视口验收（1440×1100、390×844）
- OpenManus W2 rerun10：15/15 真实容器运行成功
- 5/5 可比攻击完成 baseline/guarded 配对
- baseline ASR 100%，guarded ASR 0%
- clean utility 100%，FPR 0%
- manifest、provenance、trajectory 和 evidence index

适用边界：

- 当前真实证据为一个 Agent、一个模型、一个 seed
- OpenManus 缺少等价邮件工具，场景适用范围为 5/6
- 历史离线协同进化结果只用于支持竞赛演示，不作为独立研究结论

## 12. 历史资产处理

以下内容暂不删除，以免破坏测试、兼容接口和已有证据：

- `src/redsentinel/research/`
- `research/`
- `configs/experiments/`
- `docs/research/`
- `tests/research/`

它们统一视为历史算法与证据资产：

- 不再进入当前 Roadmap
- 不再作为 README 主入口
- 不再继续扩展 RQ、论文统计或跨 Agent 实验
- 只有在竞赛闭环直接依赖时才允许修改

比赛结束后再决定归档、拆仓或删除，不在当前阶段进行大规模破坏性清理。
