# RedSentinel 简历项目材料

## 中文项目标题

**RedSentinel：面向大模型 Agent 的安全评测与攻防协同进化框架**

## 中文简历 Bullet

以下版本不把离线 smoke 包装为真实 Agent 结果：

1. 设计并实现 Agent 轨迹级安全评测框架，将评测对象从最终文本扩展到 LLM 推理、RAG、工具调用、记忆和状态变化，覆盖提示注入、工具篡改、记忆污染、目标漂移等 7 类威胁，并支持节点级风险归因。
2. 构建基于 Agent 画像、失败轨迹和归因证据的攻防协同进化机制，统一实现静态攻防、仅攻击进化、仅防御优化和双边进化 4 类基线，以及画像、轨迹异常、节点归因、反思、效用约束 5 类消融。
3. 建立可复现实验与可信证据链，记录数据/配置哈希、Git 状态、模型参数、原始结果和 evidence index；默认离线测试 752 项通过，确定性 smoke 可复现 3/3 攻击对和 7 轮收敛过程。

完成真实 Agent 实验后，第三条可替换为真实数据版本：

> 在 OpenManus 与 `<第二 Agent>`、`<模型 A/B>` 上完成 `<N>` 个 seed 的统一预算实验；相对 `<最强基线>` 将 holdout ASR 从 `<x>` 降至 `<y>`，FPR 为 `<z>`，业务成功率保持 `<u>`，并报告 `<cost>` 开销。

只有真实实验产物存在后才能使用该版本。

## English Project Title

**RedSentinel: Security Evaluation and Attack-Defense Co-Evolution for LLM Agents**

## English Resume Bullets

1. Designed a trajectory-level security evaluation framework for LLM agents, extending evaluation from final text to reasoning, retrieval, tool calls, memory operations, and state changes; covered seven threat categories with node-level attribution.
2. Built an evidence-guided attack-defense co-evolution workflow with four controlled baselines and five ablation switches, jointly evaluating attack success, false positives, business utility, and execution cost.
3. Implemented reproducible experiment provenance across datasets, configurations, Git state, model parameters, raw results, and evidence indexes; maintained 752 deterministic offline tests and replayable smoke experiments.

## 一页项目说明

### 问题

传统 LLM 安全评测主要比较输入和输出，难以覆盖 Agent 的工具执行、记忆写入、状态变化和多轮目标漂移。固定攻击集容易漏掉架构特定风险，全局防御又可能通过过度拒绝降低 ASR。

### 方法

RedSentinel 使用以下闭环：

```text
AgentProfile
 -> AttackCandidate population
 -> Runtime trajectory
 -> Risk evaluation and node attribution
 -> DefenseCandidate population
 -> Utility-aware regression
 -> Next round
```

方法使用 Agent 画像、历史失败轨迹和节点归因约束候选生成，并在相同预算下比较静态、单边和双边优化。

### 工程实现

- 统一 `redsentinel.*` 领域包；
- Direct API、LangGraph、Docker、HTTP、SDK、OpenManus adapters；
- 九阶段协同进化状态机和 append-only ledger；
- 四类基线和五类消融；
- development/holdout 数据治理；
- provenance、evidence index 和论文图表生成；
- 可选 Product API 和 dashboard。

### 当前结果

| 结果 | 数值 | 运行模式 | 可使用范围 |
|---|---:|---|---|
| 默认全量测试 | 778 passed | 本地默认测试 | 简历、面试 |
| 单轮 smoke | 3/3 passed | offline_fixture | 简历工程验证 |
| 协同进化 smoke | ASR 43.75% -> 0% | offline_fixture | 说明链路，不作真实效果结论 |
| 基线/消融 | 4 arms / 5 switches | offline_fixture | 说明实验能力 |
| OpenManus | not_evaluated | real_runtime | 不可写效果数字 |

### 研究问题

主问题是：在相同预算下，证据约束、效用感知的双边协同进化能否比静态攻防和单边优化取得更好的安全与业务效用平衡。

### 边界

- 离线结果不代表真实 Agent；
- 真实多 Agent、多模型、多 seed 实验尚未完成；
- dashboard 是展示层；
- 哈希链提供篡改证据，不保证数据源天然可信。

## 数字证据分级

| 结论 | 证据等级 | 证据路径 | 状态 |
|---|---|---|---|
| 默认测试 778 passed | E2 工程回归 | 当前 `python -m pytest -q` | 可用 |
| 单轮 3/3 | E2 离线集成 | `artifacts/p0-demo/` 及 P0 证据卡 | 可用，须标离线 |
| ASR 43.75% -> 0% | E2 离线算法 smoke | evolution evidence index | 可讲链路，不可作真实效果 |
| 四类基线/五类消融可运行 | E2 离线研究 | baseline/ablation tests | 可用 |
| OpenManus 防御效果 | 无 | 尚无 real runtime 产物 | 禁止使用 |
| 跨 Agent 泛化 | 无 | P1 待完成 | 禁止使用 |
| 论文显著性 | 无 | P2/P4 待完成 | 禁止使用 |

## 三类结论

### 面试可讲

- 为什么 Agent 需要轨迹级评测；
- 如何区分环境、业务和安全失败；
- 如何设计公平的四类基线和消融；
- 如何保证数据、配置和结果可追溯；
- 离线协同进化链路和工程实现。

### 当前论文可用

- 系统架构和问题定义；
- ExperimentManifest、trajectory 和 evidence 模型；
- 实验协议、基线设计和有效性威胁；
- 离线 smoke 作为实现正确性验证。

### 暂不可使用

- 真实 Agent 的防御提升；
- 跨模型和跨框架泛化；
- 协同进化的统计显著性；
- 完整性机制的密码学安全证明；
- 企业生产落地效果。
