# RedSentinel 项目一页说明

## 一句话定位

RedSentinel 是面向大模型 Agent 的轨迹级安全评测与攻防协同进化研究框架，核心研究问题是：证据约束、效用感知的双边进化能否在相同预算下优于静态攻防和单边优化。

## 问题

普通 LLM 安全评测主要比较输入与最终文本，难以观察 Agent 的检索、工具调用、记忆写入、目标变化和运行时失败。固定攻击集还可能遗漏架构特定风险，而只追求降低 ASR 的防御容易通过过度拒绝损害业务效用。

## 方法

```text
Agent 物料与配置
 -> 证据约束画像
 -> 攻击候选生成、变异与选择
 -> 隔离执行和轨迹记录
 -> 风险判定与节点归因
 -> 防御候选生成与效用回归
 -> 下一轮协同进化
```

实验在统一预算下比较四类基线：固定攻防、仅攻击进化、仅防御优化、双边协同进化；通过画像、轨迹异常、节点归因、失败反思、效用约束五类消融识别有效组件。

## 工程实现

- 统一 `redsentinel.*` 领域命名空间和版本化契约；
- 覆盖 LLM、RAG、工具、记忆和状态变化的轨迹模型；
- 九阶段协同进化状态机、停止条件与 append-only ledger；
- dataset manifest、配置/数据哈希、Git 状态、模型参数和 evidence index；
- 确定性规则为主、LLM Judge 为辅的双轨裁判；
- Direct API、LangGraph、Docker、HTTP、SDK 和 OpenManus adapter；
- 多 seed 统计、置信区间、效应量、配对置换检验和论文图表入口。

## 当前已验证结果

| 证据 | 结果 | 模式 | 使用边界 |
|---|---:|---|---|
| 默认全量测试 | 778 passed | 本地默认测试 | 当前工程回归 |
| 配对单轮 smoke | 3/3 passed，FPR 0 | `offline_fixture` | 链路验证 |
| 协同进化 smoke | ASR 43.75% -> 0%，7 轮 | `offline_fixture` | 算法 smoke |
| 研究设计 | 4 类基线、5 类消融 | 配置与测试 | 实验能力 |
| OpenManus | `not_evaluated` | `real_runtime` | 不得引用效果数字 |

其中 ASR、FPR 均来自固定 fixture，不能表述为真实 Agent 防御效果；P0 未正式测量 business success rate 和 overhead。

## 可信证据

一键演示：

```bash
redsentinel demo --output-dir artifacts --seed 42
```

输出 `artifacts/p0-demo/p0-demo-summary-v1.json`，并回指：

- Agent profile；
- 单轮 report、audit refs、provenance 和 evidence index；
- memory poisoning、tool tampering、goal perturbation 三条典型证据；
- 协同进化 raw result、收敛图和 evidence index；
- 允许使用与禁止外推的结论边界。

## 个人贡献与背景衔接

项目把企业知识引擎中的质量评测、解析效果验证和自动化经验，扩展到 Agent 的轨迹级质量与安全评测；密码学背景主要用于威胁模型、哈希链完整性和证据可验证性。个人工作聚焦研究问题、领域契约、评测/进化协议、provenance、实验设计和统一 CLI。OpenManus 是固定版本的第三方被测 Agent，Matplotlib、FastAPI、Pydantic 等为基础依赖。

## 当前边界与下一步

当前最薄弱的证据是真实 Agent 外部有效性。P1 将优先完成 OpenManus 与第二个 Agent、两个模型家族、统一 benchmark 和 3-seed pilot；P2 再深化 Pareto 选择、变异算子和正式统计，避免先写论文结论再寻找支持数据。

代码入口：

- CLI：`src/redsentinel/cli.py`
- 研究执行：`src/redsentinel/research/`
- 评测与归因：`src/redsentinel/evaluation/`
- 协同进化：`src/redsentinel/research/evolution.py`
- 实验矩阵：`configs/experiments/rq-matrix-v1.yaml`
- 路线：`ROADMAP.md`
