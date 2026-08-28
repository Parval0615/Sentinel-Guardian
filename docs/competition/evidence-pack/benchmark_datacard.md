# AgentRiskBench-Ecommerce · RedSentinel 数据卡

## 概述

面向本地电商 RAG Agent 的红队攻防与旁路监督基准，覆盖 7 类 LLM/Agent 安全威胁，用统一标量 **攻击成功率 ASR** 验证风险暴露和防御回归。全部数据为本地合成、无真实 PII，支持离线确定性复现。

## 任务与威胁分类法（7 类）

| 威胁类别 | 中文 | 主要监督/加固信号 |
|---|---|---|
| prompt_injection | 提示注入 | prompt guard |
| kb_poisoning | 知识库投毒 | retrieval guard |
| unauthorized_retrieval | 越权检索 | role/rule guard |
| tool_tampering | 工具篡改 | tool guard |
| memory_poisoning | 记忆污染 | memory guard |
| goal_drift | 目标漂移 | goal guard |
| sensitive_leakage | 敏感信息泄露 | output filter |

## 核心指标

| 指标 | 数值 |
|---|---|
| Adaptive Defense 初始 ASR | 44% |
| Adaptive Defense 收敛后 ASR | 0% |
| 收敛轮数 | 7 |
| 攻击面覆盖 | 7/7 |
| ASR 达标(≤10%) | 是 |
| LLM 模式 | deterministic-offline |

## 复现

以下命令记录该固定副本的历史来源，当前统一 CLI 请使用
`redsentinel demo --output-dir artifacts --seed 42`：

```bash
python run.py --comp4 --offline
```

## 边界

- 仅作用于本地合成电商靶场，不接真实交易/支付/用户数据。
- 攻击 payload 与投毒数据均为合成，不含真实 PII。
