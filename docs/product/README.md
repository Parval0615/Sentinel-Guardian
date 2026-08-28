# Sentinel-Guardian 产品口径

## 产品定义

Sentinel-Guardian 是面向企业智能体上线前安全审计与自动加固的安全审计智能体。

它解决的具体问题不是“如何展示更多安全指标”，而是：

> 企业提交一个待上线 Agent 的源码后，如何自动识别风险、验证真实影响、生成最小化加固，
> 并给出可审计的上线建议。

## 用户与输入

目标用户：

- 企业 Agent 开发团队
- AI 安全与红队团队
- 上线审批和质量保障团队

唯一 Agent 接入输入：

- Agent 源码目录
- 位于源码目录内的 `agent-sandbox-build-v0.1` JSON 构建清单
- 正常业务任务与安全目标
- 可选的组织策略和审批门槛

不接受：

- 客户 API endpoint 或 API Key
- 客户预构建 Docker 镜像
- 客户生产环境运行入口
- 仅有 OpenAPI 或运行轨迹、没有源码的 Agent

## 自主任务

```text
冻结源码与构建清单 SHA-256
 -> 在 Sentinel 管理的隔离沙箱构建运行副本
 -> 理解 Agent
 -> 生成结构化测试计划
 -> 在隔离环境执行针对性攻击
 -> 分析轨迹和真实效果
 -> 定位风险节点
 -> 生成并安装局部防御
 -> 同条件复测攻击与正常任务
 -> 输出上线决策和证据报告
```

四态决策：

- `允许上线`
- `修复后复测`
- `高风险，禁止上线`
- `需要人工审批`

## 技术底座

- AgentProfile：从源码、配置和运行材料提取证据约束画像
- Attack Agent：根据风险面和失败轨迹生成、变异和选择攻击候选
- Evaluation Agent：融合确定性 Oracle、轨迹信号和节点归因
- Defense Agent：基于风险节点生成局部 Guard 并验证业务效用
- Source Ingress：只接受源码与构建清单，生成不可变源码快照摘要
- Runtime Adapter：作为 Sentinel 内部沙箱执行器，不作为客户接入方式
- Evidence Layer：保存 manifest、provenance、raw trajectory 和 evidence index

## 信任边界

- Sentinel 不调用客户生产 Agent。
- 所有攻击、工具调用和修复复测只发生在 Sentinel 管理的沙箱副本。
- baseline 与 guarded 必须绑定同一个 `source_snapshot_sha256`。
- 修复后通过仅表示指定源码快照与 `RemediationBundle` 在沙箱中验证通过。
- 客户部署最终修复组合后仍需执行最终发布复验，才能签发 `allow_release`。

攻击变异、失败反馈和防御优化作为审计闭环内部能力使用，不再维护独立研究路线。

## 当前状态

已完成：

- 离线 profile、paired evaluation、co-evolution 和 evidence summary
- OpenManus 真实 runtime W2 门禁
- 攻击、评测、防御、复测和报告底层能力
- 本地 API 与报告页面

正在收敛：

- 单一审计任务 API/CLI
- 可观察的结构化测试计划
- 四态上线决策模型
- 企业知识助手端到端案例

暂不承诺：

- 生产 SaaS 成熟度
- 自动决策替代企业人工审批
- 比赛范围之外的通用平台能力

执行路线见 [`../../ROADMAP.md`](../../ROADMAP.md)；竞赛材料见
[`../competition/README.md`](../competition/README.md)。

## 兼容标识

对外产品名统一为 Sentinel-Guardian。以下标识为现有兼容接口，不进行破坏性迁移：

- Python 包：`redsentinel`
- CLI：`redsentinel`、`redsentinel-agent`、`redsentinel-defense`
- 配置文件：`redsentinel.yaml`
- 已发布 schema、artifact id 和历史 evidence path
