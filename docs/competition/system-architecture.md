# Sentinel-Guardian 系统架构

```mermaid
flowchart LR
    U[审计人员] --> UI[React 审计工作区]
    UI --> API[FastAPI Product API]

    subgraph Control[审计控制面]
        API --> AUTH[认证与租户隔离]
        API --> INDEX[Agent 资产索引]
        API --> PROFILE[静态画像工作流]
        API --> PREFLIGHT[七项运行预检]
        API --> FLOW[多轮审计状态机]
        API --> STORE[租户存储与证据索引]
    end

    subgraph Intelligence[三 Agent 决策层]
        ATTACK[攻击 Agent]
        EVAL[评测与归因]
        DEFENSE[防御 Agent]
    end

    subgraph Runtime[隔离执行面]
        DOCKER[Docker Desktop]
        OPENMANUS[OpenManus Runtime]
        TARGET[被测 Agent 镜像]
        GUARD[局部 Guard]
    end

    INDEX --> PROFILE
    PROFILE -->|agent-profile-v0.2| ATTACK
    PREFLIGHT -->|画像 / Docker / 镜像 / 三模型| FLOW
    FLOW -->|攻击计划| REVIEW[人工审阅授权]
    REVIEW -->|批准| ATTACK
    ATTACK --> DOCKER
    DOCKER --> OPENMANUS
    OPENMANUS --> TARGET
    TARGET -->|轨迹与攻击效果| EVAL
    EVAL -->|失效节点| DEFENSE
    DEFENSE --> GUARD
    GUARD -->|同 case / 模型 / seed / 预算复测| TARGET
    EVAL -->|ASR / FPR / Utility / Evidence| FLOW
    FLOW -->|四态上线决策| UI
    FLOW --> STORE
```

## 安全门禁

1. 镜像摘要、画像 ID 与画像 SHA-256 必须保持绑定。
2. 每一轮攻击计划均停在 `attack_review`，由用户明确授权。
3. `/execute`、`/resume` 和下一轮生成前均执行七项环境预检。
4. 三组模型凭据仅保存在 App 进程内存中，不进入任务、日志或报告。
5. 轨迹由后端在租户目录边界内读取，经过限长和敏感字段脱敏后展示。

## 输出

- `agent-profile-v0.2` 与风险路径
- 逐攻击 baseline/guarded 结果和失效节点
- Guard 挂载记录与正常业务效用
- 四态上线决策、manifest、provenance 和 evidence index
