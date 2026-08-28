# Sentinel-Guardian 复现说明

## 环境

- Python 3.10+
- 离线演示不需要网络、Docker 或 API key
- 真实 OpenManus 运行需要 Docker daemon、固定镜像和显式模型配置

安装完整依赖：

```bash
python -m pip install -e ".[all,dev]"
```

## 当前主链路

环境检查：

```bash
redsentinel doctor --dry-run
```

五分钟离线审计演示：

```bash
redsentinel demo --output-dir artifacts --seed 42
```

该命令执行：

```text
doctor -> profile -> paired evaluation -> co-evolution -> evidence summary
```

主要输出为 `artifacts/p0-demo/p0-demo-summary-v1.json`，并回指 profile、report、
provenance、raw result 和 evidence index。

底层兼容入口：

```bash
redsentinel profile examples/agents/simple_agent/redsentinel.yaml --dry-run
redsentinel evaluate --output-dir artifacts --seed 42
```

`redsentinel` 是 Sentinel-Guardian 保留的兼容 CLI 名称。
`evolve` 和 `experiment` 属于历史算法验证入口，不再进入比赛主流程。

## 自动化验证

默认测试：

```bash
python -m pytest -q
```

完整离线测试：

```bash
python -m pytest -q -o addopts=''
```

静态检查：

```bash
python -m ruff check . --select F401,F841,F821,F811
```

## 真实 OpenManus 证据

真实运行必须满足：

- `real_runtime=true`
- `simulated=false`
- baseline/guarded 使用相同模型、case、seed 和预算
- 环境失败、模型拒答和 Guard 拦截分别归因
- manifest、provenance、raw trajectory 和 evidence index 完整
- stdout、stderr、events 和 provenance 通过 secret scan

当前 W2 rerun10 已通过上述门禁。复现所需镜像、模型元数据、运行结果与限制见
[`../research/stages/p1-execution-log.md`](../research/stages/p1-execution-log.md)。
外部模型凭据不得写入命令、配置、日志或文档。

## 历史固定证据包

[`evidence-pack/`](./evidence-pack/) 保存旧竞赛阶段生成的确定性离线副本。其
`python run.py --comp*` 命令属于已删除的历史入口，仅用于解释固定产物来源，不是
当前复现命令。离线结果不得替代真实 Agent 效果。

## 结果边界

- 历史 `43.75% -> 0%` 是 `offline_fixture` 算法 smoke。
- W2 rerun10 是单 Agent、单模型、单 seed 真实门禁。
- OpenManus 缺少等价邮件工具，适用覆盖为 5/6。
- 本仓库不再推进跨 Agent、跨模型或正式统计实验路线。
