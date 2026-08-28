# Sentinel Guardian 使用说明

## 启动

1. 双击 `Sentinel Guardian.app`。
2. 等待 `Sentinel Guardian` 桌面窗口打开。
3. 首次使用时注册账号，然后登录。
4. 进入“Agents”，可以看到“电商客服 Agent”和“OpenManus Agent”。
5. 点击 Agent 名称进入详情，选择“生成画像”；静态画像发布后即可发起审计。
6. 在“新建安全审计”中设置授权风险面和业务 Oracle，然后点击“生成攻击集”。
7. 确认运行环境预检中的画像、Docker、OpenManus 镜像和三模型均显示就绪。
8. 在攻击集审阅页核对每条攻击的风险面、预测节点、路径与证据，确认授权后启动正式审计。
9. 报告会逐条展示攻击是否成功、预测攻击节点、实际失效节点和挂载的防御。
10. 点击“生成下一轮攻击集”，审阅根据本轮结果生成的新攻击后再开始下一轮。

如果 macOS 阻止首次打开，请右键应用，选择“打开”，再确认一次。

## 停止

关闭应用窗口会同时停止本地服务。也可以在 Dock 中右键 `Sentinel Guardian`
并选择“退出”。

## 发给其他人

请发送 `Sentinel Guardian-macOS-arm64.zip`，不要直接通过普通文件复制拆散
`.app` 内部目录。对方需要：

1. 使用 Apple Silicon Mac，解压 ZIP。
2. 首次启动时右键 `Sentinel Guardian.app`，选择“打开”并确认。
3. 在应用窗口中注册自己的账号。

电商 Agent 已包含在分发包中，不需要安装 Python、Node.js、Uvicorn 或项目源码。
由于应用没有 Apple Developer ID 签名和公证，无法保证从所有传输渠道下载后都能
直接双击通过 Gatekeeper；正式公开分发需要开发者证书。

## 生成分发包

在仓库根目录运行唯一打包命令：

```bash
.venv/bin/python scripts/package_macos_release.py
```

该命令构建两个 `linux/arm64` Agent 镜像、前端和桌面应用，执行临时签名与完整性
校验，并在项目根目录生成 `Sentinel Guardian.app` 及同名 ZIP。开发时可显式复用
已存在的应用包，但不会复用其中的旧前端：

```bash
.venv/bin/python scripts/package_macos_release.py \
  --reuse-app "Sentinel Guardian.app"
```

只有确认两个本机镜像均来自当前 Dockerfile 时，才可加 `--reuse-images`。一次构建
在导出后中断时，可加 `--reuse-archives` 继续使用已经通过摘要校验的归档。缺少任一
`image.tar`、镜像平台不符或任一校验失败时，命令不会生成 ZIP。

画像制品有两条相互隔离的生成路径。离线静态回归不需要 Docker，只生成
`artifacts/task15-partial/` 与 `artifacts/task13-partial-*.json`，结果必须是
`partial`：

```bash
python3 scripts/generate_task15_artifacts.py --mode partial
```

真实 Docker 画像验收要求 Docker Desktop 正在运行。以下命令通过生产镜像解析、
加载和动态探针重新生成两个 Agent 的正式制品。容器内探针属于镜像自报证据，因此
当前正式制品必须明确标记为 `partial`，不能作为独立运行时观测：

```bash
python3 scripts/verify_task13_e2e.py
```

仅复核现有正式制品可运行：

```bash
python3 scripts/verify_task13_e2e.py --existing
```

正式 Docker 制品位于 `artifacts/task15/` 与 `artifacts/task13-*.json`。manifest 绑定完整度、
镜像摘要、配置摘要、画像 ID、画像 SHA-256 和各内容文件 SHA-256；缺失或不一致均会
阻断验收。离线 `partial` 制品不能替代正式制品。

## 数据位置

账号、审计和报告保存在：

```text
~/Library/Application Support/Sentinel Guardian/
```

删除或替换 `.app` 不会自动删除这些数据。

## Agent 目录

应用只读取与 `.app` 同级的 `agents/`。分发包固定包含 `agents/电商/` 和
`agents/openmanus/`，每个目录均包含 `agent.json` 与 `image.tar`；不存在应用内部
资产回退。`agent.json` 中的摘要必须与归档一致；替换镜像后必须同步更新摘要，系统
会据此创建新画像版本，既有审计仍绑定旧版本。

画像的静态阶段直接读取离线归档，不启动容器，不需要 Docker 或 AI 凭据。未配置
AI 时语义补全显示为“已跳过”；离线归档没有可信的本地运行时镜像引用时，动态阶段
显示失败，最终画像为“部分完成”。这表示静态证据已经发布，但不代表运行时行为已
验证。即使容器内探针成功运行，其工具调用和 guard 结果仍是 `attested`；只有
Sentinel 控制的宿主侧独立观测覆盖全部关键声明时，画像才是“完成”。

## OpenManus

电商 Agent 可以直接执行确定性演示。OpenManus 的静态画像无需 Docker；真实动态
验证需要：

- Docker Desktop 正在运行；
- 分发目录包含 `agents/openmanus/image.tar`，并可将其加载到 Docker。

执行真实容器审计时，在“新建安全审计”的“配置 Agent 模型”区域分别填写被测 Agent、
攻击 Agent 和防御 Agent 的模型 API 地址、模型名与 API Key，并逐项点击“测试并保存”。
也可以通过侧栏“模型配置”提前完成配置；失败审计页面提供同一入口，便于补充配置后续跑。
三项均显示“可用”后才能点击“启动审计”。选择 OpenManus 后，页面会自动切换到
`openmanus-security-v0.1` 和 `openmanus_real`。API Key 只保存在当前 App 进程，
不写入审计任务、报告或证据文件；退出 App 后需要重新填写和测试。

## 攻击交接

发布画像会生成最小化 `attack-profile-v0.1` 及基于风险路径的 AttackSpec，只包含攻击所需的
`verified/supported` 节点、能力、权限、控制、风险路径和证据引用，不包含源码全文、
环境变量值、镜像命令或层列表。创建和恢复审计时都必须校验画像页显示的
`image_digest`、`profile_id` 和 `profile_sha256`；任一值变化时，旧审计不能继续恢复。

每条攻击计划还会绑定静态画像中的预测 `node_id` 和 `path_id`。执行阶段记录该攻击
是否成功；成功时记录被测 Agent 的实际失效节点。Baseline 结果驱动局部 Guard
生成和挂载，Guarded 阶段复测同一风险面；下一轮攻击集根据上一轮失败场景、绕过节点
和最弱链路生成。

## 兼容性

当前应用为 Apple Silicon（arm64）macOS 版本，未使用 Apple 开发者证书公证，
不适用于 Windows 或 Intel Mac。当前机器已验证，其他 macOS 版本仍建议先做兼容性测试。
