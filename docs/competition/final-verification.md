# Sentinel-Guardian 最终验证记录

验证日期：2026-08-31  
目标版本：`0.1.0`  
目标平台：macOS arm64

## 自动化结果

| 检查 | 命令 | 结果 |
|---|---|---|
| Python 全量回归 | `python -m pytest -q` | `1068 passed, 2 deselected` |
| 前端单元与交互测试 | `npm test -- --run` | `50 passed` |
| TypeScript 与生产构建 | `npm run build` | 通过 |
| 桌面与移动真实服务验收 | `npm run test:e2e` | `2 passed` |
| WCAG A/AA 自动扫描 | Playwright + axe | `0 violations` |
| Python correctness lint | `python -m ruff check . --select F401,F841,F821,F811` | 通过 |
| 空白与冲突标记检查 | `git diff --check` | 通过 |
| 前端生产依赖审计 | `npm audit --omit=dev --audit-level=high` | `0 vulnerabilities` |

Playwright 使用真实 FastAPI 与 Vite 服务完成注册和工作台加载，覆盖：

- 1440×1100 桌面视口
- 390×844 移动视口
- 无横向溢出
- 无浏览器控制台错误
- 移动底部导航不覆盖内容

截图位于同目录：

- `ui-login-desktop-1440.png`
- `ui-dashboard-desktop-1440.png`
- `ui-login-mobile-390.png`
- `ui-dashboard-mobile-390.png`
- `ui-enterprise-agent-desktop-1440.png`
- `ui-enterprise-agent-mobile-390.png`

## 安全闭环

- `/execute`、`/resume` 和下一轮生成前均执行完整环境预检。
- 每一轮新攻击集先进入 `attack_review`，不会直接执行。
- 注销会递增持久化 token 版本，旧 JWT 立即失效。
- API Key 仅保存在 App 进程内存，不进入浏览器存储、任务或报告。
- 密钥模式扫描命中均为攻击样本和脱敏回归夹具；未发现真实凭据。
- 已移除停止维护的 `langchain-community` 运行依赖，RAG 使用独立维护包和直接解析器。

## 发布包

| 项目 | 结果 |
|---|---|
| App | `Sentinel Guardian.app` |
| ZIP | `Sentinel Guardian-macOS-arm64.zip` |
| Bundle ID | `ai.redsentinel.guardian` |
| App 版本 | `0.1.0` |
| 架构 | arm64 |
| ZIP SHA-256 | `b527fed286be004aeba5e628942ed731fcb6b7ebfb956848ad2eadec15223578` |
| ZIP 完整性 | 通过 |
| 深度签名验证 | 通过 |
| 打包后健康接口 | 通过 |
| 打包后注册、认证、注销失效 | 通过 |

当前使用 ad-hoc 本地签名，适用于竞赛演示机和受控分发。面向互联网公开分发时仍需
Developer ID 签名与 Apple notarization；这不影响当前离线竞赛交付。

## 证据边界

真实 OpenManus W2 证据仍限定为一个 Agent、一个模型和一个 seed。当前验证不使用
未提供的真实模型凭据，也不把离线 smoke 结果表述为新的跨模型实测结论。
