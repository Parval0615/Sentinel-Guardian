# Sentinel-Guardian Frontend

当前产品界面是位于 `src/` 的 React + TypeScript 应用。`app.html` 是 Vite
源码入口；构建完成后，`vite.config.ts` 将产物入口统一为
`dist/index.html`，由 Product API 或桌面应用托管。

根目录的 `index.html` 是历史静态演示资产，不再作为 Product API 的自动回退入口。

## 开发

先启动后端：

```bash
python -m uvicorn redsentinel.application.engine.app:create_app \
  --factory --host 127.0.0.1 --port 8000
```

再启动前端开发服务器：

```bash
npm install
npm run dev
```

打开 `http://127.0.0.1:5173/`。Vite 会把 `/v1` 请求代理到
`http://127.0.0.1:8000`。

## 生产构建

```bash
npm run build
```

构建会执行 TypeScript 检查，并生成：

```text
dist/
  index.html
  assets/
```

完成构建后，也可以只启动 Product API 并打开
`http://127.0.0.1:8000/`。后端只托管 `dist/index.html`，不会回退到历史静态页面。

## 测试

```bash
npm test -- --run
npm run build
npm run test:e2e
```

前端测试覆盖认证、API 请求、画像完整性、轮询退出条件、攻击审阅门禁和主要工作区流程。
Playwright 会在 1440×1100 与 390×844 两个目标视口启动真实前后端，验证注册、工作台、
横向溢出和控制台错误，并更新 `docs/competition/evidence-pack/ui-*.png`。

## 安全边界

- 浏览器仅在 `localStorage` 或 `sessionStorage` 保存登录 token。
- 模型 API Key 只提交到当前 App 进程，不写入浏览器存储、审计任务或报告。
- 画像、审计、证据和模型配置均按认证用户绑定的租户访问。
- 每一轮攻击计划都必须停在 `attack_review`，通过完整预检并由用户确认后才能执行。
