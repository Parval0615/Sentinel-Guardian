# 电商客服 Agent 镜像

构建上下文必须是仓库根目录：

```bash
docker build --platform linux/arm64 \
  --build-arg SOURCE_DATE_EPOCH=0 \
  -f agents/电商/Dockerfile \
  -t redsentinel/ecommerce-agent:task12 .
```

通常不需要单独执行该命令。统一分发命令会构建、导出并校验镜像。
