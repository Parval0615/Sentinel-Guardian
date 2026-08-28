# OpenManus Agent 镜像

该制品必须使用仓库现有 `infra/openmanus/Dockerfile` 构建：

```bash
docker build --platform linux/arm64 \
  --build-arg SOURCE_DATE_EPOCH=0 \
  --provenance=false \
  -f infra/openmanus/Dockerfile \
  -t redsentinel/openmanus-real:task12 .
```

Dockerfile 默认固定 `python:3.12-slim-bookworm` 的多架构摘要。网络受限时可显式指定
Debian 主源和安全源；构建仍会校验并安装完整运行依赖：

```bash
docker build --platform linux/arm64 \
  --build-arg APT_MIRROR=https://mirrors.aliyun.com/debian \
  --build-arg APT_SECURITY_MIRROR=https://mirrors.aliyun.com/debian-security \
  --provenance=false \
  -f infra/openmanus/Dockerfile \
  -t redsentinel/openmanus-real:task12 .
```

运行时仍需通过环境变量提供模型 API 地址、模型名和密钥。统一分发命令负责构建、
导出和校验镜像，镜像中不包含真实凭据。
