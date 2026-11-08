# 实施记录与限制（2026-11-08）

## Phase 0：首批工程骨架

| 内容 | 当前状态 | 说明 |
|---|---|---|
| 三容器 Compose | 已编写，未在 Docker Engine 实测 | manager / control-agent / openvpn-runtime，独立生命周期 |
| OpenVPN 2.7.9 官方源码构建 | 已编写，Docker 构建未实测 | tarball + asc + 公钥指纹三项核验；禁用 DCO |
| Vue 3 管理页 | 已编写，npm 构建未实测 | 展示状态；不提供可写按钮或敏感功能 |
| Go Manager HTTPS | 已实现并通过 Go 测试 | 引导自签名证书；未实现身份认证，暂不生产可用 |
| Go Agent Unix Socket 状态 | 已实现并通过 Go 测试 | 本阶段只有状态查询；尚无强认证 RPC |
| Go Runtime Supervisor | 已实现状态骨架 | 不启动 OpenVPN，即使有配置也仅回报 UNINITIALIZED |
| Docker 默认只读 | 已编写并通过 Go 单测 | 精确匹配 true；Manager/Agent 各自读取，未实现 mutation API |
| DSM 网络/TUN/容器实测 | 未完成 | 必须到 DS920+ 机器上测试 |
| PKI、登录/TOTP、API 权限 | 未实现 | Phase 2–4 |
| 初始化向导、OpenVPN 真实连接 | 未实现 | Phase 3–4 |
| 证书吊销、备份、审计 | 未实现 | Phase 4–5 |

## 已运行的检查

- `go test ./...`：通过（开发容器 Go 1.23.2）
- `go test -race ./...`：通过
- `go vet ./...`：通过
- Docker Engine：本会话环境无 Docker，**未进行实际镜像构建、签名验证运行或运行容器检查**。
- npm：本会话环境不能联网下载依赖，**未进行前端真正打包检查**。GitHub Actions 已配置执行这些构建。

## 尚需处理的发布阻塞项

1. 在 CI 实际完成 `docker compose build`；核对官方 2.7.9 GPG 签名、OpenVPN configure 与运行库、Node/Vue 构建。
2. 生成并提交 frontend 的 lockfile，用 `npm ci` 替代当前的 `npm install`；固定基础镜像 digest，并执行容器镜像漏洞扫描和许可证清单。
3. 三容器共享 Unix Socket 的 Docker named-volume UID/GID、Socket 访问在 DSM 实机必须验收。
4. HTTPS 仅为短期自签名测试证书；需提供可信证书管理、到期更新与浏览器提示。
5. Manager-Agent、Agent-Runtime **写 RPC 尚不存在**，后续必须加入调用方身份认证、请求幂等、时间戳防重放和白名单权限验证，禁止无授权控制能力。
6. 本阶段所有写请求均返回 `423 WRITE_MODE_DISABLED` 或 `501 NOT_IMPLEMENTED`，不能把 `effectiveWriteAllowed: true` 理解为已经实现写操作。
7. OpenVPN 的真实进程托管、管理接口、TLS、证书吊销、netfilter 路由、灾难恢复均尚未完成。

## 后续开发指令

请按 AGENTS.md / DESIGN.md **Phase 1** 开发；不要跳阶段到“可用 VPN”。优先实现身份验证的受限 Agent/Runtime IPC、Runtime 无配置和合法配置状态机，独立重建 Manager/Agent 不影响 Runtime 的集成测试。
