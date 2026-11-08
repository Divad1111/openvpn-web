# 实施记录与限制（2026-11-08）

## Phase 1：已实现认证 RPC 与 Runtime 只读诊断

- Manager ↔ Control Agent 与 Agent ↔ Runtime：两组独立 32 字节随机密钥 + HMAC-SHA256，签名绑定 method/URI/时间戳/nonce/请求体 hash，60 秒内重放防护；HMAC 错误返回 401。
- Manager 与 Agent 再次分别读取严格 `true` Docker 写入模式；操作接口仍未开发，永远拒绝写入（只读返回 423，模式 true 返回 501）。
- Runtime Supervisor：固定路径只读检查 TUN 字符设备、OpenVPN 可执行文件、server.conf 是否存在及权限；存在配置时仅报告 `CONFIG_PRESENT_UNVALIDATED`，不自动启动 VPN。
- Docker IPC 卷：Manager ↔ Agent 的 Manager 挂载为只读；Agent ↔ Runtime 的 Agent 挂载为只读；运行时/证书卷保持分离。
- 管理 API 新增 `GET /api/v1/system/checks`；页面显示经过认证的 Runtime 状态和检查诊断。
- 已本地验证：`go test ./...`、`go test -race ./...`、`go vet ./...`、`bash tests/integration/local-ipc.sh`，均通过。
- **未验证：** Docker 实际运行、容器间只读挂载的 Unix Socket 连接、DSM 7.x / DS920+ TUN/netfilter、OpenVPN 握手；暂无真实 VPN 连接能力。CI 镜像构建需 GitHub Actions 再次验证。
- **待实现 Phase 2：** 登录/TOTP、Bootstrap Token、双门禁写 API/Agent RPC 的安全授权与事务、审计；Phase 3 才开始真实 OpenVPN。


## Phase 0：首批工程骨架

| 内容 | 当前状态 | 说明 |
|---|---|---|
| 三容器 Compose | GitHub Actions 已完成构建；DS920+ 未实测 | manager / control-agent / openvpn-runtime，独立生命周期 |
| OpenVPN 2.7.9 官方源码构建 | GitHub Actions Docker 构建与版本验证通过 | tarball + asc + 公钥指纹三项核验；禁用 DCO |
| Vue 3 管理页 | GitHub Actions Vue 生产构建通过 | 展示状态；不提供可写按钮或敏感功能 |
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
- Docker Engine：本地环境无 Docker；**GitHub Actions run 42473097338 已实际通过三镜像构建、官方源码签名验证、OpenVPN 版本检查**；尚未在 DS920+ 上部署和运行容器。
- npm：本地环境不能联网下载依赖；**GitHub Actions run 42473097338 已通过 npm 安装、Vue/TypeScript 构建**。

## 尚需处理的发布阻塞项

1. **CI 已完成** OpenVPN 2.7.9 官方验签源码构建、三镜像构建、Vue/Go 编译。接下来仍需 DS920+ 实机加载镜像、检查运行库、网络与容器权限。
2. 生成并提交 frontend 的 lockfile，用 `npm ci` 替代当前的 `npm install`；固定基础镜像 digest，并执行容器镜像漏洞扫描和许可证清单。
3. 三容器共享 Unix Socket 的 Docker named-volume UID/GID、Socket 访问在 DSM 实机必须验收。
4. HTTPS 仅为短期自签名测试证书；需提供可信证书管理、到期更新与浏览器提示。
5. Manager-Agent、Agent-Runtime **写 RPC 尚不存在**，后续必须加入调用方身份认证、请求幂等、时间戳防重放和白名单权限验证，禁止无授权控制能力。
6. 本阶段所有写请求均返回 `423 WRITE_MODE_DISABLED` 或 `501 NOT_IMPLEMENTED`，不能把 `effectiveWriteAllowed: true` 理解为已经实现写操作。
7. OpenVPN 的真实进程托管、管理接口、TLS、证书吊销、netfilter 路由、灾难恢复均尚未完成。

## 后续开发指令

请按 AGENTS.md / DESIGN.md **Phase 2** 开发；不要跳阶段到“可用 VPN”。优先实现管理员身份认证、TOTP 与 Bootstrap Token、写入权限双校验的操作请求与审计；不得提前开放真正的 VPN 修改接口。
