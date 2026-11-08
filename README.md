# OpenVPN CE Manager

面向 **Synology DS920+ / Docker Compose / OpenVPN Community Edition 2.7.9 / TCP** 的开源 Web 管理平台。

> **当前状态：设计阶段，尚未实现服务和 Docker 镜像。** 不要将本仓库当作已可部署的 VPN 产品。

## 项目目标

用户在 NAS 上构建并启动 Docker 容器后，通过浏览器完成管理员初始化、CA 和证书管理、VPN 网络配置、设备创建、客户端 `.ovpn` 导出、在线状态监控、吊销和维护。OpenVPN 核心从**官方源码**构建，不使用 OpenVPN Access Server 或第三方 OpenVPN 成品镜像。

计划架构由三个容器组成：

- **manager**：Go API + Vue 3 Web 界面；身份认证、TOTP、只读监控。
- **control-agent**：证书管理、配置管理、双重写入安全校验、受限控制协议。
- **openvpn-runtime**：OpenVPN CE 2.7.9 + Runtime Supervisor；连接不依赖 manager 存活。

## 关键安全设计：Docker 控制写入模式

```dotenv
# .env — 默认只读
OPENVPN_MANAGER_WRITE_ENABLED=false
```

仅当 Docker 管理员显式设置为 `true`，并重新创建 manager 和 control-agent 两个容器后，才能执行系统变更；网页上**没有**开启写权限的开关。Manager 与 Agent 必须分别校验，任何失败均拒绝写入。

实现完成后的目标操作（**当前不可执行**）：

```bash
# 编辑 .env: OPENVPN_MANAGER_WRITE_ENABLED=true
docker compose up -d --no-deps --force-recreate manager control-agent

# 完成维护后把 .env 改回 false，然后再次执行：
docker compose up -d --no-deps --force-recreate manager control-agent
```

注意：`docker compose restart` 不会应用变更后的环境变量。OpenVPN Runtime 不应因切换 Web 写模式而重建。

## 文档

- [完整开发设计规格书](docs/DESIGN.md)：架构、模块边界、API、数据模型、安全规范、测试/验收标准与 Phase 0–5。
- [Codex 工作规范](AGENTS.md)：不可绕过的安全要求、开发顺序、交付标准。

## 让 Codex 开始开发

在 Codex 工作目录指向本仓库后使用：

> 阅读 AGENTS.md 和 docs/DESIGN.md。严格按照设计方案，从 Phase 0 开始实现：官方 OpenVPN CE 2.7.9 源码签名验证构建、三容器 Compose、Go/Vue 工程脚手架、默认只读配置、安全基线和 CI。只实现 Phase 0，完成测试并明确未验证项，然后提交代码。不要跳过写权限双重校验，不要挂载 docker.sock，也不要使用 privileged。

## 构建与兼容性说明

DS920+ 是 x86-64 / amd64；DSM 的 TUN、netfilter/iptables、Docker 网络和防火墙兼容性必须在实机验收。公网访问 VPN 需要路由器端口转发；默认管理 HTTPS 仅绑定可信地址。

## 许可证

仓库当前包含 Apache-2.0 许可证。OpenVPN 与其他第三方组件保留各自许可证，后续发布镜像须进行许可证检查并保留上游声明。
