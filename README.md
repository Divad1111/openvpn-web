# OpenVPN CE Manager

面向 **Synology DS920+ / Docker Compose / OpenVPN Community Edition 2.7.9 / TCP/IPv4** 的开源 Web 管理平台。

> **目前完成 Phase 1：认证 IPC 与只读诊断。不能用它连接 VPN。** Docker 中的 OpenVPN 二进制从官方发行源码编译，Runtime Supervisor 通过身份验证的 Unix Socket 提供只读状态、TUN/程序/配置文件检查，不启动 OpenVPN。Web 尚无登录、初始化、证书签发或 VPN 启停功能。不要将此阶段部署到生产环境。

## 当前交付（Phase 1）

- `openvpn-runtime`：签名校验的官方 OpenVPN **2.7.9** 源码构建 + 独立 Runtime Supervisor（本阶段不会运行 VPN）。
- `control-agent`：独立 Go 服务，通过 HMAC-SHA256 签名、时间窗口与 nonce 防重放认证的 Unix Socket 读取 Runtime 状态；独立读取容器启动时的写入环境变量；所有尚未实现的变更请求拒绝执行。
- `manager`：Go HTTPS API + Vue 3/TypeScript 管理首页，通过认证 IPC 报告 Docker 写模式、Runtime 状态与只读诊断；自签名**仅供引导测试**的 HTTPS 证书按部署实例独立生成并持久化。
- 默认 `OPENVPN_MANAGER_WRITE_ENABLED=false`，并分别传入 Manager 与 Agent。只接受**精确小写** `true`；未定义或无效时强制只读。
- 默认 Web 仅绑定宿主机 `127.0.0.1:9443`，不自动开放公网端口；Runtime 独立于管理组件。

完整规范：[`docs/DESIGN.md`](docs/DESIGN.md)；Codex 约束：[`AGENTS.md`](AGENTS.md)；实施状态：[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md)。

## DS920+ 测试部署（Phase 1）

前提：DSM 7.x Container Manager、Docker Compose、NAS SSH；确认 `/dev/net/tun` 存在且可用。**未经验证的 DS920+ 内核、iptables 和路由器行为仍需实测。**

```bash
# 进入仓库根目录
cp .env.example .env

# 查看默认配置（必须只读、管理端口仅回环）
docker compose config

# 从官方签名源码构建 OpenVPN，并构建 Go/Vue
# 第一次需联网访问 Debian、Go/Node 镜像仓库、OpenVPN 官方源站与 GPG keyserver
docker compose build

# 启动三个容器；这不会真正启动 OpenVPN VPN 进程
docker compose up -d

docker compose ps
# 检查 2.7.9 二进制版本
docker compose run --rm --no-deps --entrypoint /usr/local/sbin/openvpn openvpn-runtime --version
```

默认端口在 NAS 的回环地址上，**其他电脑无法直接打开** `https://NAS-IP:9443`。若要从可信 LAN 电脑打开测试页，编辑 `.env` 将 `MANAGER_BIND_IP=127.0.0.1` 改为 NAS 的具体局域网 IPv4 地址，并在 DSM 防火墙限制来源；重新创建 manager：

```bash
docker compose up -d --no-deps --force-recreate manager
```

随后访问 `https://NAS-LAN-IP:9443`。初期 HTTPS 证书是本实例自签名证书，浏览器可能提示不受信任；生产阶段须配置受信任证书，不要为了绕过证书问题公开明文 HTTP 管理口。

## Docker 控制的写保护

`.env`：

```dotenv
OPENVPN_MANAGER_WRITE_ENABLED=false
```

切换为可写之前请理解：**Phase 1 即使开启环境变量也没有任何可执行的写功能**。后续阶段的授权上限由 Docker 环境控制，并由 Manager 和 Agent 分别强制校验。

需要切换时仅编辑 `.env` 并执行：

```bash
# 开启：手动修改 .env 为 OPENVPN_MANAGER_WRITE_ENABLED=true
# 关闭：手动修改 .env 为 OPENVPN_MANAGER_WRITE_ENABLED=false
# 每次修改后执行（不重启 OpenVPN Runtime）：
docker compose up -d --no-deps --force-recreate manager control-agent
```

注意：`docker compose restart` **不读取变更后的环境变量**；已有容器必须重新创建。Runtime 在模式切换期间保持独立；完成维护后必须手动把变量改回 false。

## 本地 Go 检查

```bash
go test ./...
go test -race ./...
go vet ./...
```

前端工程（首次需下载 npm 包）：

```bash
cd frontend
npm install
npm run build
```

**供应链限制：** Phase 0 已对 OpenVPN 上游 tarball 进行 GPG 签名和指纹验证，但 Node lockfile 与基础镜像 digest 固定仍是发布前待完成项；见实施状态文档。构建失败不应绕过验签。

## Phase 1 IPC 及诊断安全性

- Manager 与 Agent、Agent 与 Runtime 使用不同命名卷中的 **独立 HMAC 密钥**（32 字节随机数）。服务端首次启动原子创建密钥，之后重启保持原密钥；密钥缺失、权限异常或签名不正确时拒绝请求。
- 请求签名覆盖 HTTP 方法、完整 URI、时间戳、nonce 和请求体 SHA-256；默认 60 秒有效窗口，并在服务内限制重放。跨容器读密钥的卷只读挂载。
- Manager 和 Agent 不接受未经授权的 Unix Socket 请求，Agent 无法直接覆盖 Runtime 的控制 Socket。Runtime 不持有 CA 私钥。
- Runtime 只会报告 `UNINITIALIZED`、`CONFIG_PRESENT_UNVALIDATED`、`UNSAFE_CONFIG` 等状态；配置存在并不代表已验证有效，也不代表 VPN 已启动。
- 当 Agent 不可用或签名失败时，Manager 将写权限按失败关闭处理。
- 可以在普通 Linux 系统执行 `bash tests/integration/local-ipc.sh`，验证三进程通信、未认证请求拒绝、只读拦截和 Agent 重新启动不影响 Runtime。
- **限制：** Phase 1 只实现受限只读 RPC；管理员身份认证、客户端证书、实际 OpenVPN 启停与路由由 Phase 2–4 完成。断线、容器卷权限和 DSM TUN 仍需在 Docker/DS920+ 实测。

## 下一阶段

按 [`docs/DESIGN.md`](docs/DESIGN.md) 的 Phase 2–5 顺序实现：证书密钥安全隔离、管理员/TOTP、初始化向导、VPN 实际启动/路由、客户端管理和备份。**不能使用当前代码管理真实 VPN 服务器。**

仓库采用 Apache-2.0 许可证；上游 OpenVPN 及其他组件依其各自许可证分发。
