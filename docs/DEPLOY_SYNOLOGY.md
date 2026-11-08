# DS920+ 安全部署与实机验收清单

> 以下命令是预期流程，尚未在 DS920+ 上执行。验证前不要用于生产业务。

## 1. 环境准备

- DS920+ x86-64 + DSM 7.x + Container Manager，允许 SSH 管理的账户。
- NAS 上 `/dev/net/tun` 应为字符设备；如果不存在，核对 DSM 的驱动/权限，不自动运行不可信内核模块。
- 路由器 TCP/1194 转发到 NAS LAN IP；若处于 CGNAT，公网 IPv4 接入不可用。
- 保证公网 DNS 解析到路由器的外部 IP。管理 HTTPS 9443 只允许可信 LAN IP。
- 避免 VPN CIDR（默认 10.8.0.0/24）和家用 LAN、Docker Bridge、外出网络的网段冲突。

## 2. 构建和初始化

```bash
cd /volume1/docker/openvpn-web
cp .env.example .env
vi .env  # 指定 MANAGER_BIND_IP，保持 write=false
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
# 需要首次管理员初始化时：将 write 改成 true
docker compose up -d --no-deps --force-recreate manager control-agent
docker compose logs manager  # 若首次 token 丢失，不要重复生成 CA
```

> 容器内不可使用 Web 修改 Compose 的 host 端口或 NAS 全局防火墙；这些都属于 Docker 管理员操作。

## 3. 初始化向导

创建管理员、绑定 TOTP、创建加密 CA、配置 DNS/分流、生成服务端配置，完成后从外部非家庭 Wi-Fi 的网络导入测试客户端配置。

## 4. 网络核验

```bash
# 检查宿主 TUN
ls -l /dev/net/tun
# 检查容器日志（脱敏后再分享）
docker compose logs --tail=100 openvpn-runtime
# 检查群晖监听/转发 TCP 1194
# 具体工具依 DSM 版本而定，切勿清空全局 iptables 规则。
```

验证真实客户端：TLS 握手通过 → 分配 10.8.0.x → 能访问家庭 LAN IP → 分流后公网 IPv4 不经过 VPN → 吊销证书后重新连接失败；还要重建 manager 与 agent 以证实 Runtime 会话不断开。

## 5. 安全恢复

Web 已提供加密备份创建、校验与下载，但**跨容器恢复尚未实现**；请勿把此版本视为已验证的灾备系统。维护前仍应在 DSM 中对持久化卷完成受保护的离线快照，并确保私钥备份和口令保存在不同地方。不要删除 `agent-state`/`manager-state`/`runtime-config` 卷；不要使用 `docker compose down -v`。
