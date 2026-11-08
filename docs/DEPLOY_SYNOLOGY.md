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

Web 已提供加密备份创建、校验与下载；还实现了单次离线 recovery 服务和日志化回滚，但尚未在真实 DS920+ 上完成恢复与断电测试。**不能视为已经验证的生产灾备系统。**离线恢复命令见 README。维护前仍应在 DSM 中对持久化卷完成受保护的离线快照，并确保私钥备份和口令保存在不同地方。不要删除 `agent-state`/`manager-state`/`runtime-config` 卷；不要使用 `docker compose down -v`。

## 6. 跨容器离线恢复（仅限停机维护）

> **危险操作**：只有 Docker 管理员可以运行；Web 永远不能触发。恢复前应对当前三个数据卷完成单独、加密且可用的外部快照。该流程已经通过合成数据的单元测试，但仍需 DS920+ 真实灾备演练。

1. 将 `.ovpnbackup` 拷贝到项目目录的 `import/`，文件只允许 NAS 管理员访问，并确保 Compose recovery 容器的 UID/GID 10001 可以只读访问。备份密码与 NAS 上的备份文件分别保存。
2. 将 `.env` 的 `OPENVPN_MANAGER_WRITE_ENABLED` 设置为精确小写 `true`，**停止所有三个容器**（运行中的 VPN 连接将断开）：

```bash
docker compose stop manager control-agent openvpn-runtime
```

3. 临时以不回显方式输入密码，在停止状态下验证备份内容；这里的 ID 是备份文件名中 32 位十六进制字符串：

```bash
read -rs -p 'Backup password: ' BACKUP_PASSWORD; echo
printf '%s\n' "$BACKUP_PASSWORD" | docker compose --profile recovery run --rm -T recovery \
  --id=0123456789abcdef0123456789abcdef \
  --archive=/import/openvpn-ce-0123456789abcdef0123456789abcdef.ovpnbackup \
  --check-only
```

4. 确认备份通过验证、当前业务已停机，并有可靠的旧卷快照后，执行：

```bash
printf '%s\n' "$BACKUP_PASSWORD" | docker compose --profile recovery run --rm -T recovery \
  --id=0123456789abcdef0123456789abcdef \
  --archive=/import/openvpn-ce-0123456789abcdef0123456789abcdef.ovpnbackup \
  --apply --confirm=RESTORE_ALL_OPENVPN_STATE
unset BACKUP_PASSWORD
```

5. 将 Docker 写入变量改回 `false`，启动三个容器，核验 CA、证书、客户端、VPN TCP 连接和 LAN 路由。成功前不要删除三个数据卷下 `.ovpn-restore-old-*` 和 `.ovpn-restore-journal-*`。

6. 如恢复后服务不可用，**再次停止三个容器**、临时开启 Docker 写入变量，再执行恢复工具的 `--rollback --confirm=RESTORE_ALL_OPENVPN_STATE --id=<ID>`。回滚也要求三个服务停机。若发生突然断电，应先检查数据卷和恢复日志，禁止同时启动正常服务及离线恢复容器。

在线恢复被有意禁用，因为跨容器数据库/PKI/Runtime 在服务运行状态下无法提供可信的原子回滚保障。临时 recovery 容器不会通过正常 `docker compose up -d` 启动，也不挂载 Docker Socket。
