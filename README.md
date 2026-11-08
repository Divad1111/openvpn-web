# OpenVPN CE Manager

社区版 OpenVPN Community Edition **2.7.9** 的 Web 管理项目，目标平台 **Synology DS920+（amd64）**、Docker Compose、TCP/IPv4。OpenVPN 二进制从官方 GPG 签名源码构建，不使用 OpenVPN Access Server 或第三方 VPN 镜像。

> **安全警告：这是尚未经过 DS920+ 真实 TUN / iptables / TCP 连接验证的开发版本，不可作为生产 VPN 部署。** 目前代码包含认证、Easy-RSA、配置生成、客户端页面等功能，已经实现离线恢复工具，但 Web 在线恢复及 DS920+ 灾备演练尚未完成。参见 [实施状态](docs/IMPLEMENTATION_STATUS.md)。

## 容器架构

- `manager`：Go HTTPS API、Vue3 UI、SQLite 管理员账号、Argon2id 密码哈希、TOTP、会话、审计。
- `control-agent`：独立的双重写入校验、Easy-RSA/CA、证书、OpenVPN 配置、客户端及 CRL。
- `openvpn-runtime`：官方编译的 OpenVPN CE 2.7.9 和独立 Supervisor，只有此容器持有 TUN 与 NET_ADMIN。

Manager ↔ Agent ↔ Runtime 使用带时间戳/随机数/防重放校验的 Unix Socket HMAC 请求；不提供任意 Shell、Docker Socket 和公网控制端口。

## Docker 控制的安全保护（默认只读）

```dotenv
OPENVPN_MANAGER_WRITE_ENABLED=false
```

Web 页面**没有**写模式开关；即使管理员登录，也只有在 Manager **和** Agent 的环境变量都严格为小写 `true` 时才能执行变更。首次安装也是修改操作，必须先由 Docker 管理员开启。

```bash
cp .env.example .env
# 编辑 .env，把 OPENVPN_MANAGER_WRITE_ENABLED 设为 true
# 仅重新创建两个管理容器，运行中的 VPN 不会被重建
docker compose up -d --no-deps --force-recreate manager control-agent
# 完成维护后，把 .env 改回 false，并再次执行同一命令
```

注意：`docker compose restart` 不会读取更新后的环境变量。

## 构建（开发测试环境）

```bash
cp .env.example .env
# 如需 LAN 管理，请显式指定 NAS 的 LAN IP，设置防火墙和 HTTPS 证书
# MANAGER_BIND_IP=192.168.1.100

docker compose --env-file .env config
docker compose --env-file .env build
docker compose --env-file .env up -d

docker compose logs manager
# 首次启动日志只会显示一次 ONE-TIME BOOTSTRAP TOKEN
```

管理页面默认为 `https://127.0.0.1:9443` 的宿主回环绑定，初次自签名证书需要在可信 LAN 环境内自行确认证书指纹。若从其他设备访问，请修改 `MANAGER_BIND_IP` 并仅允许可信 LAN 来源，绝不将 9443 直接转发到公网。

Docker 端口映射默认为 TCP 1194，若更改 `.env` 中的 `OPENVPN_TCP_PORT`，必须重建 `openvpn-runtime`（这会断开连接）。路由器要转发该 TCP 端口，DSM 防火墙需允许；Web 不管理宿主机 iptables。

## 初次配置（尚未在 DS920+ 实测）

1. 开启 Docker 写模式并重新创建 manager 和 control-agent。确认 `/dev/net/tun` 可用。
2. 打开 HTTPS 页面，输入 `docker compose logs manager` 里的一次性 token，创建管理员并绑定 TOTP。
3. 登录后在“VPN 配置”填写公网域名、VPN CIDR、家庭 LAN CIDR、DNS。
4. 输入至少 16 字符的 CA 口令与 TOTP，初始化 CA 和服务端证书。妥善保存口令，未持有口令无法签发/吊销。
5. 预览并应用配置。Supervisor 启动 OpenVPN；若 iptables/TUN 不兼容，应报告错误而不是绕过。
6. 为每个设备签发单独证书、通过 TOTP 一次性导出 `.ovpn`，导入支持 TCP 的 OpenVPN 客户端。
7. 将 `.env` 的写入模式改回 `false`，重新创建管理容器，保留 Runtime 连线。

更多信息参阅 [设计文档](docs/DESIGN.md)、[Codex 工作规则](AGENTS.md) 和 [部署核验清单](docs/DEPLOY_SYNOLOGY.md)。

## 当前不足

加密备份和离线恢复已实现，Linux Docker 中真实 TCP/TLS 握手及证书吊销重连拒绝已通过 CI；但完整 Web→Agent→Runtime 联调、DSM 网络/防火墙与 NAS 上的灾备恢复仍未实测。**请勿把页面“运行中”当作真实互联网 VPN 已连通的证明。**

## 许可证

本仓库 Apache-2.0；OpenVPN、Easy-RSA 等上游分别按各自许可证分发，不因本仓库许可证而更改。

## Phase 5 当前边界（安全提示）

已加入双份独立加密的 `.ovpnbackup` 创建、下载与完整性校验。Manager 的 SQLite、master.key 与 Agent 的 PKI、配置、SQLite 分别使用独立 salt/nonce 的 Argon2id + AES-256-GCM 保护；Manager 不持有 Agent 明文 CA 私钥。创建和下载均需 Docker 写模式与管理员 TOTP。**已提供按需启动的离线 recovery 工具及回滚日志；Web 在线恢复、跨机器迁移与 DS920+ 全流程验收仍未完成**。请继续使用 DSM 受保护的离线卷快照作为独立兜底。

## 离线恢复（仅 Docker 管理员）

新增可选 Compose `recovery` profile，正常运行仍为三容器。恢复必须先停止 manager、control-agent、openvpn-runtime，输入独立备份密码，并显式传入 `--apply --confirm=RESTORE_ALL_OPENVPN_STATE`。恢复工具检查三个进程生命周期锁，验证双层加密与归档哈希，保留可人工回滚的旧状态。Web 不提供在线恢复按钮，实际 DS920+ 恢复仍需验收。详细步骤见 [Synology 部署与离线恢复说明](docs/DEPLOY_SYNOLOGY.md)。

## 离线恢复（Phase 5 开发验证，仍需 DSM 实机演练）

已实现一个**按需启动**的 `recovery` 服务，不属于常驻三容器。恢复只能由 Docker 管理员操作，网页中不开放恢复 API，且 Manager、Agent、Runtime 必须全部停止。恢复工具会验证 `.ovpnbackup` 双重加密负载、证书/SQLite 基本结构、原始配置和文件哈希，并在各数据卷上保留回滚副本和恢复日志。

```bash
# 备份归档放入 ./import/<32位备份ID>.ovpnbackup，确保仅 NAS 管理员可读。
# 下面命令必须在维护窗口执行，会中断全部 VPN 客户端。
# 先在 .env 中设置 OPENVPN_MANAGER_WRITE_ENABLED=true

docker compose stop manager control-agent openvpn-runtime

# 通过 stdin 传递口令，避免将密码放在命令行参数中（请使用仅管理员可读的私密文件）。
docker compose --profile recovery run --rm -T recovery \
  --id <32位备份ID> \
  --archive /import/<32位备份ID>.ovpnbackup \
  --check-only < /secure/backup-passphrase.txt

# 校验通过后执行；恢复工具只接受写模式 true 和明确确认短语。
docker compose --profile recovery run --rm -T recovery \
  --id <32位备份ID> \
  --archive /import/<32位备份ID>.ovpnbackup \
  --apply --confirm RESTORE_ALL_OPENVPN_STATE < /secure/backup-passphrase.txt

# 手动确认已完成原始数据卷备份，然后重新启动三个容器。
docker compose up -d
```

如果恢复后需要回滚，**先停止三个容器**，再执行 `docker compose --profile recovery run --rm recovery --id <备份ID> --rollback --confirm RESTORE_ALL_OPENVPN_STATE`；无需重新提供归档口令。现有数据的旧版本会保留在各持久化卷的 `.ovpn-restore-old-<id>` 下，验证成功之前不要清理。恢复完成后把 `.env` 的写模式改回 `false`，再只重新创建 Manager 和 Agent。

**限制：** 此功能已由 Go 级别的签名校验/恢复/回滚测试覆盖，但尚未在 DS920+ 真实持久卷、断电和端口转发环境中演练。实际使用前应对三个卷额外制作离线 DSM 快照。禁止 `docker compose down -v`，否则会删除持久卷。
