# OpenVPN CE Manager — 开发设计规格书（Codex Implementation Specification）

> **文档版本：** v1.0（2026-11-08）  
> **仓库：** https://github.com/Divad1111/openvpn-web  
> **项目状态：** 设计基线，尚未实现；本文件定义实现目标和验收条件。  
> **目标环境：** Synology DS920+ / DSM 7.x / Container Manager / linux/amd64  
> **VPN 核心：** OpenVPN Community Edition **2.7.9**（官方源码自行构建，非 Access Server、非第三方 OpenVPN 成品镜像）  
> **协议：** TCP/IPv4，默认 1194/tcp；MVP 使用 tun、IPv4 分流。  
> **优先级：** **安全 > 可恢复性 > 功能 > 易用性**。

## 0. Codex 阅读指南和交付目标

本文件面向可以独立编码、测试并提交 PR 的 Codex Agent。实施前必须阅读根目录的 `AGENTS.md`，按第 15 节阶段顺序推进；一个阶段完成并通过对应测试后，再开始下一阶段。**不得**为了实现一键管理而挂载 Docker Socket、开启 privileged、放宽权限门禁或绕过证书安全。

交付物不是本文档里的示例代码片段，而是一个可从零部署的开源项目：用户拉取仓库，在 DS920+ 用 `docker compose build` 构建 OpenVPN 2.7.9 和管理组件，通过网页完成配置、证书、客户端管理；Docker 环境变量控制的写入保护默认关闭，网页没有解锁按钮。

### 0.1 必须满足的最小成功场景（MVP）

1. DS920+ 运行 Compose，Manager、Control Agent、Runtime 三个容器正常就绪；没有配置时 Runtime 不崩溃重启。
2. 默认 `OPENVPN_MANAGER_WRITE_ENABLED=false`，Web 可以登录查看初始化状态，但所有系统修改（包括首次创建管理员和 PKI）均不可执行。
3. NAS 管理员将 `.env` 中该变量设为 `true`，重新创建 **manager 和 control-agent** 容器后，才能进入初始化向导；OpenVPN Runtime 不需要随之重启。
4. 使用首次启动令牌创建管理员、设置强密码和 TOTP，完成 TUN 检测、VPN/LAN 网段、域名、证书与 TCP 参数配置。
5. Agent 生成服务器配置和 CA/证书，通过受限 Runtime Supervisor 启动 OpenVPN；可为设备创建单独证书、生成完整 `.ovpn` 并安全下载。
6. 通过客户端连接访问家庭局域网；查看在线状态、日志；吊销客户端并使 CRL 生效。
7. 维护完成后将变量改回 `false`，重新创建 manager 与 control-agent，Web 回到只读；已连接的 OpenVPN 客户端不因模式切换断线。
8. 断电/容器重启后配置和证书仍在，VPN Runtime 按已保存的有效配置自动恢复；不重置 CA。

### 0.2 明确不在 MVP 范围

- 不做 OpenVPN Access Server、LDAP、RADIUS、SSO、用户计费；
- 不实现 Web 内编译/升级容器，不让网页修改 Docker/Compose 文件；
- 不做 UDP、IPv6、多节点、HA、多租户、手机 App；
- 不承诺全网段任意拓扑自动修复；路由器端口转发和 DSM 防火墙保留明确人工操作；
- 不支持网页输入任意 Shell 命令或粘贴任意 OpenVPN 指令作为执行脚本；
- 不提供“仅查看但下载私钥”的绕过途径。

## 1. 决策记录（冻结项）

| ID | 决策 | 理由/约束 |
|---|---|---|
| ADR-001 | OpenVPN 2.7.9 从官方 tarball 构建 | 避免依赖第三方 OpenVPN 打包镜像；固定版本、签名校验 |
| ADR-002 | 三容器：manager / control-agent / openvpn-runtime | Web 无系统权限；Agent 处理配置/PKI；Runtime 承载长连接 |
| ADR-003 | 默认只读，由 Docker 环境变量控制写入 | Web 不能改变写入状态；修改变量后必须 recreate |
| ADR-004 | 管理页面仅 LAN / 可信 VPN 可达，HTTPS | 不对公网开放管理口 |
| ADR-005 | 管理 API 与 Agent 采用受限、认证过的 Unix Socket | 不开放 Agent TCP 管理端口，不挂载 docker.sock |
| ADR-006 | OpenVPN Management Interface 仅 Unix Socket + 凭据/权限 | 禁止向宿主/公网发布原生 management 端口 |
| ADR-007 | PKI 由 Agent 管理；CA 私钥不进入 Runtime | Runtime 只能拿到运行必需证书和私钥、CRL |
| ADR-008 | SQLite + 版本化文件 + 审计日志 | 简化单机部署，支持重建和恢复 |
| ADR-009 | 首次初始化也是写操作，必须先开启 Docker 写入变量 | 没有隐藏的初始化后门 |
| ADR-010 | Docker 端口映射不是 Web 可修改项 | 修改外部端口应编辑 Compose 并单独重建 Runtime |

如需变更冻结项，应先更新本文件、列出安全影响并新增 ADR 后再编码。

## 2. 体系结构

```text
Browser (LAN only, HTTPS 9443)
        |
        v
+------------------------------+
| manager                      |   non-root, no NET_ADMIN
| Vue3 UI + Go HTTPS API       |   no Docker socket
| auth / TOTP / RBAC / audit   |   own DB volume
| effective write-mode display |
+------------------------------+
        | authenticated Unix socket, API allowlist
        v
+------------------------------+
| control-agent                |   separate process/container
| write-gate (own env check)   |   PKI encrypted at rest
| Easy-RSA / config generator  |   validated fixed operations
| transactions + versioning    |   writable config/PKI volumes
+------------------------------+
        | restricted control socket and config files
        v
+------------------------------+
| openvpn-runtime              |   /dev/net/tun + NET_ADMIN only
| Supervisor (stable PID 1)    |   config/cert mounts RO
| OpenVPN CE 2.7.9             |   TCP 1194 exposed
| management Unix socket       |   no CA private key
+------------------------------+
        |
        v
VPN clients --> home LAN (split tunnel) / optional future full tunnel
```

### 2.1 三容器职责

**manager：**
- 提供静态前端、HTTPS API、身份认证、TOTP、RBAC、只读状态聚合、审计；
- 在启动时严格解析 `OPENVPN_MANAGER_WRITE_ENABLED`：只有小写精确值 `true` 可写；缺失、空串、`1`、`TRUE`、其他任何值都只读；
- 所有更改请求按统一 middleware 拦截，且绝不拥有 CA 私钥、Runtime socket、NET_ADMIN 或 Docker socket；
- 保存 `/data/manager/state.db`、安全会话、系统设置的展示缓存；内部登录会话、日志、审计等“控制面运行记录”允许在只读模式继续写数据库，但不得变更 VPN 受管状态。

**control-agent：**
- 独立读取同名环境变量，执行二次安全门禁；只接受认证 Manager 的固定操作；
- 唯一持有受保护 CA 私钥的常驻组件；生成配置、签发/吊销证书、CRL、打包客户端配置；
- 串行化有副作用的任务，基于临时文件 + fsync + 原子 rename 生成持久化配置；
- 经受限 Runtime Supervisor Socket 执行 `start/stop/reload/status/kick`；不接受任意命令字符串或任意文件路径；
- Manager 不可直接挂载 Agent 的 PKI 数据卷或 Runtime 控制 Socket。

**openvpn-runtime：**
- 独立生存，即使 manager 和 control-agent 被重建仍保持运行/连接；
- 受限 Supervisor 作为 PID 1：无配置时保持就绪并报告 `UNINITIALIZED`；有有效配置则启动 OpenVPN 子进程、监视退出并执行受控重启；
- 只能读取 `/etc/openvpn` 运行所需数据；不读取数据库、CA 私钥；
- OpenVPN `management /run/openvpn/management.sock unix <password-file>`，Socket 严格限制用户/组，不映射任何公网端口；
- 如果运行环境缺少 TUN、netfilter 能力或配置无效，报告明确诊断，不循环破坏文件。

### 2.2 Socket 安全约束

- manager ↔ agent：只挂载必要的通信 Socket 卷，使用固定 UID/GID、目录 `0700`/`0750` 与 Socket `0600`/`0660`，使用请求鉴权（共享受限凭据或等效机制）、请求 ID、过期时间、重放检测；实际权限以容器内 UID/GID 为准，不能只假定 Unix Socket 自动可信。
- agent ↔ runtime：另一独立 Socket；manager 无权挂载此路径。Supervisor 使用允许列表命令，命令带最小参数，不提供 shell、文件读取 API。
- OpenVPN 原生 Management Interface 和 Supervisor Socket 不同；原生接口只供 runtime/Supervisor 使用；禁止暴露原生接口到 Web 或宿主端口。
- 在 Agent 实施 `kick/reload` 前，必须核验授权；用户不能借任何“只读查询”触发会断开连接的管理命令。

## 3. Docker 构建、部署与版本治理

### 3.1 建议仓库结构

```text
.
├── AGENTS.md
├── README.md
├── LICENSE
├── docs/
│   ├── DESIGN.md                         # 本文
│   ├── SECURITY.md                       # 后续威胁模型与操作手册
│   ├── API.md                            # OpenAPI 生成/维护
│   └── DEPLOY_SYNOLOGY.md                # DSM 实测后撰写
├── docker/
│   ├── Dockerfile.openvpn                # 官方源码的多阶段构建
│   ├── Dockerfile.manager                # Go + Vue 多阶段构建
│   ├── Dockerfile.agent
│   └── entrypoint-runtime.sh             # 如用 shell，保持固定流程
├── backend/
│   ├── cmd/manager/
│   ├── internal/api/
│   ├── internal/auth/
│   ├── internal/store/
│   ├── internal/policy/
│   └── internal/audit/
├── agent/
│   ├── cmd/control-agent/
│   ├── internal/pki/
│   ├── internal/config/
│   ├── internal/transactions/
│   └── internal/runtimeclient/
├── runtime/
│   ├── cmd/supervisor/
│   ├── internal/openvpn/
│   └── internal/network/
├── frontend/
│   ├── src/pages/
│   ├── src/components/
│   ├── src/api/
│   └── src/router/
├── config/templates/                      # 仅允许安全白名单生成
├── migrations/
├── compose.yaml
├── .env.example
├── .gitignore
└── tests/
    ├── security/
    ├── integration/
    └── e2e/
```

### 3.2 OpenVPN 构建规范

- `docker/Dockerfile.openvpn` 必须多阶段构建：构建阶段从 **官方发布地址** 下载 `openvpn-2.7.9.tar.gz` 与 `.asc`，验证发行签名与固定可信发布密钥指纹；不能只执行 `curl | sh`，不能以 HTTPS 下载成功代替签名校验。可信公钥指纹应从独立、可信的官方渠道人工核实，文档记录来源；签名失败则构建失败。
- 生产 Runtime 镜像只保留 OpenVPN 可执行文件、必要运行库、Supervisor 与诊断所需最小工具；构建器、编译器、GPG 工具不可带入生产镜像。
- 构建默认目标 `linux/amd64`；在 DS920+ 原生构建或 CI 上构建。固定基础镜像到合适的 digest，生成 SBOM，记录上游版本与构建时间。
- 默认使用 TUN、TCP、IPv4，先禁用 DCO（具体 Configure 选项以 2.7.9 `./configure --help` 实测确定），禁止压缩；运行时若 `/dev/net/tun` 不可用则给出检测/修复指导，不尝试安装未知内核模块。
- Easy-RSA 使用明确固定版本并验证来源；作为 Agent 管理 PKI 的工具，不应将其密钥材料复制到 Runtime 镜像层。
- 禁止把私钥、真实 IP、管理员密码、TOTP seed、.env 注入镜像 build context 或镜像 layer。

### 3.3 Compose 与环境变量契约

```dotenv
# 一旦缺失或非法，强制只读。仅严格 true 解锁。
OPENVPN_MANAGER_WRITE_ENABLED=false

# 宿主机管理入口默认只绑定 loopback；LAN 使用前需显式指定 NAS 的局域网 IP
MANAGER_BIND_IP=127.0.0.1
MANAGER_HTTPS_PORT=9443

# 仅 Docker/Compose 可控制的网络端口
OPENVPN_TCP_PORT=1194
OPENVPN_PUBLIC_HOST=vpn.example.com

# 家庭 LAN 与 VPN 地址段仍由首次初始化 Web 向导设置
```

- Compose 将 `OPENVPN_MANAGER_WRITE_ENABLED` 同时传入 `manager` 和 `control-agent`，而不是 Runtime。
- `manager` 的持久化卷不包含可写 OpenVPN 配置/CA；`control-agent` 只挂必要的写卷，`runtime` 仅以只读方式加载配置及已签发证书。
- `manager` 与 `control-agent` 均不得 `privileged: true` 或挂载 `/var/run/docker.sock`；`runtime` 仅添加 `NET_ADMIN`、映射 `/dev/net/tun`，不暴露 9443 公网入口。尽可能 `cap_drop: [ALL]` 后仅添加必需权限，并使用 `no-new-privileges`、只读根文件系统、临时 tmpfs。
- 必须先给用户明确提示：DSM 的 TUN 驱动、Docker/DSM 防火墙与家用路由器端口转发可能需要手动设置；这些不是 Web 平台可以静默修改的对象。
- 管理 HTTPS 使用用户提供的可信证书，或仅用于初始化的自签名证书。没有证书时不能降级明文 HTTP 向公网暴露。

### 3.4 切换只读/可写模式（强制验收）

在 `.env` 改为 `true` 后，**不是**运行 `docker compose restart`，而是运行：

```bash
docker compose up -d --no-deps --force-recreate manager control-agent
```

设置回 `false` 后再次执行上面的命令。`docker compose restart` 不会将 Compose 环境变量变更应用到已有容器。

- 重新创建 manager 与 agent 期间，Runtime 和当前 VPN 连接应保持运行；如果实现中的 `depends_on` 或共享卷导致重建 Runtime，则属于架构失败。
- 写权限是**容器启动时锁定的权限上限**，不从 DB、文件、HTTP Header、Cookie、请求参数修改；不提供 Web 开关 API。
- Manager 和 Agent **都**必须判定 `true` 才可变更；任一拒绝、状态不一致、Agent 失联、认证异常，返回 `WRITE_MODE_DISABLED` 或 `WRITE_MODE_MISMATCH`；不得自动补偿为开放。
- 容器因系统异常自动重启仍使用其既有环境变量：如果环境保留 `true`，重启后仍可写。Web 应持续展示橙色“当前可写，请维护后关闭”的警告，不虚构自动超时回落。
- 切模式时必须使写操作可中断/可恢复，正在进行的事务要么完整完成，要么根据事务日志回滚，不能留下半写配置。

## 4. 首次启动、状态机与初始化向导

### 4.1 状态机

```text
UNINITIALIZED
  -> (Docker write=false) READ_ONLY_UNINITIALIZED
  -> (Docker write=true + recreate 2 containers) BOOTSTRAP_ALLOWED
  -> ADMIN_CREATED
  -> PKI_INITIALIZED
  -> CONFIG_VALIDATED
  -> READY_STOPPED
  -> RUNNING
  -> MAINTENANCE / ERROR / DEGRADED
```

状态必须从持久数据和运行进程检测推导，不能仅凭前端 localStorage。异常时显示可操作诊断，禁止偷偷重新创建 CA 或清空存量用户。

### 4.2 首次初始化的安全规则

- `write=false` 时页面提示如何在 Docker 中开启写权限，但 **禁止**首次创建管理员、证书、生成服务配置等操作；无“首次安装豁免”。
- 首次管理员创建必须同时满足：`write=true`、未初始化、持有一次性 Bootstrap Token（首次由容器日志**仅显示一次**，生成时至少 256 bit CSPRNG）、在管理绑定入口访问、通过初始化节流与一次性消费校验。
- 管理员密码：Argon2id 自适应散列、密码强度/长度限制；MVP 强制配置 TOTP，并保存加密的 TOTP secret；提供一次性恢复码，绝不记录明文。
- Bootstrap Token 使用后立即撤销；重启不能重新暴露、重复初始化；管理员遗失访问通过离线 CLI 恢复流程，不提供不验证身份的 Web 重置入口。

### 4.3 Web 初始化向导步骤

1. **环境检查**：NAS CPU 架构、OpenVPN/Agent 版本、TUN 存在/可用、容器 NET_ADMIN、可用磁盘、监听端口、NAT/转发支持、DSM 防火墙提醒；可标记“需要用户手动操作”的问题。
2. **管理员安全**：一次性令牌、管理员账号、密码、TOTP 和恢复码。
3. **网络配置**：域名或公网 IPv4、监听 TCP 端口显示（来自 Compose）、VPN CIDR（默认 `10.8.0.0/24`）、LAN CIDR（由用户确认）、DNS、分流策略；验证 VPN/LAN/Docker CIDR 不重叠。
4. **证书与加密**：初始化 CA、服务器证书、TLS 控制通道密钥 `tls-crypt`；CA 私钥用非空强口令加密，口令仅在签发/吊销时短时使用内存；证书最短/最长有效期校验。
5. **预览与应用**：显示配置 diff、计划路由/防火墙规则、容器网络约束，运行静态校验与可执行程序配置检查；请求管理员确认后原子应用。
6. **完成与连通性**：启动 OpenVPN、检查管理状态、显示外部路由器 `1194/tcp` 转发指引；提供新增设备入口和故障诊断。

**注意**：同一个 LAN CIDR 出现在异地客户端当前网络时，分流可能路由冲突，应给出明确警告和手动修正建议。

## 5. 核心功能设计

### 5.1 页面与导航

| 页面 | 只读可见内容 | 仅 Docker 写模式下可操作 |
|---|---|---|
| 初始化 | 环境诊断、需要打开写模式的说明 | 管理员创建/PKI/配置应用 |
| Dashboard | Runtime 状态、版本、在线数、流量、告警 | 重启/停止/启动（需二次确认） |
| 网络配置 | 域名、端口、LAN/VPN CIDR、DNS、分流、最终配置预览 | 修改/验证/应用/回滚 |
| 客户端 | 列表、在线状态、证书有效期、吊销状态 | 创建设备、续签、吊销、踢下线 |
| 连接监控 | 连接 IP、时间、收发字节、错误日志 | 踢客户端 |
| 安全与证书 | CA 指纹、证书概览、CRL 状态 | 签发、吊销、导出敏感密钥（默认禁止）、恢复 |
| 日志与审计 | 检索、过滤、导出脱敏日志 | 清理历史日志（如实现） |
| 备份恢复 | 查看备份版本、哈希、可恢复性 | 创建/下载含密钥备份、恢复、重置（强验证） |
| 系统信息 | 只读/可写标志、Docker 版本、健康度 | 无 Web 侧模式切换按钮 |

含私钥的 `.ovpn` 导出属于**敏感操作**，即使技术上是 HTTP 下载，也必须通过 write gate + 身份验证 + TOTP + 审计；不允许在只读模式通过 GET 或缓存地址获取。

### 5.2 OpenVPN 服务配置基线

候选生成内容（MVP；具体选项以 **2.7.9 语法**做集成验证）：

```conf
port 1194
proto tcp-server
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/server.crt
key /etc/openvpn/pki/server.key
crl-verify /etc/openvpn/pki/crl.pem
tls-crypt /etc/openvpn/pki/tls-crypt.key
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
verify-client-cert require
persist-key
persist-tun
keepalive 10 120
status /run/openvpn/status.log 10
verb 3
management /run/openvpn/management.sock unix /run/secrets/management-password
management-client-user openvpnctl
management-client-group openvpnctl
```

- 不启用 OpenVPN 压缩（如 `compress`/`comp-lzo`），不使用过时的静态共享主密钥认证模式，不开放 management TCP 端口。
- 客户端认证默认每设备独立证书，必须有私钥、证书、CA、`tls-crypt`、`remote 域名 端口`、`proto tcp-client`、`remote-cert-tls server`。客户端名称只能受限字符集（例如 `[A-Za-z0-9_-]{1,64}`），不得作为未转义 shell 参数执行。
- 推荐使用 EC 或 RSA 密钥参数由统一 PKI 策略决定，不允许按客户端参数注入任意证书扩展。
- `status.log` 与管理 Socket 是 Runtime 临时文件，不应把 Socket 暴露到 Web。
- 影响监听端口/协议/Docker port mapping 的变化，Web 只能提示 Compose 修改，不得声称页面保存即已变更宿主端口。

### 5.3 证书生命周期

- CA 创建：强密码加密 CA 私钥，CA metadata/指纹、serial/index/CRL 持久化，备份同时加密。
- 每个设备一张证书（CN 唯一，绑定客户端记录），签发、续期或替换、吊销有独立审计事件。
- 新增设备：签发客户端证书、生成包含私钥的 inline `.ovpn`，通过 **一次性、短时有效、认证后** 的下载返回；不在应用日志、审计或数据库明文记录私钥；临时文件用受限目录并尽快销毁。
- 吊销：Easy-RSA revoke → gen-crl → 验证 CRL 含目标 serial → 原子发布 CRL → 使 Runtime 确认读入 CRL；已连接会话主动 kick，重新连接应被拒绝。失败不能将 DB 标记为“吊销已生效”。
- 禁止重新生成 CA 来解决签发/吊销错误。重置 CA 是单独的毁灭性操作，MVP 不在 Web 开放。
- CA 解锁密钥不进入 DB、日志、panic、环境变量、命令行参数；避免口令出现在进程列表，采用安全 stdin/fd 或安全子进程通道，尽量清理内存驻留。

### 5.4 配置更改事务

1. Web 提交严格结构化的 DTO（拒绝额外字段、CRLF、路径穿越、异常 CIDR/端口）。
2. Manager 鉴权 + 写模式校验 + CSRF 防御 + 细粒度权限 + 幂等键。
3. Agent 再验证写模式、请求身份、操作范围；获取独占配置锁。
4. 以版本号生成候选配置；做模板/语法/资源校验；展示 diff，禁止露出私钥。
5. 审批确认后备份上一版本，生成临时文件、权限校验、fsync、原子替换。
6. Runtime Supervisor 根据变更类型执行可控 reload/restart；健康探针确认生效，保存 `effective_generation`。
7. 失败：尝试回滚并恢复服务，记录 `FAILED`/`ROLLED_BACK`，不能回滚时进入 `DEGRADED` 并给出恢复步骤。
8. 所有任务写入不可篡改式审计记录（MVP 可采用 append-only 语义 + 哈希链，说明单机管理员仍有能力篡改本地介质，不宣称绝对不可篡改）。

### 5.5 网络与 NAS 边界

- MVP 仅 IPv4/TCP/TUN，默认 split tunnel：只有家庭 LAN CIDR 通过 VPN；将来全局 IPv4 流量模式需额外验收 NAT/DNS/泄漏处理后再开放。
- Docker bridge 下 Runtime 负责其网络命名空间中的转发/NAT 规则，并验证宿主 Docker 转发和 DSM 防火墙；不要未经检查直接改宿主全局 iptables。
- 应生成明确、可撤销、带项目标识的有限规则；启动幂等、退出恢复；不能用 `iptables -F` 清空现有规则；nftables/iptables 兼容性检测不通过时禁止自动应用。
- 由用户管理家庭路由器的 TCP 1194 转发到 NAS；若公网侧 CGNAT 或 DNS 不可达，向导明确指出限制而不是声称配置已成功。
- TCP-over-TCP 存在性能缺点，文档应提示；但此项目 MVP 按明确需求使用 TCP。
- IPv6、局域网到 NAS 的访问控制、容器发起的出站流量需要纳入测试和防火墙设计，不能假设 Docker 发布端口必受 DSM 防火墙完全约束。

## 6. 写入保护安全模型（不可回退的最高优先级）

### 6.1 保护范围

受管写操作包括任何可能改变以下状态的行为：VPN 配置、路由/DNS/防火墙策略、VPN 运行状态（start/stop/reload/kick）、CA/证书/CRL、客户端记录、管理员策略、授权角色、备份创建/恢复/密钥导出。**首次初始化也在此范围内。**

唯一允许在只读模式写磁盘的内部运行行为是：登录会话计数/安全审计、只读状态缓存、短期诊断缓存、Runtime 运行日志和必须的健康状态。不得借“缓存/诊断”改变受管配置或证书。

### 6.2 三重授权判定

```text
HTTP mutation / sensitive export
  -> authenticated session
  -> role permission
  -> manager startup write flag == true
  -> CSRF / TOTP for sensitive action
  -> authenticated agent RPC
  -> agent startup write flag == true
  -> whitelist + validation + transaction lock
  -> runtime supervisor (only limited operations)
```

- 一切写 API、WebSocket 写消息、CLI 控制命令和“下载私钥”等效敏感读都受统一门禁；不能只按 POST/PUT/DELETE 判定，必须按操作语义分类。
- 状态不匹配或服务异常 **fail closed**。返回 HTTP `423 Locked`（只读）、`409 Conflict`（状态冲突）、`403 Forbidden`（无权限）、`503`（Agent 不可用），均带稳定错误码。
- Web 不显示“修改权限开关”。仅显示 `只读（Docker 控制）` / `可写（Docker 控制）`，并给出 Compose 操作指引。
- 可写模式仍强制登录，涉及私钥/PKI/停机/备份恢复的操作需要 TOTP 二次确认和明确影响预览。
- 单次可写请求在 Agent 处理前再次检查；用户在 Docker 切回只读时，后续写入必须停止，已开始的事务应在重启恢复时核对最终状态。

### 6.3 必测的绕过路径

- 直接 curl 写 API（绕过 UI）；
- 伪造 HTTP Header `X-Write-Enabled: true`、JSON 字段 `writeEnabled`、Cookie 和 WebSocket；
- 只重建 manager 而 agent 保持只读，或反过来；
- 变量缺失、`TRUE`、`1`、`yes`、空字符串和无效值；
- 登录前调用初始化、删除 CA、导出客户端私钥；
- 缓存的下载 URL 在切回只读后尝试使用；
- 通过 GET 请求触发状态修改；
- 多个并发签发/吊销/应用配置请求；
- Agent 失联、SQLite 写失败、端口变更导致服务启动失败。

## 7. 后端 API 契约（v1）

API 必须编写 OpenAPI 3.1 描述，前端生成类型/客户端；响应统一：

```json
{
  "code": "OK",
  "message": "success",
  "data": {},
  "requestId": "req-..."
}
```

失败示例：`{"code":"WRITE_MODE_DISABLED","message":"Docker write mode is disabled","requestId":"req-..."}`。所有时间使用 RFC3339 UTC；分页使用 `limit/cursor`，禁止泄漏堆栈到用户。

| 方法 | 路径 | 能力 | 是否需要 Docker 写模式 |
|---|---|---|---|
| GET | `/api/v1/meta` | 版本、Manager/Agent/Runtime 可用性、只读模式 | 否 |
| GET | `/api/v1/health` | 非敏感健康状态 | 否 |
| POST | `/api/v1/auth/login` | 登录，不授予写权限 | 否 |
| POST | `/api/v1/auth/logout` | 结束本人会话 | 否（会话操作例外） |
| GET | `/api/v1/setup/state` | 初始化阶段、检查项 | 否 |
| POST | `/api/v1/setup/admin` | 创建初始管理员/配置 TOTP | 是，另需 Bootstrap Token |
| POST | `/api/v1/setup/pki` | 初始化 CA/服务器证书 | 是 |
| POST | `/api/v1/setup/complete` | 应用首轮配置 | 是 |
| GET | `/api/v1/system/checks` | TUN、网卡、端口、运行依赖检查 | 否；不得改变环境 |
| GET | `/api/v1/vpn/status` | 状态和连接数 | 否 |
| GET | `/api/v1/vpn/config` | 脱敏后的期望/生效配置 | 否 |
| POST | `/api/v1/vpn/config/validate` | 纯预览/静态校验 | 否，必须无副作用 |
| POST | `/api/v1/vpn/config/apply` | 事务化应用配置 | 是 |
| POST | `/api/v1/vpn/start` | 启动 | 是 |
| POST | `/api/v1/vpn/stop` | 停止 | 是 + TOTP |
| POST | `/api/v1/vpn/reload` | 重载 | 是 |
| GET | `/api/v1/clients` | 客户端列表 | 否 |
| POST | `/api/v1/clients` | 创建设备证书 | 是 |
| POST | `/api/v1/clients/{id}/revoke` | 吊销 + CRL 生效 | 是 + TOTP |
| POST | `/api/v1/clients/{id}/export` | 一次性敏感 .ovpn 下载 | 是 + TOTP |
| POST | `/api/v1/connections/{id}/disconnect` | 踢下线 | 是 |
| GET | `/api/v1/connections` | 在线信息 | 否 |
| GET | `/api/v1/events` | 受身份约束的事件订阅 | 否 |
| GET | `/api/v1/audit` | 脱敏审计查询 | 否，Admin |
| GET | `/api/v1/backups` | 备份元数据 | 否 |
| POST | `/api/v1/backups` | 创建加密备份 | 是 + TOTP |
| POST | `/api/v1/backups/{id}/restore` | 恢复（后续阶段） | 是 + TOTP + 双确认 |

建议错误码：`AUTH_REQUIRED`、`FORBIDDEN`、`WRITE_MODE_DISABLED`、`WRITE_MODE_MISMATCH`、`AGENT_UNAVAILABLE`、`TOTP_REQUIRED`、`UNINITIALIZED`、`INVALID_CIDR`、`PORT_REDEPLOY_REQUIRED`、`CERT_ALREADY_REVOKED`、`TRANSACTION_CONFLICT`、`RUNTIME_UNHEALTHY`。

安全约束：会话使用 Secure/HttpOnly/SameSite Cookie；针对写操作加 CSRF Token 和 Origin 校验；严控 CORS；限流和登录失败锁定；浏览器不持久化 CA 私钥、管理员口令、TOTP seed；SSE/WebSocket 做会话验证和来源限制。API 权限不允许由 UI 状态代替。

## 8. 数据存储模型（SQLite）

实现可分迁移文件（`migrations/`），默认启用 WAL（需验证 NAS 文件系统），设置 `busy_timeout`、外键并验证备份一致性。

### 8.1 主要表

| 表 | 关键字段 | 说明 |
|---|---|---|
| `admins` | id, username(unique), password_hash, totp_secret_encrypted, created_at, disabled_at | 密码 Argon2id，不存明文 |
| `sessions` | id_hash, admin_id, expires_at, revoked_at, created_ip | 只保存 Session Hash |
| `system_state` | key, value, generation, updated_at | 状态/模式展示，**不得作为写模式授权源** |
| `vpn_config_versions` | id, generation, config_hash, author_id, state, created_at, applied_at | 配置版本和回滚 |
| `clients` | id, name, cert_serial(unique), cert_cn(unique), status, issued_at, expires_at, revoked_at | 用户设备与证书一对一 |
| `cert_events` | id, client_id, serial, event, status, created_at | 证书签发/吊销任务历史 |
| `jobs` | id, type, requested_by, idempotency_key, status, error_code, created_at, finished_at | 有副作用任务串行化 |
| `audit_logs` | id, request_id, actor_id, action, target_id, source_ip, outcome, old_hash, new_hash, created_at, chain_hash | 仅保存摘要/元数据，不保存密钥 |
| `backups` | id, version, manifest_hash, encrypted, created_at, last_verified_at | 文件另存安全卷 |

SQLite 只负责 metadata；CA 私钥、证书、OpenVPN 配置和一次性下载内容按受保护文件树保存。文件和 DB 的跨介质一致性由事务协调器和 `jobs` 恢复逻辑处理。

### 8.2 持久化文件布局

```text
/data/
  manager/
    state.db
    tls/
  agent/
    pki/               # CA 私钥只有 Agent 可读，强制权限
      private/
      issued/
      crl/
    transactions/
    backups/
  runtime/
    versions/
      000001/
      000002/
    active/            # config + server cert/key + CRL，Runtime RO
  audit/
```

容器 UID/GID 和 DSM bind mount 权限必须在安装文档解释；不要使用宽泛 `chmod -R 777`。`.gitignore` 禁止提交 `data/`、`*.key`、`*.ovpn`、`*.db`、`.env`、包含密钥的备份。

## 9. Web UI / 交互约定

**前端：** Vue 3 + TypeScript + Vite + Naive UI（可替换组件库但保持类型约束），路由至少 `/setup`、`/dashboard`、`/network`、`/clients`、`/connections`、`/security`、`/logs`、`/backups`、`/system`。

- 页面顶栏常驻显示服务状态和“Docker 控制的只读/可写”标签；可写状态需警告色且提示“维护后请修改 .env 并重建容器”。
- 只读模式所有写按钮显式禁用并说明原因；**后端禁止**才是安全边界，不能以隐藏按钮代替。
- 配置页必须同时显示“期望配置/实际生效配置”，展示差异与需要重新部署的参数。
- 所有敏感字段默认遮挡，日志下载需脱敏；生成客户端 profile 不应在 UI 自动长期缓存。
- 操作中 UI 显示 jobId、阶段、最终结果，失败提供恢复建议，不能先显示“成功”再异步才发现失败。
- 页面应适配桌面和手机；初版全部中文，后端错误码不依赖中文文本判断逻辑。

## 10. Runtime 管理、可观测性与故障恢复

- 以官方 OpenVPN 2.7 Management Interface 的 `status`、`state`、`bytecount`、`kill`、`signal` 等能力读取状态和执行受控动作；对协议返回做严格解析，避免把输出当命令。
- Runtime Supervisor 需要健康检查、子进程托管、启动配置验证、退出信号处理、启动时无配置可等待；启动后 Manager/Agent 失联不影响现有 VPN 流量。
- 采集指标：连接数、每客户端连接时长、收发字节、TLS 失败统计、最近配置版本、CRL 版本、证书过期告警；**不保存 VPN 用户的访问网站与流量内容**。
- Agent/Manager/Runtime 日志使用结构化 JSON（UTC、trace ID、actor ID、operation ID、result）；按大小轮转；敏感信息（密钥、一次性 token、私钥、TOTP）不能写入日志。
- Agent 崩溃重启：从事务日志恢复或回滚，重复请求幂等；Runtime 可独立保留连线。
- 首次验收要求覆盖容器独立重启、DS920+ 关机重启、TUN 不可用、CA 锁定、证书过期、CRL 应用失败、DNS 不通、家庭路由器无端口转发等情况。

## 11. 备份、恢复与升级

- 备份必须包含：SQLite 一致性快照、受保护 CA/PKI（加密）、server config 历史、CRL、manifest 和校验哈希；用强加密加密码，严禁无加密导出包含 CA 私钥的归档。
- 恢复前验证格式、schema 版本、散列与可解密性；恢复前自动创建恢复点，操作受写模式 + TOTP + 二次确认约束。
- 镜像更新不能改变受管数据目录；DB schema 升级要提供 migration + 回滚策略；升级前备份，失败保持已有 Runtime 服务或明确停止策略。
- OpenVPN 版本升级不是 Web 写操作：由有权运行 Docker 的管理员调整官方源码版本、核验签名、构建、重新部署 Runtime；变更可能导致连接中断，需提示维护窗口。
- 项目自身许可证 Apache-2.0 不代表 OpenVPN/Easy-RSA 等上游组件改为 Apache；打包分发时遵循各自上游许可证、保留 NOTICE/来源和 SBOM。

## 12. 安全威胁模型与边界

| 风险 | 防御与验收 |
|---|---|
| Web 账号被盗 | 默认只读；密码 + TOTP、限流、审计；即使登录不得绕过 Docker 写门禁 |
| Web RCE | 无 Docker socket、无 NET_ADMIN、无 CA/Runtime 写卷；Agent 独立校验 |
| Agent 失陷 | 最小权限、白名单 RPC、独立环境变量、无通用 shell/exec API；CA 加密私钥 |
| Socket 暴露 | Unix socket 目录权限、UID/GID、认证；不得对外 publish |
| API CSRF / SSRF / 注入 | CSRF+Origin，结构化 DTO、严格 allowlist，禁任意 URL 下载与外部命令参数 |
| 证书泄漏 | 单设备证书、一次性导出、访问日志脱敏、吊销+CRL+踢线 |
| 文件访问/路径穿越 | 固定根目录、openat/安全路径封装，禁止用户控制文件系统绝对路径 |
| 重放并发 | 幂等键、Agent request nonce/expiration、任务串行锁、明确事务状态 |
| 权限开关误判 | 严格 `true` 解析；manager/agent 双判定；故障关闭 |
| 容器网络权限过大 | Runtime 最小能力、TUN、网络规则限制；不采用 `privileged` 默认值 |
| 公开管理面 | 默认绑定 loopback；改 LAN IP 需明确 DSM 防火墙和可信 HTTPS；永不默认公网暴露 |
| 供应链风险 | 官方源码签名校验、固定依赖、镜像 digest/SBOM/CI 扫描、禁止 secrets 入镜像 |

说明：Docker 环境变量门禁属于**防御纵深中的操作授权边界**，不等同于抵御已拥有 Docker 宿主 root 权限的攻击者。真正的 Docker 管理员始终能够绕过应用级授权，因此要保护 NAS 的 SSH、DSM 和 Docker 权限。

## 13. 测试计划与强制验收用例

### 13.1 自动化测试

- Go：单元测试（policy、crypto、CIDR、模板、PKI 状态机、事务/回滚、API auth/CSRF）；`go test ./...` + race test（适用模块）。
- 前端：Vitest 组件/Store 测试、类型检查、lint；Playwright 初始化/只读/写模式 E2E。
- 集成：在 Linux CI/专用测试环境运行测试容器、临时 TUN 和证书；必须测试握手与 LAN 路由；不在没有 NET_ADMIN 的常规 CI 中伪造“VPN 真正连通”结果。
- 安全：写入绕过测试、密钥扫描、依赖扫描、Go `govulncheck`（或等效工具）、容器镜像扫描、日志脱敏检查。
- DSM 实机：DS920+ 上测试 `/dev/net/tun`、Docker iptables、重启、持久卷权限；与普通 Linux CI 结果分开报告。

### 13.2 不可省略的验收清单

- [ ] Git clone 后文档明确、可复现地构建官方 OpenVPN 2.7.9；`openvpn --version` 与版本一致。
- [ ] 源码包签名校验失败时构建终止。
- [ ] 首次只读下不能创建管理员、CA、客户端或改变 Runtime。
- [ ] 仅 manager 设 true / 仅 agent 设 true 均被拒绝。
- [ ] `true` 才可写；`TRUE`、`1`、`yes`、未定义与异常均只读。
- [ ] 使用 `docker compose restart` 不能改变原有容器环境，文档指向 `up --no-deps --force-recreate`。
- [ ] 模式切换只重建 manager 和 control-agent，Runtime PID/现有 VPN 连接保持不变。
- [ ] 没有 server.conf 时 Runtime 不 crash-loop，Web 可报告 UNINITIALIZED。
- [ ] Agent 不可执行任意 Shell；Manager 不挂 Docker Socket、PKI 私钥卷和 NET_ADMIN。
- [ ] 管理 API、管理 Socket 不向公网开放，HTTPS 正常，TOTP 正常。
- [ ] VPN TCP 客户端证书握手成功，访问指定家庭 LAN 地址成功。
- [ ] 每设备单独 CN/serial；吊销后 CRL 生效、旧证书重新连接失败。
- [ ] 吊销/更新配置失败时返回错误、不误报成功，回滚到上一个可用版本。
- [ ] 客户端 .ovpn/CA 私钥不进入数据库明文、日志、Git 或镜像层。
- [ ] DSM/Router 手动步骤明确，不能自动完成时有准确的错误或提示。
- [ ] 操作日志有 actor/requestId/结果；密码和密钥在日志中不可见。
- [ ] 数据卷在容器重建与 NAS 重启后仍保存且可恢复。
- [ ] README 与实际启动命令、Compose 服务名和环境变量保持一致。

## 14. 可供 Codex 使用的开发工作约定

1. **优先提交小而完整的阶段性 PR**；PR 描述写清实现内容、威胁模型影响、测试命令与尚未完成的项。
2. 若发现设计存在不可行之处（例如 DSM 内核、iptables、跨容器 Unix Socket 权限限制），先提供最小可复现证明、替代方案和安全影响，更新 ADR，再修改实现；禁止通过扩大权限“快速解决”。
3. 所有对外 API 必须从 OpenAPI spec 生成或严格同步到文档；环境变量与默认值必须在 `.env.example` 和 README 保持同步。
4. 禁止在测试快照、CI artifacts、日志里包含真实密钥和真实 NAS 地址；测试采用临时密钥和 RFC 5737 文档网段。
5. 服务启动不得自动初始化或重置已有 PKI；“未配置”和“数据损坏”必须区分。
6. 每个阶段至少包含正常路径 + 明确失败路径 + 权限绕过测试。无实机条件时在交付说明中明确哪些 DSM 功能尚未验证。

## 15. 研发阶段 / 推荐 PR 拆分

### Phase 0 — 仓库脚手架与供应链（优先）

交付：三个 Dockerfile、Compose、`.env.example`、Go/Vue 脚手架、CI 基本检查、OpenVPN 官方 2.7.9 签名验证/版本输出、README。尚不需要 VPN 联网成功。

**验收：** `docker compose build` 三镜像成功；`openvpn --version` 符合 2.7.9；默认无 Docker Socket 和 privileged。

### Phase 1 — 独立 Runtime / Agent 通信

交付：Runtime Supervisor 无配置等待状态、最小管理 Socket、Agent 鉴权 RPC、运行状态 API、健康探针、跨容器 UID/GID 与卷权限测试。

**验收：** 未初始化可观测；单独重启 Manager/Agent 不重启 Runtime；不能通过 Socket 任意执行命令。

### Phase 2 — Docker 写门禁与管理员认证

交付：Manager+Agent 双门禁、strict true 解析、Web 状态 banner、密码 + TOTP + Bootstrap Token、只读操作、审计、权限绕过集成测试。

**验收：** 第 13 节全部写门禁绕过用例通过。首次初始化只能在 Docker 写模式启动后执行。

### Phase 3 — 初始化向导和 OpenVPN 实际连通（MVP）

交付：网络参数校验、Easy-RSA CA/服务器证书、OpenVPN 配置生成与事务应用、TUN/NAT 检查、TCP 1194、分流模式、运行状况、真实客户端连接测试。

**验收：** 首次部署无需手工编辑 server.conf/证书即可连通家庭 LAN；不能自动配置的路由器步骤准确展示。

### Phase 4 — 客户端生命周期 / 监控

交付：创建设备、.ovpn 敏感导出、证书吊销+CRL、kick、连接流量/日志、失败回滚。

**验收：** 吊销后旧配置无法重新连接，当前会话可被主动断开；回退只读后敏感导出被拒绝。

### Phase 5 — 备份恢复、DSM 验收与发布

交付：加密备份/恢复、完整 DSM DS920+ 测试、镜像 SBOM/安全扫描、安装与升级手册、发布 Tag；不将未实测项写成已经支持。

**验收：** 断电/重建不丢密钥/配置；备份恢复演练通过；README 可以独立指导首次安装和安全维护。

## 16. 供 Codex 开始执行的指令

将以下内容作为 Codex 的第一条任务（也可以直接让 Codex 阅读 `AGENTS.md` 和本文件）：

> 请阅读仓库根目录 AGENTS.md 和 docs/DESIGN.md，遵守全部安全不可变约束。先只实现 Phase 0：官方 OpenVPN Community Edition 2.7.9 签名验证源码构建、manager/agent Docker 镜像脚手架、三容器 Compose、.env.example、Go/Vue 工程与 CI。默认 OPENVPN_MANAGER_WRITE_ENABLED=false，且 manager 和 control-agent 必须双重校验。不要开启 privileged，不挂载 docker.sock，不实现任意 shell API，不修改 Runtime 的独立生命周期。请提交可运行代码、自动化测试、README，列出已通过与未实测项。不要提前开发下一阶段。

## 17. 官方参考资料

- OpenVPN CE 2.7.9 官方发布记录： https://community.openvpn.net/ReleaseHistory/source
- OpenVPN 2.7 官方手册（含 TCP、TUN、Management Socket）： https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual/
- OpenVPN Management Interface 协议说明： https://openvpn.net/community-docs/management-interface/
- 官方源码包： https://swupdate.openvpn.org/community/releases/openvpn-2.7.9.tar.gz
- 官方源码签名： https://swupdate.openvpn.org/community/releases/openvpn-2.7.9.tar.gz.asc
- Easy-RSA 官方文档： https://github.com/OpenVPN/easy-rsa/tree/master/doc
- Docker Compose restart 环境变量限制： https://docs.docker.com/reference/cli/docker/compose/restart/
- Docker Compose up： https://docs.docker.com/reference/cli/docker/compose/up/

---

**执行基线：** 先守住 Docker 控制的默认只读和 Runtime 不间断两大约束，再开发功能。任何破坏这两个性质的变更，即使“更容易安装”，也视为不符合本设计。
