<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'

type Meta = {
  openvpnVersion: string
  phase: string
  initialized: boolean
  managerWriteEnabled: boolean
  agentWriteEnabled: boolean
  agentAvailable: boolean
  effectiveWriteAllowed: boolean
  runtimeAvailable: boolean
  runtimeState: string
  setupAvailable: boolean
}
type Client = { id: string; name: string; serial: string; expires_at: string; status: string; exported: string }
type Config = { publicHost: string; vpnCIDR: string; lanCIDR: string; dns: string }
const meta = ref<Meta | null>(null)
const username = ref('')
const csrf = ref('')
const error = ref('')
const info = ref('')
const loading = ref(false)
const bootstrap = reactive({ token: '', username: 'admin', password: '', challenge: '', totpURI: '', otp: '' })
const login = reactive({ username: 'admin', password: '', otp: '' })
const network = reactive<Config>({ publicHost: 'vpn.example.com', vpnCIDR: '10.8.0.0/24', lanCIDR: '192.168.1.0/24', dns: '192.168.1.1' })
const serverConfig = ref('')
const caPassphrase = ref('')
const totp = ref('')
const newClient = reactive({ name: '', days: 365 })
const clients = ref<Client[]>([])
const connections = ref<Record<string, string>[]>([])
const audit = ref<Record<string, string>[]>([])
const pkiReady = ref(false)
const tab = ref('dashboard')
const needsSetup = computed(() => meta.value?.initialized === false)
const writable = computed(() => !!meta.value?.effectiveWriteAllowed)
const state = computed(() => meta.value?.runtimeState ?? 'UNKNOWN')
let timer: ReturnType<typeof setInterval> | undefined

async function request<T>(url: string, body?: unknown): Promise<T> {
  const options: RequestInit = { credentials: 'same-origin', cache: 'no-store', headers: {} }
  if (body !== undefined) {
    options.method = 'POST'; options.body = JSON.stringify(body)
    options.headers = { 'Content-Type': 'application/json', ...(csrf.value ? { 'X-CSRF-Token': csrf.value } : {}) }
  }
  const response = await fetch(url, options)
  const data = await response.json().catch(() => ({})) as Record<string, unknown>
  if (!response.ok) throw new Error(String(data.message || data.code || `HTTP ${response.status}`))
  return data as T
}
async function run(job: () => Promise<void>) {
  loading.value = true; error.value = ''; info.value = ''
  try { await job() } catch (e) { error.value = e instanceof Error ? e.message : '操作失败' } finally { loading.value = false }
}
async function refresh() {
  try {
    meta.value = await request<Meta>('/api/v1/meta')
    if (username.value) {
      const result = await request<{ runtimeState: string; pkiReady: boolean }>('/api/v1/vpn/status')
      pkiReady.value = !!result.pkiReady
      if (tab.value === 'clients') await getClients()
    }
  } catch (e) { error.value = e instanceof Error ? e.message : '服务不可用' }
}
async function bootstrapStart() {
  await run(async () => {
    const out = await request<{ challenge: string; totpURI: string }>('/api/v1/setup/start', { token: bootstrap.token, username: bootstrap.username, password: bootstrap.password })
    bootstrap.challenge = out.challenge; bootstrap.totpURI = out.totpURI
    bootstrap.token = ''; bootstrap.password = ''
    info.value = '请将 TOTP Secret 添加到身份验证器，并输入当前 6 位验证码确认。'
  })
}
async function bootstrapFinish() {
  await run(async () => {
    await request('/api/v1/setup/finish', { challenge: bootstrap.challenge, otp: bootstrap.otp })
    bootstrap.challenge = ''; bootstrap.totpURI = ''; bootstrap.otp = ''
    await refresh(); info.value = '管理员已创建。请使用密码和 TOTP 登录。'
  })
}
async function signIn() {
  await run(async () => {
    const out = await request<{ username: string; csrfToken: string }>('/api/v1/auth/login', { username: login.username, password: login.password, otp: login.otp })
    username.value = out.username; csrf.value = out.csrfToken
    login.password = ''; login.otp = ''
    await refresh()
  })
}
async function restoreSession() {
  try {
    const out = await request<{ username: string; csrfToken: string }>('/api/v1/auth/me')
    username.value = out.username; csrf.value = out.csrfToken
  } catch { username.value = ''; csrf.value = '' }
}
async function signOut() {
  await run(async () => { await request('/api/v1/auth/logout', {}); username.value = ''; csrf.value = ''; clients.value = [] })
}
async function preview() {
  await run(async () => {
    const out = await request<{ serverConfig: string }>('/api/v1/vpn/config/validate', { ...network })
    serverConfig.value = out.serverConfig; info.value = '静态校验通过；实际网络/证书检查在应用时进行。'
  })
}
async function initializePKI() {
  if (!confirm('即将创建 CA 和服务器证书。已存在的 CA 不会被覆盖。确认继续？')) return
  await run(async () => { await request('/api/v1/setup/pki', { passphrase: caPassphrase.value, totp: totp.value }); pkiReady.value = true; info.value = 'PKI 初始化成功，请妥善保管 CA 口令并创建加密备份。' })
}
async function applyConfig() {
  if (!confirm('应用新配置可能重启 VPN，导致客户端断开。是否继续？')) return
  await run(async () => { await request('/api/v1/vpn/config/apply', { ...network, totp: totp.value }); info.value = '配置已提交并收到 Runtime 响应。'; await refresh() })
}
async function runtimeAction(action: 'start' | 'stop' | 'reload') {
  if (!confirm(`确认执行 ${action}？连接可能中断。`)) return
  await run(async () => { await request(`/api/v1/vpn/${action}`, action === 'stop' ? { totp: totp.value } : {}); await refresh(); info.value = `${action} 命令已执行。` })
}
async function getClients() {
  const out = await request<{ clients: Client[] }>('/api/v1/clients'); clients.value = out.clients
}
async function getConnections() {
  await run(async () => { const out = await request<{ connections: Record<string, string>[] }>('/api/v1/connections'); connections.value = out.connections })
}
async function getAudit() {
  await run(async () => { const out = await request<{ entries: Record<string, string>[] }>('/api/v1/audit'); audit.value = out.entries })
}
async function addClient() {
  await run(async () => { await request('/api/v1/clients', { ...newClient, passphrase: caPassphrase.value, totp: totp.value }); newClient.name = ''; info.value = '证书已签发，请立即进行一次性配置导出。'; await getClients() })
}
async function exportClient(id: string) {
  await run(async () => {
    if (!confirm('客户端 .ovpn 含有私钥，只能导出一次。请确保设备安全。')) return
    const result = await request<{ ovpn: string }>('/api/v1/clients/' + encodeURIComponent(id) + '/export', { totp: totp.value })
    const filename = `openvpn-${id}.ovpn`
    const link = document.createElement('a')
    const file = new Blob([result.ovpn], { type: 'application/x-openvpn-profile' })
    const href = URL.createObjectURL(file)
    link.href = href; link.download = filename; document.body.appendChild(link); link.click(); link.remove()
    setTimeout(() => URL.revokeObjectURL(href), 30000)
    result.ovpn = ''
    info.value = `已请求下载 ${filename}，请将文件保存在安全位置。`; await getClients()
  })
}
async function revokeClient(id: string) {
  if (!confirm('吊销证书后该设备将无法再连接，无法撤销。确认继续？')) return
  await run(async () => { await request('/api/v1/clients/' + encodeURIComponent(id) + '/revoke', { passphrase: caPassphrase.value, totp: totp.value }); info.value = '证书吊销命令已执行。'; await getClients() })
}
function selectTab(value: string) {
  tab.value = value; error.value = ''; info.value = ''
  if (value === 'clients') void getClients().catch(e => { error.value = String(e) })
  if (value === 'connections') void getConnections()
  if (value === 'audit') void getAudit()
}
onMounted(async () => { await restoreSession(); await refresh(); timer = setInterval(() => { void refresh() }, 15000) })
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<template>
  <div class="shell">
    <header class="header">
      <div><p class="eyebrow">OPENVPN COMMUNITY EDITION</p><h1>OpenVPN CE Manager</h1><p class="subtitle">DS920+ · Docker Compose · TCP/IPv4 · {{ meta?.openvpnVersion || '2.7.9' }}</p></div>
      <span :class="['pill', writable ? 'unlocked' : 'locked']">{{ writable ? 'Docker 可写模式' : 'Docker 只读保护' }}</span>
    </header>
    <div v-if="writable" class="warning" role="alert"><strong>维护模式已开放</strong>：操作完成后请将 Docker 环境变量改回 false，并重新创建 manager 与 control-agent。</div>
    <div v-else class="tip" role="status">所有配置和证书修改均受到 Docker 环境变量保护；Web 不提供解除只读保护的开关。</div>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <p v-if="info" class="tip" role="status">{{ info }}</p>
    <section v-if="needsSetup" class="card">
      <h2>初次安装 · 创建管理员</h2>
      <p>首先在 NAS 的 .env 中设置 OPENVPN_MANAGER_WRITE_ENABLED=true，并重新创建 manager 与 control-agent；随后从首次启动日志取得一次性令牌。</p>
      <div v-if="!bootstrap.challenge" class="form-grid">
        <label>初始化令牌 <input v-model.trim="bootstrap.token" type="password" autocomplete="off" /></label>
        <label>管理员用户名 <input v-model.trim="bootstrap.username" autocomplete="username" /></label>
        <label>强密码（至少 12 字符） <input v-model="bootstrap.password" type="password" autocomplete="new-password" /></label>
        <button :disabled="loading || !writable" @click="bootstrapStart">下一步：配置 TOTP</button>
      </div>
      <div v-else class="form-grid">
        <p>将下面的 <strong>otpauth 地址</strong>加入你的身份验证器（包含敏感信息，请勿分享）：</p>
        <textarea :value="bootstrap.totpURI" readonly rows="4" aria-label="TOTP URI"></textarea>
        <label>当前 TOTP 验证码 <input v-model.trim="bootstrap.otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" /></label>
        <button :disabled="loading || !writable" @click="bootstrapFinish">验证并完成管理员初始化</button>
      </div>
    </section>
    <section v-else-if="!username" class="card login">
      <h2>管理员登录</h2>
      <div class="form-grid">
        <label>用户名 <input v-model.trim="login.username" autocomplete="username" /></label>
        <label>密码 <input v-model="login.password" type="password" autocomplete="current-password" /></label>
        <label>TOTP 验证码 <input v-model.trim="login.otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" /></label>
        <button :disabled="loading" @click="signIn">登录</button>
      </div>
    </section>
    <template v-else>
      <nav class="tabs" aria-label="管理功能">
        <button v-for="item in [['dashboard','概览'],['config','VPN 配置'],['clients','客户端'],['connections','连接监控'],['audit','审计日志'],['backup','备份']]" :key="item[0]" :class="['tab',tab===item[0] ? 'active' : '']" @click="selectTab(item[0])">{{ item[1] }}</button>
        <button class="tab" @click="signOut">退出 · {{ username }}</button>
      </nav>
      <section v-if="tab==='dashboard'" class="layout">
        <article class="card"><h2>运行状态</h2><dl>
          <div><dt>OpenVPN Runtime</dt><dd>{{ state }}</dd></div>
          <div><dt>Control Agent</dt><dd>{{ meta?.agentAvailable ? '可用' : '不可用' }}</dd></div>
          <div><dt>写入权限</dt><dd>{{ writable ? 'Manager 和 Agent 均允许' : '禁止' }}</dd></div>
          <div><dt>PKI</dt><dd>{{ pkiReady ? '已初始化' : '尚未初始化' }}</dd></div>
        </dl><p class="tip">管理权限的切换不应重启 Runtime，但 VPN 进程主动重启会断开客户端。</p></article>
        <article class="card"><h2>服务管理</h2><p>所有操作需要 Docker 可写模式；停止服务属于敏感操作，还需 TOTP。</p>
          <label>TOTP 二次确认 <input v-model.trim="totp" inputmode="numeric" maxlength="6" autocomplete="off" /></label>
          <div class="actions"><button :disabled="!writable||loading" @click="runtimeAction('start')">启动 VPN</button><button :disabled="!writable||loading" @click="runtimeAction('reload')">重启 VPN</button><button :disabled="!writable||loading" class="danger" @click="runtimeAction('stop')">停止 VPN</button></div>
        </article>
      </section>
      <section v-if="tab==='config'" class="layout">
        <article class="card"><h2>网络配置</h2><p>Web 不会修改 Docker 对外映射端口；默认 TCP 1194。</p>
          <div class="form-grid"><label>公网域名/IPv4 <input v-model.trim="network.publicHost" /></label><label>VPN 网段 <input v-model.trim="network.vpnCIDR" /></label><label>家庭 LAN 网段 <input v-model.trim="network.lanCIDR" /></label><label>DNS IPv4 <input v-model.trim="network.dns" /></label><button :disabled="loading" @click="preview">预览配置（只读）</button></div>
          <pre v-if="serverConfig" class="code">{{ serverConfig }}</pre>
        </article>
        <article class="card"><h2>证书初始化与应用</h2><p>CA 密钥必须加密保存，口令不会保存在应用数据库中。</p>
          <div class="form-grid"><label>CA 口令（至少 16 字符） <input v-model="caPassphrase" type="password" autocomplete="off" /></label><label>管理员 TOTP <input v-model.trim="totp" maxlength="6" inputmode="numeric" /></label><button :disabled="!writable || loading || pkiReady" @click="initializePKI">创建 CA 和服务端证书</button><button :disabled="!writable || !pkiReady || loading" @click="applyConfig">确认并应用配置</button></div>
        </article>
      </section>
      <section v-if="tab==='clients'" class="card"><h2>客户端证书管理</h2><p>每个设备单独签发证书；配置文件包含私钥，仅允许一次导出。</p>
        <div class="form-grid"><label>客户端名称 <input v-model.trim="newClient.name" /></label><label>有效天数 <input v-model.number="newClient.days" type="number" min="30" max="825" /></label><label>CA 口令 <input v-model="caPassphrase" type="password" autocomplete="off" /></label><label>管理员 TOTP <input v-model.trim="totp" inputmode="numeric" maxlength="6" /></label><button :disabled="!writable||loading" @click="addClient">新增客户端</button></div>
        <div class="table-scroll"><table><thead><tr><th>设备</th><th>有效期</th><th>状态</th><th>配置</th><th>操作</th></tr></thead><tbody><tr v-for="c in clients" :key="c.id"><td>{{ c.name }}</td><td>{{ c.expires_at }}</td><td>{{ c.status }}</td><td>{{ c.exported === '1' ? '已导出' : '未导出' }}</td><td><button :disabled="!writable||c.exported==='1'||c.status!=='ACTIVE'||loading" @click="exportClient(c.id)">导出 .ovpn</button><button class="danger" :disabled="!writable||c.status!=='ACTIVE'||loading" @click="revokeClient(c.id)">吊销</button></td></tr></tbody></table></div>
      </section>
      <section v-if="tab==='connections'" class="card"><h2>在线连接</h2><p>由 OpenVPN Runtime 状态文件提供数据，不记录访问内容。</p><button @click="getConnections">刷新</button><pre class="code">{{ JSON.stringify(connections,null,2) }}</pre></section>
      <section v-if="tab==='audit'" class="card"><h2>管理审计</h2><button @click="getAudit">刷新</button><pre class="code">{{ JSON.stringify(audit,null,2) }}</pre></section>
      <section v-if="tab==='backup'" class="card"><h2>加密备份与恢复</h2><p>此功能涉及 CA 私钥、SQLite 一致性和 VPN 运行时回滚；在备份恢复验收通过前不得投入生产使用。</p><p class="tip">暂未在本阶段提供未经验证的备份下载或恢复按钮。</p></section>
    </template>
    <footer>管理界面不提供 Docker 写入开关。任何系统修改仍须受 Manager/Agent 双重授权。未通过 DS920+ 实机验收前不得用于生产。</footer>
  </div>
</template>
