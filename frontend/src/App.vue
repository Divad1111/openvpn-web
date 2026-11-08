<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

type Meta = {
  phase: string
  openvpnVersion: string
  managerWriteEnabled: boolean
  agentAvailable: boolean
  agentWriteEnabled: boolean
  effectiveWriteAllowed: boolean
  runtimeState: string
  setupAvailable: boolean
}
const meta = ref<Meta | null>(null)
const error = ref('')
let timer: ReturnType<typeof setInterval> | undefined

async function refresh() {
  try {
    const response = await fetch('/api/v1/meta', { cache: 'no-store' })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    meta.value = await response.json() as Meta
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'API 不可用'
    meta.value = null
  }
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh() }, 10000) })
onUnmounted(() => { if (timer !== undefined) clearInterval(timer) })
</script>

<template>
  <main class="shell">
    <header class="header">
      <div>
        <p class="eyebrow">OPENVPN COMMUNITY EDITION</p>
        <h1>OpenVPN CE Manager</h1>
        <p class="subtitle">群晖 DS920+ · Docker · TCP / IPv4</p>
      </div>
      <span class="version">v{{ meta?.openvpnVersion ?? '2.7.9' }}</span>
    </header>
    <div class="warning" role="alert">
      <strong>开发阶段 · Phase 0</strong>
      <p>当前仅实现容器、管理接口和界面骨架。尚不能创建证书、配置 VPN 或提供实际 VPN 连接。请勿用于生产环境。</p>
    </div>
    <section class="layout">
      <article class="card">
        <div class="section-title"><h2>Docker 写入保护</h2><span :class="['pill', meta?.effectiveWriteAllowed ? 'unlocked' : 'locked']">{{ meta?.effectiveWriteAllowed ? 'Docker 允许写入' : '只读保护中' }}</span></div>
        <p>修改权限只来自 Docker 环境变量。网页不提供修改开关，所有修改接口在 Phase 0 均不可用。</p>
        <dl>
          <div><dt>Manager 环境</dt><dd>{{ meta?.managerWriteEnabled ? 'true' : 'false' }}</dd></div>
          <div><dt>Control Agent</dt><dd>{{ !meta?.agentAvailable ? '未连接' : meta.agentWriteEnabled ? 'true' : 'false' }}</dd></div>
          <div><dt>有效写入权限</dt><dd>{{ meta?.effectiveWriteAllowed ? '允许（尚未实现写操作）' : '禁止' }}</dd></div>
        </dl>
        <p class="tip">维护时通过 Docker 修改 <code>OPENVPN_MANAGER_WRITE_ENABLED</code>，重新创建 manager 和 control-agent 容器；OpenVPN Runtime 保持运行。</p>
      </article>
      <article class="card">
        <div class="section-title"><h2>服务状态</h2><span class="pill neutral">{{ meta?.runtimeState ?? '检测中' }}</span></div>
        <p>运行容器已设计为与管理容器独立；当前 Supervisor 仅报告初始化状态。</p>
        <dl>
          <div><dt>管理 API</dt><dd>{{ error ? '不可用' : meta ? '在线' : '检测中' }}</dd></div>
          <div><dt>Agent</dt><dd>{{ meta?.agentAvailable ? '在线' : '未连接' }}</dd></div>
          <div><dt>VPN 服务</dt><dd>未部署</dd></div>
          <div><dt>初始化向导</dt><dd>Phase 3 开发</dd></div>
        </dl>
        <p v-if="error" class="error">连接错误：{{ error }}</p>
        <button type="button" class="refresh" @click="refresh">刷新状态</button>
      </article>
    </section>
    <footer>完整开发规范请参阅仓库 docs/DESIGN.md。启动成功不代表 VPN 已经可以连接。</footer>
  </main>
</template>
