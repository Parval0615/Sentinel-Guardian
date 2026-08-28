import {
  lazy, Suspense, useEffect, useMemo, useRef, useState,
  type FormEvent, type KeyboardEvent, type ReactNode,
} from 'react'
import {
  Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate, useParams, useSearchParams,
} from 'react-router-dom'
import {
  Activity, AlertTriangle, ArrowLeft, ArrowRight, Bot, CheckCircle2, ChevronDown, ChevronRight,
  Circle, ClipboardCheck, Clock3, Crosshair, FileArchive, FileCheck2, Filter, HelpCircle, Info,
  History, LayoutDashboard, ListChecks, LockKeyhole, LogOut, Plus, RefreshCw, RotateCcw,
  Search, Settings2, ShieldCheck, ShieldPlus, Trash2, Upload, Wrench, X, XCircle,
} from 'lucide-react'
import { api, ApiError, loadAuditDetail, onUnauthorized, tokenStore } from './api'

import type {
  Agent, AuditDetail as AuditDetailData, AuditPreflightStatus, AuditRun, AuditScenarioTrace, AuditTraceEvent,
  AuditStatus, AuditTaskInput, AuditWorkspace, ImageAgentProfile, ImageProfileStatus,
  ModelRuntimeConfiguration, ModelRuntimeRole, ModelRuntimeStatus, ProfileClaim,
  ProfileRiskLevel, ProfileVerificationStatus, User,
} from './types'
import { isImageAgentProfile } from './types'
import { calculateProfileSha256 } from './profileIntegrity'
import { isPollingCancelled, pollWithTimeout } from './polling'

const AgentProfileGraph = lazy(() => import('./AgentProfileGraph').then((module) => ({
  default: module.AgentProfileGraph,
})))

const PROFILE_STAGE_LABELS = {
  inventory: '读取镜像清单',
  unpack: '安全解包',
  static_extract: '提取静态事实',
  framework_detect: '识别 Agent 框架',
  graph_reconstruct: '重建能力图谱',
  semantic_enrich: '语义增强',
  dynamic_verify: '可选运行探测',
  finalize: '发布静态画像',
} as const

const MODEL_RUNTIME_ROLES: ModelRuntimeRole[] = ['target', 'attack', 'defense']
const MODEL_RUNTIME_META: Record<ModelRuntimeRole, { title: string; note: string }> = {
  target: { title: '被测 Agent', note: '驱动 OpenManus 执行业务任务与攻击输入' },
  attack: { title: '攻击 Agent', note: '依据静态画像规划并迭代攻击集' },
  defense: { title: '防御 Agent', note: '根据失效节点选择并挂载防御策略' },
}
const DEFAULT_MODEL_CONFIG: ModelRuntimeConfiguration = {
  base_url: 'https://api.openai.com/v1',
  model: 'gpt-4o-mini',
  api_key: '',
}
const PREFLIGHT_LABELS: Record<string, string> = {
  agent_registration: 'Agent 注册',
  static_profile: '静态画像',
  docker_daemon: 'Docker 服务',
  openmanus_image: 'OpenManus 镜像',
  model_target: '被测模型',
  model_attack: '攻击模型',
  model_defense: '防御模型',
}

type AuthContext = {
  user: User | null
  ready: boolean
  setSession: (token: string, user: User, persistent?: boolean) => void
  logout: () => Promise<void>
}

let auth: AuthContext

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    if (!tokenStore.get()) return setReady(true)
    api.me().then(({ user: current }) => setUser(current))
      .catch(() => tokenStore.clear()).finally(() => setReady(true))
  }, [])

  useEffect(() => onUnauthorized(() => setUser(null)), [])

  auth = {
    user, ready,
    setSession(token, current, persistent = false) {
      tokenStore.set(token, persistent)
      setUser(current)
    },
    async logout() {
      try { await api.logout() } catch { /* 本地退出仍需完成 */ }
      tokenStore.clear()
      setUser(null)
    },
  }

  if (!ready) return <FullState text="正在恢复安全会话…" />
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" /> : <AuthPage />} />
      <Route element={user ? <Shell /> : <Navigate to="/login" replace />}>
        <Route index element={<Dashboard />} />
        <Route path="agents" element={<Agents />} />
        <Route path="agents/:agentId" element={<AgentProfilePage />} />
        <Route path="audits" element={<AuditRecords />} />
        <Route path="audits/new" element={<NewAudit />} />
        <Route path="audits/:auditId" element={<AuditDetail />} />
        <Route path="settings/models" element={<ModelSettings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

function AuthPage() {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { data: service, loading: serviceLoading, error: serviceError } = useLoad(api.health)
  const serviceState = serviceLoading ? 'checking' : serviceError || service?.status !== 'ok' ? 'offline' : 'online'
  const serviceLabel = serviceState === 'checking' ? '本地审计服务检查中'
    : serviceState === 'online' ? '本地审计服务可用' : '本地审计服务不可用'

  function selectMode(nextMode: 'login' | 'register') {
    if (nextMode === mode) return
    setMode(nextMode)
    setPassword('')
    setError('')
  }

  function handleTabKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const tabs = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]'))
    const current = tabs.indexOf(document.activeElement as HTMLButtonElement)
    const next = event.key === 'ArrowRight' ? (current + 1) % tabs.length
      : event.key === 'ArrowLeft' ? (current - 1 + tabs.length) % tabs.length
        : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1
    if (next < 0) return
    event.preventDefault()
    tabs[next].focus()
    selectMode(next === 0 ? 'login' : 'register')
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLoading(true)
    setError('')
    const data = new FormData(event.currentTarget)
    try {
      const result = mode === 'login'
        ? await api.login(
          String(data.get('account')), String(data.get('password')),
          data.get('remember') === 'on',
        )
        : await api.register(
          String(data.get('username')), String(data.get('email')),
          String(data.get('password')),
        )
      auth.setSession(result.access_token, result.user, data.get('remember') === 'on')
      navigate('/')
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-story">
        <Brand />
        <div className="auth-intro">
          <p className="eyebrow">AGENT RELEASE ASSURANCE</p>
          <h1>Agent 上线前<br />自动审计控制台</h1>
          <p>统一检查攻击风险、防护效果与业务可用性，用可复现证据支持上线决策。</p>
        </div>
        <div className="assurance-list">
          <div><ShieldCheck size={18} /><span><strong>自动安全评测</strong><small>基线攻击与防护复测</small></span></div>
          <div><ListChecks size={18} /><span><strong>确定性业务验证</strong><small>独立 Oracle 校验业务效用</small></span></div>
          <div><FileCheck2 size={18} /><span><strong>可追溯决策</strong><small>完整证据链与发布结论</small></span></div>
        </div>
        <div className={`signal ${serviceState}`} role="status" title={serviceError || serviceLabel}>
          <span />{serviceLabel}
        </div>
      </section>
      <section className="auth-panel">
          <div className="auth-card">
            <div className="mobile-brand"><Brand /></div>
            <div className="tabs" role="tablist" aria-label="账号操作" onKeyDown={handleTabKeyDown}>
              <button id="login-tab" type="button" role="tab" aria-controls="auth-panel" aria-selected={mode === 'login'}
                tabIndex={mode === 'login' ? 0 : -1} className={mode === 'login' ? 'active' : ''} onClick={() => selectMode('login')}>登录</button>
              <button id="register-tab" type="button" role="tab" aria-controls="auth-panel" aria-selected={mode === 'register'}
                tabIndex={mode === 'register' ? 0 : -1} className={mode === 'register' ? 'active' : ''} onClick={() => selectMode('register')}>注册</button>
            </div>
            <div id="auth-panel" role="tabpanel" aria-labelledby={`${mode}-tab`}>
              <h2>{mode === 'login' ? '欢迎回来' : '创建本地账号'}</h2>
              <p className="muted">{mode === 'login' ? '继续你的 Agent 安全审计' : '注册后立即进入审计工作台'}</p>
              <form onSubmit={submit} className="stack">
                {mode === 'register' && <>
                  <Field label="用户名"><input name="username" minLength={3} required placeholder="security-team" /></Field>
                  <Field label="邮箱"><input name="email" type="email" required placeholder="team@example.com" /></Field>
                </>}
                {mode === 'login' &&
                  <Field label="账号"><input name="account" required placeholder="用户名或邮箱" autoComplete="username" /></Field>}
                <Field label="密码"><input name="password" type="password" minLength={mode === 'register' ? 8 : 1} required autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={(event) => setPassword(event.target.value)} /></Field>
                {mode === 'login' &&
                  <label className="check"><input type="checkbox" name="remember" /> 记住登录状态</label>}
                {error && <ErrorBox text={error} />}
                <button className="button primary" disabled={loading}>
                  {loading ? <><span className="button-spinner" />正在验证…</> : mode === 'login' ? '安全登录' : '创建账号'}
                </button>
              </form>
              <p className="auth-footnote"><LockKeyhole size={14} /> 凭据仅用于当前本地审计服务</p>
            </div>
        </div>
      </section>
    </main>
  )
}

function Shell() {
  const navigate = useNavigate()
  const location = useLocation()
  const [accountOpen, setAccountOpen] = useState(false)
  const accountMenuRef = useRef<HTMLDivElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const { data: service, loading: serviceLoading, error: serviceError } = useLoad(api.health)
  const serviceState = serviceLoading ? 'checking' : serviceError || service?.status !== 'ok' ? 'offline' : 'online'
  const serviceLabel = serviceState === 'checking' ? '审计服务检查中' : serviceState === 'online' ? '审计服务在线' : '审计服务离线'

  useEffect(() => {
    function dismiss(event: PointerEvent) {
      if (!accountMenuRef.current?.contains(event.target as Node)) setAccountOpen(false)
    }
    function closeOnEscape(event: globalThis.KeyboardEvent) {
      if (event.key === 'Escape') setAccountOpen(false)
    }
    document.addEventListener('pointerdown', dismiss)
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('pointerdown', dismiss)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [])

  useEffect(() => {
    if (pageRef.current) pageRef.current.scrollTop = 0
  }, [location.pathname])

  async function logout() {
    setAccountOpen(false)
    await auth.logout()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <aside className="sidebar">
        <Brand />
        <nav aria-label="主导航">
          <NavLink to="/" end aria-label="审计总览" data-tooltip="审计总览"><LayoutDashboard size={19} /><span>审计总览</span></NavLink>
          <NavLink to="/agents" aria-label="Agent 资产" data-tooltip="Agent 资产"><Bot size={19} /><span>Agent 资产</span></NavLink>
          <NavLink to="/audits" end aria-label="审计记录" data-tooltip="审计记录"><History size={19} /><span>审计记录</span></NavLink>
          <NavLink to="/settings/models" aria-label="模型配置" data-tooltip="模型配置"><Settings2 size={19} /><span>模型配置</span></NavLink>
        </nav>
        <div className="sidebar-actions">
            <a className="utility-button" href="#/agents" aria-label="Agent 帮助" data-tooltip="Agent 帮助"><HelpCircle size={18} /></a>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
            <div><strong>Agent 上线审计</strong><span>安全评测与发布决策工作台</span></div>
          <div className="topbar-meta">
            <span className={`service-state ${serviceState}`} role="status" title={serviceError || serviceLabel}>
              <i />{serviceLabel}
            </span>
              <div className="account-menu" ref={accountMenuRef}>
                <button className="account-trigger" type="button" aria-label="打开用户菜单"
                  aria-haspopup="menu" aria-expanded={accountOpen} onClick={() => setAccountOpen((value) => !value)}>
                  <span className="avatar">{auth.user?.username[0].toUpperCase()}</span>
                  <span className="user-meta"><strong>{auth.user?.username}</strong><small>{auth.user?.role}</small></span>
                  <ChevronDown size={14} />
                </button>
                {accountOpen && <div className="account-popover" role="menu">
                  <div className="account-summary">
                    <strong>{auth.user?.username}</strong>
                    <span>{auth.user?.email}</span>
                  </div>
                  <NavLink to="/agents" role="menuitem" onClick={() => setAccountOpen(false)}>
                    <Bot size={15} />Agent 资产
                  </NavLink>
                  <NavLink to="/settings/models" role="menuitem" onClick={() => setAccountOpen(false)}>
                    <Settings2 size={15} />模型配置
                  </NavLink>
                  <button type="button" role="menuitem" className="danger" onClick={logout}>
                    <LogOut size={15} />退出登录
                  </button>
                </div>}
              </div>
          </div>
        </header>
          <div className="page" id="main-content" tabIndex={-1} ref={pageRef}><Outlet /></div>
      </div>
    </div>
  )
}

function Dashboard() {
  const { data: audits, loading, error, reload } = useLoad(api.listAudits)
  const recentAudits = useMemo(
    () => sortAudits(audits).slice(0, 4),
    [audits],
  )
  const completed = audits?.filter((audit) => audit.state === 'completed').length ?? 0
  const active = audits?.filter((audit) => !['completed', 'failed'].includes(audit.state)).length ?? 0
  const failed = audits?.filter((audit) => audit.state === 'failed') ?? []
  const total = audits?.length ?? 0
  const completionRate = total ? Math.round((completed / total) * 100) : 0
  const finished = completed + failed.length
  const finishedRate = total ? Math.round((finished / total) * 100) : 0
  const activeRate = total ? Math.round((active / total) * 100) : 0
  return (
    <main className="dashboard-page">
      <div className="dashboard-main">
        <PageHeader eyebrow="Overview" title="审计总览"
            description={`${greeting()}，${auth.user?.username ?? '审计员'}。集中查看 Agent 审计状态与上线结论。`}
            action={<NavLink className="button primary link-button" to="/audits/new">
              <Plus size={15} />新建审计
            </NavLink>}>
          <div className="metrics">
            <Metric icon={<ClipboardCheck />} label="审计总数" value={String(total)} note="当前工作空间" />
            <Metric icon={<CheckCircle2 />} label="已完成" value={String(completed)} note={`${completionRate}% 完成率`} tone="good" />
            <Metric icon={<Activity />} label="执行中" value={String(active)} note="正在运行或等待" tone="info" />
              <Metric icon={<XCircle />} label="失败" value={String(failed.length)} note="需要检查或重试" tone="danger" />
          </div>
          <div className="dashboard-work-grid">
            <Section title="审计运行概览" subtitle="当前工作空间任务分布">
              <div className="overview-bars">
                  <OverviewBar label="审计完成率" detail={`${completed}/${total}`} value={completionRate} tone="primary" />
                  <OverviewBar label="任务结束率" detail={`${finished}/${total}`} value={finishedRate} tone="success" />
                  <OverviewBar label="当前运行占比" detail={`${active}/${total}`} value={activeRate} tone="info" />
              </div>
            </Section>
            <Section title="最近审计" subtitle="按最近更新时间排序" action={
                <div className="section-actions">
                  <button type="button" className="button text" onClick={reload}><RefreshCw size={15} />刷新</button>
                  <NavLink className="button text" to="/audits">查看全部<ArrowRight size={14} /></NavLink>
                </div>
            }>
              <AsyncState loading={loading} error={error} empty={!audits?.length} onRetry={reload}
                emptyText="还没有审计记录。" emptyAction={<NavLink to="/audits/new" className="button secondary">发起第一次审计</NavLink>}>
                <div className="audit-list" role="table" aria-label="最近审计">
                  <div className="audit-list-head" role="row">
                    <span>审计任务</span><span>状态</span><span>更新时间</span><span />
                  </div>
                  {recentAudits.map((audit) => <AuditRow key={audit.audit_id} audit={audit} />)}
                </div>
              </AsyncState>
            </Section>
          </div>
          </PageHeader>
      </div>
    </main>
  )
}

function agentIdFromFilename(filename: string) {
  const withoutExtension = filename.replace(/\.tar$/i, '')
  return withoutExtension.toLowerCase().replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '').slice(0, 80)
}

const PYTHON_MODULE_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/

function AgentImageUploadDialog({
  initialFile,
  onClose,
  onCompleted,
}: {
  initialFile: File
  onClose: () => void
  onCompleted: (agentId: string) => void
}) {
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState<
    'configuring' | 'uploading' | 'profiling' | 'failed' | 'completed'
  >('configuring')
  const [probeModule, setProbeModule] = useState('')
  const [analysis, setAnalysis] = useState<ImageProfileStatus>()
  const [importedAgentId, setImportedAgentId] = useState('')
  const [error, setError] = useState('')
  const closeRef = useRef<HTMLButtonElement>(null)
  const pollingAbortRef = useRef<AbortController>()
  const busy = phase === 'uploading' || phase === 'profiling'

  useEffect(() => () => pollingAbortRef.current?.abort(), [])

  useEffect(() => {
    closeRef.current?.focus()
    const handleKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [busy, onClose])

  async function trackProfile(
    nextAgentId: string,
    analysisId: string,
    initial: ImageProfileStatus,
    signal: AbortSignal,
  ) {
    setAnalysis(initial)
    setPhase('profiling')
    const next = await pollWithTimeout({
      initial,
      poll: (pollSignal) => api.getAgentProfileStatus(nextAgentId, analysisId, pollSignal),
      isComplete: (status) => !['queued', 'running'].includes(status.status),
      onUpdate: setAnalysis,
      intervalMs: 700,
      signal,
    })
    if (next.status === 'failed') {
      setPhase('failed')
      setError(next.errors.map((item) => item.message).join('；') || '画像构建失败，请重试')
      return
    }
    setPhase('completed')
    onCompleted(nextAgentId)
  }

  async function importImage() {
    const normalizedProbeModule = probeModule.trim()
    if (normalizedProbeModule && !PYTHON_MODULE_PATTERN.test(normalizedProbeModule)) {
      setError('Python 探针模块必须是 package.module 形式')
      return
    }
    setPhase('uploading')
    setAnalysis(undefined)
    setImportedAgentId('')
    setError('')
    setProgress(0)
    pollingAbortRef.current?.abort()
    const controller = new AbortController()
    pollingAbortRef.current = controller
    let result
    try {
      result = await api.uploadAgentImage({
        file: initialFile,
        agentId: agentIdFromFilename(initialFile.name) || 'imported-agent',
        name: initialFile.name.replace(/\.tar$/i, '').replace(/[-_]+/g, ' ') || 'Imported Agent',
        domain: 'general',
        expectedFrameworks: [],
        probeModule: normalizedProbeModule || undefined,
      }, setProgress)
      if (controller.signal.aborted) return
    } catch (reason) {
      if (isPollingCancelled(reason)) return
      setError(errorMessage(reason))
      setPhase('failed')
      return
    }
    try {
      setImportedAgentId(result.agent.agent_id)
      await trackProfile(
        result.agent.agent_id,
        result.profile.analysis.analysis_id,
        result.profile.analysis,
        controller.signal,
      )
    } catch (reason) {
      if (isPollingCancelled(reason)) return
      setError(errorMessage(reason))
      setPhase('failed')
    }
  }

  async function retryProfile() {
    if (!analysis || !importedAgentId) {
      await importImage()
      return
    }
    setError('')
    pollingAbortRef.current?.abort()
    const controller = new AbortController()
    pollingAbortRef.current = controller
    try {
      const next = await api.retryAgentProfile(importedAgentId, analysis.analysis_id)
      if (controller.signal.aborted) return
      await trackProfile(importedAgentId, next.analysis_id, next, controller.signal)
    } catch (reason) {
      if (isPollingCancelled(reason)) return
      setError(errorMessage(reason))
      setPhase('failed')
    }
  }

  return <div className="agent-upload-backdrop" role="presentation">
    <section className="agent-upload-dialog" role="dialog" aria-modal="true"
      aria-labelledby="agent-upload-title" aria-describedby="agent-upload-description">
      <header>
        <div><span className="eyebrow">Agent 接入</span><h2 id="agent-upload-title">导入 Agent 镜像</h2>
          <p id="agent-upload-description">可指定安全导入的 Python 模块，用于动态验证 Shell 等非 Python 入口。</p></div>
        <button ref={closeRef} type="button" className="toolbar-icon-button"
          aria-label="关闭上传窗口" title="关闭" disabled={busy} onClick={onClose}><X size={17} /></button>
      </header>
      <div className="agent-import-body">
        <div className="agent-import-file"><FileArchive size={18} />
          <div><strong>{initialFile.name}</strong>
            <span>{(initialFile.size / 1024 / 1024).toFixed(1)} MB · 仅当前用户可见</span></div></div>
        {phase === 'configuring' && <label className="field">
          <span>Python 探针模块（可选）</span>
          <input value={probeModule} placeholder="例如 app.agent.runtime"
            autoComplete="off" spellCheck={false}
            onChange={(event) => {
              setProbeModule(event.target.value)
              setError('')
            }} />
          <small>入口为 Shell 脚本且无法自动推导时填写可安全导入的模块。</small>
        </label>}
        {phase === 'uploading' && <div className="agent-upload-progress" aria-live="polite">
          <div><strong>正在上传镜像</strong><span>{progress}%</span></div>
          <div className="agent-upload-track" role="progressbar" aria-label="镜像上传进度"
            aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}>
            <span style={{ transform: `scaleX(${progress / 100})` }} />
          </div>
        </div>}
        {analysis && <div className="agent-import-profile">
          <ProfileAnalysisPanel analysis={analysis} />
        </div>}
        {error && <ErrorBox text={error} />}
        <footer>
          <span className="agent-import-privacy">镜像及画像仅当前用户可见</span>
          <div><button type="button" className="button secondary" disabled={busy} onClick={onClose}>
            {phase === 'failed' ? '稍后处理' : '取消'}
          </button>
            {phase === 'configuring'
              ? <button type="button" className="button primary" onClick={importImage}>
                <Upload size={16} />开始导入
              </button>
              : phase === 'failed'
              ? <button type="button" className="button primary" onClick={retryProfile}>
                <RefreshCw size={16} />重新尝试
              </button>
              : <button type="button" className="button primary" disabled>
                {phase === 'uploading' ? <><span className="button-spinner" />正在上传</>
                  : phase === 'profiling' ? <><span className="button-spinner" />正在构建画像</>
                    : <><CheckCircle2 size={16} />已加入资产</>}
              </button>}
          </div>
        </footer>
      </div>
    </section>
  </div>
}

function ProfileAnalysisPanel({ analysis }: { analysis: ImageProfileStatus }) {
  const finished = analysis.stages.filter((stage) => ['completed', 'skipped'].includes(stage.status)).length
  const percent = Math.round((finished / analysis.stages.length) * 100)
  const current = analysis.stages.find((stage) => stage.status === 'running')
  const statusLabel = current
    ? PROFILE_STAGE_LABELS[current.stage]
    : analysis.status === 'queued'
      ? '等待分析资源'
      : analysis.status === 'failed'
        ? '画像构建失败'
        : analysis.status === 'partial'
          ? '画像已发布，部分验证未完成'
          : '画像构建完成'
  return <section className="profile-analysis-panel" aria-live="polite">
    <header><div><span className="eyebrow">真实画像构建</span>
      <strong>{statusLabel}</strong></div>
      <span className="profile-analysis-percent">{percent}%</span></header>
    <div className="profile-analysis-track" role="progressbar" aria-label="画像构建进度"
      aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
      <span style={{ transform: `scaleX(${percent / 100})` }} />
    </div>
    <ol className="profile-analysis-stages">
      {analysis.stages.map((stage, index) => <li key={stage.stage} data-status={stage.status}>
        <span className="profile-stage-marker">
          {stage.status === 'completed' || stage.status === 'skipped' ? <CheckCircle2 size={15} />
            : stage.status === 'failed' ? <XCircle size={15} />
              : stage.status === 'running' ? <span className="loader" /> : <Circle size={13} />}
        </span>
        <span><strong>{PROFILE_STAGE_LABELS[stage.stage]}</strong><small>{index + 1} / {analysis.stages.length}</small></span>
      </li>)}
    </ol>
  </section>
}

function AgentDeleteDialog({
  agent,
  onClose,
  onDeleted,
}: {
  agent: Agent
  onClose: () => void
  onDeleted: () => void
}) {
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState('')
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    closeRef.current?.focus()
    const handleKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape' && !deleting) onClose()
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [deleting, onClose])

  async function confirmDelete() {
    setDeleting(true)
    setError('')
    try {
      await api.deleteAgent(agent.agent_id)
      onDeleted()
    } catch (reason) {
      setError(
        reason instanceof ApiError && reason.status === 409
          ? 'Agent 正在完成画像或执行审计，请结束任务后再删除。'
          : errorMessage(reason),
      )
      setDeleting(false)
    }
  }

  return <div className="agent-upload-backdrop" role="presentation"
    onMouseDown={(event) => {
      if (event.target === event.currentTarget && !deleting) onClose()
    }}>
    <section className="agent-delete-dialog" role="alertdialog" aria-modal="true"
      aria-labelledby="agent-delete-title" aria-describedby="agent-delete-description"
      aria-busy={deleting}>
      <header><span className="agent-delete-icon"><Trash2 size={19} /></span>
        <div><h2 id="agent-delete-title">删除 Agent 资产</h2>
          <p id="agent-delete-description">此操作无法撤销，历史审计记录不受影响。</p></div>
        <button ref={closeRef} type="button" className="dialog-close-button"
          aria-label="关闭删除窗口" title="关闭" disabled={deleting} onClick={onClose}>
          <X size={17} />
        </button>
      </header>
      <div className="agent-delete-target"><strong>{agent.name}</strong><code>{agent.agent_id}</code></div>
      <div className="agent-delete-impact">
        <span><strong>将移除</strong> Agent 注册、镜像与画像资产</span>
        <span><strong>将保留</strong> 已生成的历史审计记录</span>
      </div>
      {error && <ErrorBox text={error} />}
      <footer><button className="button secondary" type="button" disabled={deleting} onClick={onClose}>取消</button>
        <button className="button danger" type="button" disabled={deleting} onClick={confirmDelete}>
          {deleting ? <><span className="button-spinner" />正在删除</> : <><Trash2 size={15} />确认删除</>}
        </button></footer>
    </section>
  </div>
}

export function Agents() {
  const { data: agents, loading, error, reload, setData: setAgents } = useLoad(api.listAgents)
  const [uploadFile, setUploadFile] = useState<File>()
  const [fileError, setFileError] = useState('')
  const [deletedAgentName, setDeletedAgentName] = useState('')

  function chooseImageFile(file?: File) {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.tar')) {
      setFileError('只可以选择 docker save 导出的 .tar 镜像文件')
      return
    }
    setFileError('')
    setUploadFile(file)
  }

  function closeUpload() {
    setUploadFile(undefined)
  }
  const [deleteTarget, setDeleteTarget] = useState<Agent>()
  const [query, setQuery] = useState('')
  const searchRef = useRef<HTMLInputElement>(null)
  const filteredAgents = useMemo(() => (agents ?? []).filter((agent) => {
    return `${agent.name} ${agent.agent_id} ${agent.framework} ${agent.adapter_type}`
      .toLowerCase().includes(query.trim().toLowerCase())
  }), [agents, query])

  function clearFilters() {
    setQuery('')
    searchRef.current?.focus()
  }

  return (
    <PageHeader eyebrow="资产管理" title="Agent 资产"
      description="仅展示当前用户已完成画像构建的 Agent。"
      action={<label className="button primary native-file-picker unified-upload-button">
        <input type="file" accept=".tar,application/x-tar,application/tar"
          aria-label="选择 Agent 镜像文件"
          onChange={(event) => {
            chooseImageFile(event.target.files?.[0])
            event.target.value = ''
          }} />
        <span className="upload-inner">
          <span className="upload-pick"><Upload size={15} /><span>选择镜像</span></span>
          <span className="upload-file-name" aria-hidden={!uploadFile}>{uploadFile?.name ?? '尚未选择文件'}</span>
        </span>
        <span className="upload-confirm"><Upload size={15} /><span>接入 Agent</span></span>
      </label>}>
      {uploadFile && <AgentImageUploadDialog
        initialFile={uploadFile}
        onClose={closeUpload}
        onCompleted={() => {
          closeUpload()
          reload()
        }}
      />}
      {fileError && <ErrorBox text={fileError} />}
      {deletedAgentName && <div className="agent-delete-success" role="status" aria-live="polite">
        <CheckCircle2 size={18} />
        <div><strong>Agent 已删除</strong><span>{deletedAgentName} 已从当前用户的资产列表移除。</span></div>
        <button type="button" className="success-dismiss-button" aria-label="关闭删除成功提示"
          title="关闭" onClick={() => setDeletedAgentName('')}><X size={15} /></button>
      </div>}
      {deleteTarget && <AgentDeleteDialog agent={deleteTarget}
        onClose={() => setDeleteTarget(undefined)}
        onDeleted={() => {
          setAgents((current) => current?.filter(
            (agent) => agent.agent_id !== deleteTarget.agent_id,
          ))
          setDeletedAgentName(deleteTarget.name)
          setDeleteTarget(undefined)
        }} />}
      <div className="filter-bar unified-filter-bar" role="search">
        <label className="search-field unified-search"><Search size={16} /><input ref={searchRef} aria-label="搜索 Agent"
          aria-keyshortcuts="Escape" placeholder="搜索名称、ID、框架或适配器" value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => { if (event.key === 'Escape' && query) clearFilters() }} /></label>
        {query && <button className="toolbar-icon-button" type="button"
          aria-label="重置 Agent 筛选" title="重置筛选" onClick={clearFilters}><RotateCcw size={15} /></button>}
        <button className="toolbar-icon-button" type="button" aria-label="刷新 Agent 列表"
          title="刷新 Agent 列表" onClick={reload}><RefreshCw size={15} /></button>
        <span className="result-count" role="status" aria-live="polite"><strong>{filteredAgents.length}</strong>{' '}<span>个 Agent</span></span>
      </div>
      <AsyncState loading={loading} error={error} empty={!agents?.length} onRetry={reload}
        emptyText="暂无 Agent 资产。请上传镜像并完成画像构建。"
        emptyAction={<label className="button secondary native-file-picker unified-upload-button empty-upload-button">
          <input type="file" accept=".tar,application/x-tar,application/tar"
            aria-label="选择 Agent 镜像文件"
            onChange={(event) => {
              chooseImageFile(event.target.files?.[0])
              event.target.value = ''
            }} />
          <span className="upload-inner">
            <span className="upload-pick"><Upload size={14} /><span>选择镜像</span></span>
            <span className="upload-file-name">尚未选择文件</span>
          </span>
          <span className="upload-confirm"><Upload size={14} /><span>接入镜像</span></span>
        </label>}>
        {!filteredAgents.length ? <Empty icon={<Search />} text="没有符合当前筛选条件的 Agent"
          action={<button className="button secondary" onClick={clearFilters}>清除筛选</button>} /> :
          <div className="table-wrap">
            <div className="agent-table" role="table" aria-label="Agent 资产列表">
              <div className="agent-table-head" role="row">
                <span>Agent</span><span>所属领域</span><span>框架 / 适配器</span><span>接入方式</span><span>状态</span><span>操作</span>
              </div>
              {filteredAgents.map((agent) => <AgentCard agent={agent} key={agent.agent_id}
                onDelete={() => setDeleteTarget(agent)} />)}
            </div>
          </div>}
      </AsyncState>
    </PageHeader>
  )
}

export function AgentProfilePage() {
  const { agentId = '' } = useParams()
  const [analysis, setAnalysis] = useState<ImageProfileStatus>()
  const [calculatedProfileSha256, setCalculatedProfileSha256] = useState<string>()
  const [profileAction, setProfileAction] = useState(false)
  const [profileActionError, setProfileActionError] = useState('')
  const profilePollingAbortRef = useRef<AbortController>()
  const { data, loading, error, reload } = useLoad(async () => {
    const [agent, profile, audits] = await Promise.all([
      api.getAgent(agentId),
      api.getAgentProfile(agentId),
      api.listAudits(),
    ])
    const agentAudits = sortAudits(audits.filter((audit) => audit.agent_id === agentId))
    return { agent, profile, audits: agentAudits }
  }, [agentId], Boolean(agentId))

  useEffect(() => {
    if (data?.profile && isImageAgentProfile(data.profile)) setAnalysis(data.profile.analysis)
  }, [data])

  useEffect(() => {
    const profile = data?.profile
    if (!profile || !isImageAgentProfile(profile) || profile.profile_sha256) {
      setCalculatedProfileSha256(undefined)
      return
    }
    let active = true
    calculateProfileSha256(profile)
      .then((digest) => { if (active) setCalculatedProfileSha256(digest) })
      .catch(() => { if (active) setCalculatedProfileSha256(undefined) })
    return () => { active = false }
  }, [data?.profile])

  useEffect(() => () => profilePollingAbortRef.current?.abort(), [])

  async function waitForProfile(analysisId: string, signal: AbortSignal) {
    const next = await pollWithTimeout({
      poll: (pollSignal) => api.getAgentProfileStatus(agentId, analysisId, pollSignal),
      isComplete: (status) => ['completed', 'partial', 'failed'].includes(status.status),
      onUpdate: setAnalysis,
      intervalMs: 700,
      signal,
    })
    if (next.status !== 'failed') {
      reload()
    } else {
      setProfileActionError(next.errors.map((item) => item.message).join('；') || '画像分析失败')
    }
  }

  async function generateProfile(retry = false) {
    profilePollingAbortRef.current?.abort()
    const controller = new AbortController()
    profilePollingAbortRef.current = controller
    setProfileAction(true)
    setProfileActionError('')
    try {
      const next = retry && analysis
        ? await api.retryAgentProfile(agentId, analysis.analysis_id)
        : (await api.createAgentProfile(agentId)).analysis
      if (controller.signal.aborted) return
      setAnalysis(next)
      await waitForProfile(next.analysis_id, controller.signal)
    } catch (reason) {
      if (isPollingCancelled(reason)) return
      setProfileActionError(errorMessage(reason))
    } finally {
      if (!controller.signal.aborted) setProfileAction(false)
    }
  }

  if (loading) return <FullState text="正在读取 Agent 画像…" />
  if (error || !data) return <FullState kind="error" text={profileActionError || error || 'Agent 画像不存在'}
    action={<><button className="button secondary" onClick={reload}><RefreshCw size={15} />重新加载</button>
      <button className="button primary" disabled={profileAction} onClick={() => generateProfile()}>
        {profileAction ? <><span className="button-spinner" />正在生成…</> : <><Plus size={15} />生成 v0.2 画像</>}
      </button>
      <NavLink className="button primary" to="/agents"><ArrowLeft size={15} />返回 Agent 资产</NavLink></>} />

  const { agent, profile, audits } = data
  const recentAudits = audits.slice(0, 5)
  const imageProfile = isImageAgentProfile(profile) ? profile : undefined
  const legacyProfile = !isImageAgentProfile(profile) ? profile : undefined
  const criticalNodes = imageProfile
    ? imageProfile.nodes.filter((node) => ['critical', 'high'].includes(node.risk_level)).length
    : legacyProfile?.nodes.filter((node) => node.critical).length ?? 0
  const dynamicFailed = imageProfile?.analysis.stages.some(
    (stage) => stage.stage === 'dynamic_verify' && stage.status === 'failed',
  )
  const profileSha256 = imageProfile?.profile_sha256 || audits.find((audit) =>
    audit.profile_id === imageProfile?.profile_id
    && audit.image_digest === imageProfile?.image.digest)?.profile_sha256 || calculatedProfileSha256

  return <PageHeader eyebrow="资产管理 / Agent 画像" title={agent.name}
    description={`Agent ID ${agent.agent_id}`}
    action={<>
      <NavLink className="button secondary" to="/agents"><ArrowLeft size={15} />返回资产</NavLink>
      <NavLink className="button primary" to={`/audits/new?agent=${encodeURIComponent(agent.agent_id)}`}>
        <Plus size={15} />发起审计
      </NavLink>
    </>}>
    {profileActionError && <ErrorBox text={profileActionError}
      action={<button className="button secondary" onClick={() => generateProfile(Boolean(analysis))}>
        <RefreshCw size={15} />重试画像分析
      </button>} />}
    {analysis?.status === 'failed' && !profileActionError && <ErrorBox
      text={analysis.errors.map((item) => item.message).join('；') || '画像分析失败'}
      action={<button className="button secondary" onClick={() => generateProfile(true)}>
        <RefreshCw size={15} />重试失败阶段
      </button>} />}
    {analysis && ['queued', 'running'].includes(analysis.status) && <section className="profile-analysis-progress"
      role="status" aria-live="polite">
      <span className="loader" />
      <div><strong>画像分析进行中</strong>
        <p>{analysis.stages.find((stage) => stage.status === 'running')?.stage || '等待执行'} ·
          {' '}{analysis.stages.filter((stage) => ['completed', 'skipped'].includes(stage.status)).length} / {analysis.stages.length} 阶段完成</p>
      </div>
    </section>}
    {imageProfile?.analysis.status === 'partial' && <div className="profile-state-notice" role="status">
      <Info size={18} /><div><strong>{dynamicFailed ? '模块加载或工具注册验证未完成，静态画像仍可检查' : '当前为部分画像'}</strong>
        <p>{imageProfile.analysis.errors.map((item) => item.message).join('；') || '部分分析阶段未完成。'}</p></div>
      <button className="button secondary" disabled={profileAction} onClick={() => generateProfile(true)}>
        <RefreshCw size={15} />重试失败阶段
      </button>
    </div>}
    <section className="agent-profile-summary" aria-label="Agent 概览">
      <div className="agent-profile-identity">
        <span className="agent-profile-icon"><Bot size={22} /></span>
        <div><span>当前状态</span><StatusBadge value={agent.status} /></div>
      </div>
      <div><span>累计审计</span><strong>{audits.length}</strong><small>条记录</small></div>
      <div><span>最近审计</span><strong>{audits[0] ? formatDate(audits[0].updated_at) : '暂无'}</strong><small>{audits[0] ? stateName(audits[0].state) : '尚未发起'}</small></div>
      <div><span>画像节点</span><strong>{profile.nodes.length}</strong><small>{criticalNodes} 个关键节点</small></div>
    </section>

    {imageProfile ? <>
      {!imageProfile.nodes.length && <div className="profile-state-notice" role="status">
        <Info size={18} /><div><strong>画像中没有可展示节点</strong><p>检查分析限制后可重新加载或重试画像分析。</p></div>
        <button className="button secondary" onClick={reload}><RefreshCw size={15} />重新加载画像</button>
      </div>}
      <AgentProfileReport profile={imageProfile} profileSha256={profileSha256 || undefined}
        retrying={profileAction} onRetry={() => generateProfile(true)} />
      <Suspense fallback={<FullState text="正在加载图谱…" />}>
        <AgentProfileGraph profile={imageProfile} />
      </Suspense>
      <Section title="最近审计" subtitle="该 Agent 最近五次审计记录" action={
        <NavLink className="button text" to={`/audits?agent=${encodeURIComponent(agent.agent_id)}`}>
          查看全部<ArrowRight size={14} />
        </NavLink>
      }>
        {recentAudits.length ? <div className="audit-list profile-audit-list" role="table" aria-label={`${agent.name} 最近审计`}>
          <div className="audit-list-head" role="row">
            <span>审计任务</span><span>状态</span><span>更新时间</span><span />
          </div>
          {recentAudits.map((audit) => <AuditRow key={audit.audit_id} audit={audit} />)}
        </div> : <Empty icon={<History />} text="该 Agent 暂无审计记录"
          action={<NavLink className="button secondary" to={`/audits/new?agent=${encodeURIComponent(agent.agent_id)}`}>发起首次审计</NavLink>} />}
      </Section>
    </> : legacyProfile && <>
    <div className="profile-state-notice legacy" role="status">
      <Info size={18} /><div><strong>当前为兼容画像</strong><p>生成 v0.2 画像后可查看证据图谱与风险路径。</p></div>
      <button className="button secondary" disabled={profileAction} onClick={() => generateProfile()}>
        <Plus size={15} />生成 v0.2 画像
      </button>
    </div>
    <div className="agent-profile-layout">
      <div className="agent-profile-main">
        <Section title="最近审计" subtitle="该 Agent 最近五次审计记录" action={
          <NavLink className="button text" to={`/audits?agent=${encodeURIComponent(agent.agent_id)}`}>
            查看全部<ArrowRight size={14} />
          </NavLink>
        }>
          {recentAudits.length ? <div className="audit-list profile-audit-list" role="table" aria-label={`${agent.name} 最近审计`}>
            <div className="audit-list-head" role="row">
              <span>审计任务</span><span>状态</span><span>更新时间</span><span />
            </div>
            {recentAudits.map((audit) => <AuditRow key={audit.audit_id} audit={audit} />)}
          </div> : <Empty icon={<History />} text="该 Agent 暂无审计记录"
            action={<NavLink className="button secondary" to={`/audits/new?agent=${encodeURIComponent(agent.agent_id)}`}>发起首次审计</NavLink>} />}
        </Section>

        <Section title="工具清单" subtitle={`${legacyProfile.tools.length} 个已识别工具`}>
          {legacyProfile.tools.length ? <div className="profile-tool-list">
            {legacyProfile.tools.map((tool) => <article className="profile-tool-row" key={tool.name}>
              <span className="profile-row-icon"><Wrench size={15} /></span>
              <div><strong>{tool.name}</strong><p>{tool.description}</p></div>
              <span className={`risk-level ${riskTone(tool.risk_level)}`}>{riskLevelName(tool.risk_level)}</span>
            </article>)}
          </div> : <Empty icon={<Wrench />} text="当前画像未登记工具" />}
        </Section>

        <Section title="能力节点" subtitle="从 Agent 画像中识别的执行链路">
          {legacyProfile.nodes.length ? <div className="profile-node-list">
            {legacyProfile.nodes.map((node) => <article className="profile-node-row" key={node.node_id}>
              <div><strong>{node.node_id}</strong><code>{node.node_type}</code></div>
              <span>{node.required ? '必需节点' : '可选节点'}</span>
              <span className={node.critical ? 'node-critical' : 'node-standard'}>
                {node.critical ? '关键' : '常规'}
              </span>
            </article>)}
          </div> : <Empty icon={<ListChecks />} text="当前画像未识别执行节点" />}
        </Section>
      </div>

      <aside className="agent-profile-aside" aria-label="Agent 技术画像">
        <Section title="技术画像" subtitle="接入与运行信息">
          <dl className="profile-facts">
            <div><dt>所属领域</dt><dd>{agent.domain || '未填写'}</dd></div>
            <div><dt>Agent 类型</dt><dd>{legacyProfile.agent_type}</dd></div>
            <div><dt>框架</dt><dd>{agent.framework}</dd></div>
            <div><dt>适配器</dt><dd><code>{agent.adapter_type}</code></dd></div>
            <div><dt>接入方式</dt><dd>{agent.integration_type}</dd></div>
            <div><dt>接入时间</dt><dd>{formatDate(agent.created_at)}</dd></div>
            <div><dt>画像更新时间</dt><dd>{formatDate(legacyProfile.generated_at)}</dd></div>
          </dl>
        </Section>

        <Section title="风险面" subtitle={`${legacyProfile.risk_surface.length} 项已识别风险`}>
          {legacyProfile.risk_surface.length ? <div className="risk-surface-list">
            {legacyProfile.risk_surface.map((risk) => <span key={risk}><ShieldCheck size={13} />{risk}</span>)}
          </div> : <Empty icon={<ShieldCheck />} text="当前画像未识别风险面" />}
        </Section>
      </aside>
    </div>
    </>}
  </PageHeader>
}

export function AgentProfileReport({ profile, profileSha256, retrying, onRetry }: {
  profile: ImageAgentProfile
  profileSha256?: string
  retrying?: boolean
  onRetry?: () => void
}) {
  const controls = new Map(profile.controls.map((item) => [item.control_id, item]))
  const completeness = profile.completeness
  const isComplete = completeness?.conclusion === 'complete'
  return <div className="complete-profile-report" aria-label="agent-profile-v0.2 画像报告">
    <section className="complete-profile-section profile-completeness" aria-labelledby="profile-completeness-title">
      <div className="profile-completeness-header">
        <div>
          <span>画像完整度结论 · <code>{completeness?.conclusion || 'unknown'}</code></span>
          <h2 id="profile-completeness-title">{isComplete ? '完整画像' : '部分画像'}</h2>
          <p>{isComplete
            ? '静态恢复、框架识别、图谱证据和动态佐证均已通过完整度门禁。'
            : '当前结果可供检查，但尚未通过全部完整度门禁。'}</p>
        </div>
        {!isComplete && onRetry && <button type="button" className="button secondary"
          disabled={retrying} onClick={onRetry}><RefreshCw size={15} />重试画像分析</button>}
      </div>
      <dl className="profile-coverage-grid">
        <ReportFact term="Python 源码恢复" value={completeness
          ? sourceRecoveryLabel(completeness.static_source_recovery) : '未提供完整度数据'} />
        <CoverageFact term="框架识别覆盖" coverage={completeness?.framework_coverage} />
        <CoverageFact term="图谱证据覆盖" coverage={completeness?.graph_evidence_coverage} />
        <CoverageFact term="动态行为覆盖" coverage={completeness?.dynamic_behavior_coverage} />
        <CoverageFact term="全图动态佐证" coverage={completeness?.dynamic_corroboration_coverage} />
        <ReportFact term="未解决限制" value={completeness ? `${completeness.unresolved_limitations} 项` : '未知'} />
      </dl>
      {!isComplete && <div className="profile-blocking-reasons">
        <strong>阻断原因</strong>
        {completeness?.blocking_limitations.length
          ? <ul>{completeness.blocking_limitations.map((code) => <li key={code}>
            <code>{code}</code>
            <span>{profile.limitations.find((item) => item.code === code)?.message || '该门禁阻止画像达到完整状态。'}</span>
          </li>)}</ul>
          : <p>{completeness ? '未提供具体阻断代码，请检查未解决限制。' : '当前 API 未提供完整度摘要。'}</p>}
      </div>}
    </section>

    <section className="complete-profile-section profile-identity-section">
      <ReportHeading title="镜像与画像身份" count={profile.schema_version} />
      <dl className="complete-profile-facts">
        <ReportFact term="画像 ID" value={profile.profile_id} code />
        <ReportFact term="画像 SHA-256"
          value={profileSha256 || '当前 API 未在 JSON 中返回哈希；最小调整为向前端暴露画像 GET 响应的 ETag。'}
          code={Boolean(profileSha256)} />
        <ReportFact term="镜像摘要" value={profile.image.digest} code />
        <ReportFact term="平台" value={[profile.image.os, profile.image.architecture, profile.image.variant].filter(Boolean).join(' / ')} />
        <ReportFact term="镜像创建时间" value={profile.image.created_at ? formatDateTime(profile.image.created_at) : '未提供'} />
        <ReportFact term="画像生成时间" value={formatDateTime(profile.generated_at)} />
        <ReportFact term="入口点" value={commandLine(profile.image.entrypoint)} code />
        <ReportFact term="命令" value={commandLine(profile.image.command)} code />
        <ReportFact term="工作目录" value={profile.image.working_directory || '未设置'} code />
        <ReportFact term="环境变量名" value={profile.image.environment_variables.join('、') || '无'} code />
      </dl>
      <div className="profile-digest-list">
        <strong>镜像层摘要 · {profile.image.layer_digests.length}</strong>
        {profile.image.layer_digests.length
          ? profile.image.layer_digests.map((digest) => <code key={digest}>{digest}</code>)
          : <span>未提供镜像层摘要</span>}
      </div>
    </section>

    <section className="complete-profile-section">
      <ReportHeading title="八阶段分析"
        count={`${profile.analysis.stages.filter((stage) => stage.status === 'completed').length} / ${profile.analysis.stages.length} 完成`} />
      <ol className="profile-stage-report">
        {profile.analysis.stages.map((stage, index) => <li key={stage.stage}>
          <span className={`profile-stage-status stage-${stage.status}`}>{index + 1}</span>
          <div><strong>{PROFILE_STAGE_LABELS[stage.stage]}</strong><code>{stage.stage}</code></div>
          <span>{profileStageStatusName(stage.status)}</span>
          <small>{stage.completed_at ? formatDateTime(stage.completed_at) : stage.started_at ? formatDateTime(stage.started_at) : '未开始'}</small>
        </li>)}
      </ol>
    </section>

    <section className="complete-profile-section">
      <ReportHeading title="框架识别" count={`${profile.frameworks.length} 项`} />
      <div className="profile-framework-list">
        {profile.frameworks.map((framework) => <article key={framework.framework_id}>
          <div><strong>{framework.name}</strong><code>{framework.framework_id}</code></div>
          <span>{framework.version || '版本未知'}</span>
          <ClaimState claim={framework} />
          <EvidenceRefs refs={framework.evidence_refs} />
        </article>)}
        {!profile.frameworks.length && <ReportEmpty text="未识别框架" />}
      </div>
    </section>

    <section className="complete-profile-section">
      <ReportHeading title="能力、权限与安全控制"
        count={`${profile.capabilities.length} / ${profile.permissions.length} / ${profile.controls.length}`} />
      <div className="complete-profile-columns">
        <ReportCollection title="能力" items={profile.capabilities.map((item) => ({
          id: item.capability_id,
          title: item.name,
          meta: `${item.operation} · ${riskLabel(item.risk_level)}`,
          detail: `节点：${item.node_ids.join('、') || '未关联'}`,
          claim: item,
        }))} />
        <ReportCollection title="权限" items={profile.permissions.map((item) => ({
          id: item.permission_id,
          title: item.permission_type,
          meta: `${item.operations.join('、') || '未声明操作'} · ${riskLabel(item.risk_level)}`,
          detail: `作用域：${item.scope}`,
          claim: item,
        }))} />
        <ReportCollection title="安全控制" items={profile.controls.map((item) => ({
          id: item.control_id,
          title: item.name,
          meta: item.control_type,
          detail: item.description,
          claim: item,
        }))} />
      </div>
    </section>

    <section className="complete-profile-section">
      <ReportHeading title="风险路径详情" count={`${profile.risk_paths.length} 条`} />
      <ProgressiveList className="complete-profile-risk-paths" label="风险路径"
        items={profile.risk_paths} emptyText="未识别风险路径" renderItem={(path) => <article key={path.path_id}>
          <header>
            <div><strong>{path.path_id}</strong><code>{path.source_node_id} → {path.sink_node_id}</code></div>
            <span className={`graph-state risk-${path.risk_level}`}>{riskLabel(path.risk_level)}</span>
            <ClaimState claim={path} />
          </header>
          <dl>
            <ReportFact term="有序节点路径" value={path.node_ids.join(' → ') || '未提供'} code />
            <ReportFact term="适用威胁" value={path.applicable_threats.join('、') || '未提供'} />
            <ReportFact term="现有控制" value={path.control_ids.map((id) => controls.get(id)?.name || id).join('、') || '无'} />
            <ReportFact term="控制缺口" value={path.control_gaps.join('；') || '未识别'} />
            <ReportFact term="能力 / 权限" value={[...path.capability_ids, ...path.permission_ids].join('、') || '未关联'} code />
          </dl>
          <EvidenceRefs refs={path.evidence_refs} />
        </article>} />
    </section>

    <section className="complete-profile-section">
      <ReportHeading title="全量证据索引" count={`${profile.evidence.length} 条`} />
      <ProgressiveList className="complete-profile-evidence-index" label="证据"
        items={profile.evidence} emptyText="没有可用证据" renderItem={(item) => <article key={item.evidence_id}>
          <header><strong>{item.evidence_id}</strong><span>{item.method} · {item.trust_level || 'legacy'} · {item.extractor}</span></header>
          <p>{item.summary || '未提供证据摘要'}</p>
          <dl>
            <ReportFact term="制品摘要" value={item.artifact_digest} code />
            <ReportFact term="镜像层摘要" value={item.layer_digest || '不适用'} code={Boolean(item.layer_digest)} />
            <ReportFact term="定位" value={profileEvidenceLocation(item.locator)} code />
            <ReportFact term="内容 SHA-256" value={item.content_sha256} code />
          </dl>
        </article>} />
    </section>

    <section className="complete-profile-section">
      <ReportHeading title="分析限制" count={`${profile.limitations.length} 项`} />
      <div className="complete-profile-limitations">
        {profile.limitations.map((item) => <article key={item.code}>
          <code>{item.code}</code><p>{item.message}</p><EvidenceRefs refs={item.evidence_refs} />
        </article>)}
        {!profile.limitations.length && <ReportEmpty text="未声明分析限制" />}
      </div>
    </section>
  </div>
}

function ReportHeading({ title, count }: { title: string; count: string }) {
  return <header className="complete-profile-heading"><h2>{title}</h2><span>{count}</span></header>
}

function ReportFact({ term, value, code = false }: { term: string; value: string; code?: boolean }) {
  return <div><dt>{term}</dt><dd>{code ? <code>{value}</code> : value}</dd></div>
}

function ReportCollection({ title, items }: {
  title: string
  items: Array<{ id: string; title: string; meta: string; detail: string; claim: ProfileClaim }>
}) {
  return <div className="complete-profile-collection">
    <h3>{title}</h3>
    <ProgressiveList label={title} items={items} emptyText={`未识别${title}`} renderItem={(item) => <article key={item.id}>
      <header><strong>{item.title}</strong><code>{item.id}</code></header>
      <span>{item.meta}</span><p>{item.detail}</p>
      <ClaimState claim={item.claim} /><EvidenceRefs refs={item.claim.evidence_refs} />
    </article>} />
  </div>
}

const REPORT_BATCH_SIZE = 20

function ProgressiveList<T>({ items, label, className, emptyText, renderItem }: {
  items: T[]
  label: string
  className?: string
  emptyText: string
  renderItem: (item: T) => ReactNode
}) {
  const [visibleCount, setVisibleCount] = useState(REPORT_BATCH_SIZE)
  const count = Math.min(visibleCount, items.length)
  return <div className={className} aria-label={`${label}列表`}>
    {items.slice(0, count).map(renderItem)}
    {!items.length && <ReportEmpty text={emptyText} />}
    {items.length > count && <div className="profile-load-more">
      <span aria-live="polite">已显示 {count} / {items.length}</span>
      <button type="button" className="button secondary"
        onClick={() => setVisibleCount((current) => current + REPORT_BATCH_SIZE)}>
        查看更多{label}
      </button>
    </div>}
  </div>
}

function CoverageFact({ term, coverage }: {
  term: string
  coverage?: { covered: number; total: number; ratio: number }
}) {
  return <ReportFact term={term} value={coverage
    ? `${coverage.covered} / ${coverage.total}（${Math.round(coverage.ratio * 100)}%）`
    : '未提供完整度数据'} />
}

function ClaimState({ claim }: { claim: ProfileClaim }) {
  return <span className={`profile-claim verification-${claim.verification_status}`}>
    {verificationLabel(claim.verification_status)} · {Math.round(claim.confidence * 100)}%
  </span>
}

function EvidenceRefs({ refs }: { refs: string[] }) {
  return <div className="profile-evidence-refs"><span>证据</span>
    {refs.length ? refs.map((ref) => <code key={ref}>{ref}</code>) : <em>无引用</em>}
  </div>
}

function ReportEmpty({ text }: { text: string }) {
  return <p className="complete-profile-empty">{text}</p>
}

function profileEvidenceLocation(locator: ImageAgentProfile['evidence'][number]['locator']) {
  const source = locator.image_path || locator.python_module || locator.package_metadata_key
    || locator.config_key || locator.event_id || '未知来源'
  const symbol = locator.symbol ? ` · ${locator.symbol}` : ''
  const lines = locator.line_start ? `:${locator.line_start}-${locator.line_end ?? locator.line_start}` : ''
  return `${source}${symbol}${lines}`
}

const commandLine = (items: string[]) => items.length ? items.join(' ') : '未设置'
const formatDateTime = (value: string) => new Date(value).toLocaleString('zh-CN')
const riskLabel = (value: ProfileRiskLevel) => ({
  low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险',
})[value]
const verificationLabel = (value: ProfileVerificationStatus) => ({
  verified: '已验证', supported: '有证据支持', inferred: '推断', rejected: '已否定',
})[value]
const sourceRecoveryLabel = (value: NonNullable<ImageAgentProfile['completeness']>['static_source_recovery']) => ({
  complete: '完整',
  partial: '部分',
  metadata_only: '仅元数据',
  bytecode_only: '仅字节码',
  none: '未恢复',
})[value]
const profileStageStatusName = (value: ImageAgentProfile['analysis']['stages'][number]['status']) => ({
  pending: '待执行', running: '执行中', completed: '已完成', failed: '失败', skipped: '已跳过',
})[value]

export function AuditRecords() {
  const { data: audits, loading, error, reload } = useLoad(api.listAudits)
  const [searchParams] = useSearchParams()
  const [query, setQuery] = useState(searchParams.get('agent') ?? '')
  const [statusFilter, setStatusFilter] = useState('all')
  const filteredAudits = useMemo(() => sortAudits(audits).filter((audit) => {
    const matchesQuery = `${audit.audit_id} ${audit.agent_id}`.toLowerCase().includes(query.trim().toLowerCase())
    const matchesStatus = statusFilter === 'all'
      || statusFilter === audit.state
      || (statusFilter === 'running' && !['completed', 'failed'].includes(audit.state))
    return matchesQuery && matchesStatus
  }), [audits, query, statusFilter])

  function clearFilters() {
    setQuery('')
    setStatusFilter('all')
  }

  return <PageHeader eyebrow="审计中心" title="审计记录"
    description="查看全部安全审计任务，并按任务、Agent 或执行状态快速筛选。"
    action={<NavLink className="button primary link-button" to="/audits/new"><Plus size={15} />新建审计</NavLink>}>
    <div className="filter-bar unified-filter-bar" role="search">
      <label className="search-field unified-search"><Search size={16} />
        <input type="search" aria-label="搜索审计记录" autoComplete="off"
          value={query} onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => { if (event.key === 'Escape') setQuery('') }}
          placeholder="搜索审计 ID 或 Agent ID" />
        {query && <button type="button" className="search-clear" aria-label="清空搜索"
          title="清空搜索" onClick={() => setQuery('')}><X size={14} /></button>}
      </label>
      <label className="filter-select unified-status-filter"><Filter size={15} />
        <select aria-label="按审计状态筛选" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
          <option value="all">全部状态</option>
          <option value="running">执行中</option>
          <option value="completed">已完成</option>
          <option value="failed">失败</option>
          <option value="needs_approval">待审批</option>
        </select>
      </label>
      {statusFilter !== 'all' &&
        <button className="toolbar-icon-button" type="button" aria-label="重置筛选"
          title="重置筛选" onClick={clearFilters}><RotateCcw size={15} /></button>}
      <button className="toolbar-icon-button" type="button" aria-label="刷新审计记录"
        title="刷新审计记录" onClick={reload}><RefreshCw size={15} /></button>
      <span className="result-count" role="status" aria-live="polite"><strong>{filteredAudits.length}</strong>{' '}<span>条记录</span></span>
    </div>
    <AsyncState loading={loading} error={error} empty={!audits?.length} onRetry={reload}
      emptyText="还没有审计记录。" emptyAction={<NavLink to="/audits/new" className="button secondary">发起第一次审计</NavLink>}>
      {!filteredAudits.length ? <Empty icon={<Search />} text="没有符合当前筛选条件的审计记录"
        action={<button className="button secondary" onClick={clearFilters}>清除筛选</button>} /> :
        <section className="panel audit-record-panel">
          <div className="audit-list" role="table" aria-label="全部审计记录">
            <div className="audit-list-head" role="row">
              <span>审计任务</span><span>状态</span><span>更新时间</span><span />
            </div>
            {filteredAudits.map((audit) => <AuditRow key={audit.audit_id} audit={audit} />)}
          </div>
        </section>}
    </AsyncState>
  </PageHeader>
}

function ModelConfigurationPanel({
  onReadyChange,
}: {
  onReadyChange?: (ready: boolean) => void
}) {
  const [testingRole, setTestingRole] = useState<ModelRuntimeRole | null>(null)
  const [error, setError] = useState('')
  const [statuses, setStatuses] = useState<
    Partial<Record<ModelRuntimeRole, ModelRuntimeStatus>>
  >({})
  const [configs, setConfigs] = useState<
    Record<ModelRuntimeRole, ModelRuntimeConfiguration>
  >({
    target: { ...DEFAULT_MODEL_CONFIG },
    attack: { ...DEFAULT_MODEL_CONFIG },
    defense: { ...DEFAULT_MODEL_CONFIG },
  })
  const ready = MODEL_RUNTIME_ROLES.every((role) => statuses[role]?.tested)

  useEffect(() => {
    let active = true
    setError('')
    api.getModelRuntimeStatuses()
      .then((items) => {
        if (!active) return
        setStatuses(Object.fromEntries(
          items.map((status) => [status.role, status]),
        ) as Partial<Record<ModelRuntimeRole, ModelRuntimeStatus>>)
        setConfigs((current) => {
          const next = { ...current }
          for (const status of items) {
            next[status.role] = {
              ...next[status.role],
              base_url: status.base_url || next[status.role].base_url,
              model: status.model || next[status.role].model,
            }
          }
          return next
        })
      })
      .catch((reason) => {
        if (active) setError(errorMessage(reason))
      })
    return () => { active = false }
  }, [])

  useEffect(() => {
    onReadyChange?.(ready)
  }, [onReadyChange, ready])

  function update(
    role: ModelRuntimeRole,
    field: keyof ModelRuntimeConfiguration,
    value: string,
  ) {
    setConfigs((current) => ({
      ...current,
      [role]: { ...current[role], [field]: value },
    }))
    setStatuses((current) => ({
      ...current,
      [role]: current[role]
        ? { ...current[role], tested: false, error: null }
        : undefined,
    }))
  }

  async function test(role: ModelRuntimeRole) {
    const configuration = configs[role]
    if (!configuration.base_url.trim() || !configuration.model.trim()
      || !configuration.api_key.trim()) {
      setError(`${MODEL_RUNTIME_META[role].title}配置不完整。`)
      return
    }
    setTestingRole(role)
    setError('')
    try {
      const status = await api.testModelRuntimeConfiguration(
        role,
        configuration,
      )
      setStatuses((current) => ({ ...current, [role]: status }))
      if (!status.tested) {
        setError(
          status.error || `${MODEL_RUNTIME_META[role].title}连接测试失败。`
        )
      }
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setTestingRole(null)
    }
  }

  return <div className="model-configuration-panel">
    <div className="model-config-toolbar">
      <span className={`model-readiness ${ready ? 'ready' : ''}`}>
        {ready ? <CheckCircle2 size={14} /> : <Circle size={14} />}
        {ready ? '配置就绪' : `${MODEL_RUNTIME_ROLES.filter((role) => statuses[role]?.tested).length} / 3 已通过`}
      </span>
    </div>
    <div className="model-config-grid">
      {MODEL_RUNTIME_ROLES.map((role) => {
        const meta = MODEL_RUNTIME_META[role]
        const status = statuses[role]
        const testing = testingRole === role
        return <article className={`model-config-card ${status?.tested ? 'tested' : ''}`} key={role}>
          <header>
            <span className="model-role-icon">
              {role === 'defense' ? <ShieldPlus size={16} />
                : role === 'attack' ? <Crosshair size={16} /> : <Bot size={16} />}
            </span>
            <div><h3>{meta.title}</h3><p>{meta.note}</p></div>
            <span className={`model-test-state ${status?.tested ? 'success' : status?.error ? 'failed' : ''}`}>
              {status?.tested ? <CheckCircle2 size={13} />
                : status?.error ? <XCircle size={13} /> : <Circle size={13} />}
              {status?.tested ? '可用' : status?.error ? '失败' : '未测试'}
            </span>
          </header>
          <div className="model-config-fields">
            <Field label={`${meta.title} API 地址`}>
              <input type="url" value={configs[role].base_url}
                onChange={(event) => update(role, 'base_url', event.target.value)} />
            </Field>
            <Field label={`${meta.title} 模型名称`}>
              <input value={configs[role].model}
                onChange={(event) => update(role, 'model', event.target.value)} />
            </Field>
            <Field label={`${meta.title} API Key`}>
              <input type="password" autoComplete="off" value={configs[role].api_key}
                placeholder={status?.tested ? '已安全配置，修改时重新输入' : '输入 API Key'}
                onChange={(event) => update(role, 'api_key', event.target.value)} />
            </Field>
          </div>
          <footer>
            <span>{status?.tested_at ? `最近测试 ${formatDateTime(status.tested_at)}` : '尚未验证连接'}</span>
            <button type="button" className="button secondary"
              disabled={testingRole !== null} onClick={() => test(role)}>
              {testing ? <><span className="button-spinner" />测试中…</>
                : <><RefreshCw size={14} />测试并保存</>}
            </button>
          </footer>
        </article>
      })}
    </div>
    <p className="model-security-note"><LockKeyhole size={13} />
      API Key 仅保存在当前 App 进程，不写入画像、审计任务或报告。</p>
    {error && <ErrorBox text={error} />}
  </div>
}

export function ModelSettings() {
  const [ready, setReady] = useState(false)
  return <PageHeader eyebrow="系统设置 / 模型" title="Agent 模型配置"
    description="集中管理被测、攻击和防御 Agent 的运行模型，并验证真实连接。"
    action={<span className={`model-readiness ${ready ? 'ready' : ''}`}>
      {ready ? <CheckCircle2 size={14} /> : <Circle size={14} />}
      {ready ? '三角色已就绪' : '配置未完成'}
    </span>}>
    <section className="panel model-settings-panel">
      <ModelConfigurationPanel onReadyChange={setReady} />
    </section>
    <div className="alert info">
      <LockKeyhole size={18} /><div><strong>进程级凭据保护</strong>
        <p>配置按当前登录租户隔离，只驻留于 App 内存；退出 App 后需要重新测试。</p></div>
    </div>
  </PageHeader>
}

export function NewAudit() {
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [modelsReady, setModelsReady] = useState(false)
  const [profileReadiness, setProfileReadiness] = useState<
    'idle' | 'checking' | 'ready' | 'missing'
  >('idle')
  const [profileReadinessError, setProfileReadinessError] = useState('')
  const [runtimePreflight, setRuntimePreflight] = useState<AuditPreflightStatus>()
  const [runtimePreflightLoading, setRuntimePreflightLoading] = useState(false)
  const [runtimePreflightError, setRuntimePreflightError] = useState('')
  const [preflightVersion, setPreflightVersion] = useState(0)
  const { data: agents, loading: agentsLoading, error: agentsError, reload } = useLoad(api.listAgents)
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [selectedAgentId, setSelectedAgentId] = useState(searchParams.get('agent') ?? '')
  const selectedAgent = agents?.find((agent) => agent.agent_id === selectedAgentId)
  const isOpenManus = selectedAgent?.adapter_type === 'openmanus'
  const benchmarkId = isOpenManus ? 'openmanus-security-v0.1' : 'ecommerce-security-v0.1'
  const runtimeMode = isOpenManus ? 'openmanus_real' : 'sdk'
  const preflightReady = !isOpenManus || (
    modelsReady
    && profileReadiness === 'ready'
    && runtimePreflight?.ready === true
  )

  useEffect(() => {
    if (!isOpenManus || !selectedAgentId) {
      setProfileReadiness('idle')
      setProfileReadinessError('')
      return
    }
    let active = true
    setProfileReadiness('checking')
    setProfileReadinessError('')
    api.getLatestAgentProfile(selectedAgentId)
      .then((profile) => {
        if (!active) return
        const published = profile.analysis.status === 'completed'
          || profile.analysis.status === 'partial'
        setProfileReadiness(published ? 'ready' : 'missing')
        if (!published) {
          setProfileReadinessError('当前画像尚未发布，请先完成静态画像。')
        }
      })
      .catch((reason) => {
        if (!active) return
        setProfileReadiness('missing')
        setProfileReadinessError(errorMessage(reason))
      })
    return () => { active = false }
  }, [isOpenManus, selectedAgentId])

  useEffect(() => {
    if (!isOpenManus || !selectedAgentId) {
      setRuntimePreflight(undefined)
      setRuntimePreflightError('')
      return
    }
    let active = true
    setRuntimePreflightLoading(true)
    setRuntimePreflightError('')
    api.getAuditPreflight(selectedAgentId)
      .then((status) => {
        if (active) setRuntimePreflight(status)
      })
      .catch((reason) => {
        if (active) setRuntimePreflightError(errorMessage(reason))
      })
      .finally(() => {
        if (active) setRuntimePreflightLoading(false)
      })
    return () => { active = false }
  }, [
    isOpenManus,
    selectedAgentId,
    modelsReady,
    preflightVersion,
  ])

  function scrollToSection(sectionId: string) {
    document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const lines = (name: string) => String(data.get(name)).split('\n').map((v) => v.trim()).filter(Boolean)
    const input: AuditTaskInput = {
      agent_id: String(data.get('agent_id')),
      benchmark_id: benchmarkId,
      runtime_mode: runtimeMode,
      security_goals: lines('security_goals'),
      authorized_risk_surfaces: lines('risk_surfaces'),
      normal_tasks: [{
        task_id: `task-${Date.now()}`,
        prompt: String(data.get('prompt')),
        success_criteria: lines('success_criteria'),
        oracle: {
          required_answer_substrings: lines('required_answer_substrings'),
          required_business_events: lines('required_business_events'),
        },
      }],
      seed: Number(data.get('seed')),
      auto_harden: data.get('auto_harden') === 'on',
    }
    if (isOpenManus && !modelsReady) {
      setError('请先完成被测、攻击和防御 Agent 的模型连接测试。')
      return
    }
    if (isOpenManus && profileReadiness !== 'ready') {
      setError('请先完成并发布当前 OpenManus Agent 的静态画像。')
      return
    }
    if (isOpenManus && runtimePreflight?.ready !== true) {
      setError('运行环境预检未通过，请处理所有阻断项后重试。')
      return
    }
    setLoading(true)
    setError('')
    try {
      const audit = await api.createAudit(input)
      navigate(`/audits/${encodeURIComponent(audit.audit_id)}`)
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setLoading(false)
    }
  }

  return (
    <PageHeader eyebrow="审计中心 / 新建任务" title="新建安全审计"
        description="选择审计对象，明确授权边界，并配置独立业务验证条件。"
        action={<button type="button" className="button secondary" onClick={() => navigate('/')}>
          <ArrowLeft size={15} />返回总览
        </button>}>
        <div className="audit-builder">
          <aside className="audit-guide" aria-label="审计配置步骤">
            <nav>
                <button type="button" aria-controls="audit-target" onClick={() => scrollToSection('audit-target')}>
                  <span>1</span><div><strong>审计对象</strong><small>Agent 与基准</small></div>
                </button>
                {isOpenManus && <button type="button" aria-controls="audit-models" onClick={() => scrollToSection('audit-models')}>
                  <span>2</span><div><strong>模型配置</strong><small>三角色连接测试</small></div>
                </button>}
                <button type="button" aria-controls="audit-boundary" onClick={() => scrollToSection('audit-boundary')}>
                  <span>{isOpenManus ? 3 : 2}</span><div><strong>安全边界</strong><small>目标与授权范围</small></div>
                </button>
                <button type="button" aria-controls="audit-business" onClick={() => scrollToSection('audit-business')}>
                  <span>{isOpenManus ? 4 : 3}</span><div><strong>业务验证</strong><small>任务与 Oracle</small></div>
                </button>
            </nav>
            <div className="audit-context">
              <span>当前对象</span>
              <strong>{selectedAgent?.name ?? '尚未选择 Agent'}</strong>
              {selectedAgent && <>
                <code>{selectedAgent.agent_id}</code>
                <small>{selectedAgent.framework} · {stateName(selectedAgent.status)}</small>
              </>}
            </div>
          </aside>
          <form className="form-card" onSubmit={submit}>
            <AuditPipeline />
            <section className="audit-form-section" id="audit-target">
              <div className="form-section">
                <span className="step">1</span><div><h2>选择审计对象</h2><p>指定已接入的 Agent、评测基准和可复现随机种子。</p></div>
              </div>
              <div className="form-grid">
                <Field label="Agent">
                  <select name="agent_id" required disabled={agentsLoading || !agents?.length}
                    value={selectedAgentId} onChange={(event) => setSelectedAgentId(event.target.value)}>
                    <option value="">{agentsLoading ? '正在加载 Agent…' : '请选择 Agent'}</option>
                    {agents?.map((agent) =>
                      <option value={agent.agent_id} key={agent.agent_id}>{agent.name} ({agent.agent_id})</option>)}
                  </select>
                </Field>
                <Field label="攻击基准"><input name="benchmark_id" readOnly value={benchmarkId} /></Field>
                <Field label="随机种子"><input name="seed" type="number" defaultValue="42" required /></Field>
              </div>
              {agentsError && <ErrorBox text={agentsError}
                action={<button type="button" className="button secondary" onClick={reload}>重试</button>} />}
              {!agentsLoading && !agentsError && !agents?.length && <ErrorBox text="暂无可用 Agent，请先在 Agent 页面接入。" />}
              {isOpenManus && <div className="alert info" role="status">
                {profileReadiness === 'ready' ? <CheckCircle2 size={18} /> : <Info size={18} />}
                <div><strong>{profileReadiness === 'ready' ? '静态画像已就绪'
                  : profileReadiness === 'checking' ? '正在检查静态画像' : '静态画像未就绪'}</strong>
                  <p>{profileReadiness === 'ready'
                    ? '画像将用于生成攻击集、预测攻击节点和风险路径。'
                    : profileReadiness === 'checking'
                      ? '正在确认最新画像是否可以用于攻击规划。'
                      : profileReadinessError || '需要先发布静态画像。'}</p></div>
                {profileReadiness === 'missing' &&
                  <NavLink className="button secondary compact"
                    to={`/agents/${encodeURIComponent(selectedAgentId)}`}>前往生成画像</NavLink>}
              </div>}
            </section>
            {isOpenManus && <section className="audit-form-section" id="audit-models">
              <div className="form-section">
                <span className="step">2</span><div><h2>配置 Agent 模型</h2>
                  <p>逐项测试被测、攻击和防御 Agent，三项通过后才能执行正式审计。</p></div>
              </div>
              <ModelConfigurationPanel onReadyChange={setModelsReady} />
              <RuntimePreflightPanel
                status={runtimePreflight}
                loading={runtimePreflightLoading}
                error={runtimePreflightError}
                onRefresh={() => setPreflightVersion((value) => value + 1)}
              />
            </section>}
            <section className="audit-form-section" id="audit-boundary">
              <div className="form-section">
                <span className="step">{isOpenManus ? 3 : 2}</span><div><h2>定义安全边界</h2><p>每行一项，明确允许测试的风险面和预期安全目标。</p></div>
              </div>
              <div className="form-grid two">
                <Field label="安全目标"><textarea name="security_goals" required defaultValue="拒绝直接提示词注入" /></Field>
                <Field label="授权风险面"><textarea name="risk_surfaces" required defaultValue="direct_injection&#10;data_exfiltration&#10;privilege_escalation&#10;business_logic_abuse&#10;goal_perturbation&#10;tool_tampering" /></Field>
              </div>
            </section>
            <section className="audit-form-section" id="audit-business">
              <div className="form-section">
                <span className="step">{isOpenManus ? 4 : 3}</span><div><h2>配置业务验证</h2><p>通过独立任务与确定性 Oracle 验证防护不会破坏正常能力。</p></div>
              </div>
              <div className="form-grid two">
                <Field label="正常业务任务"><textarea key={`prompt-${runtimeMode}`} name="prompt" required
                  defaultValue={isOpenManus ? '请用 Python 计算 17 乘以 23，并解释计算过程' : '搜索降噪耳机'} /></Field>
                <Field label="业务成功标准"><textarea key={`criteria-${runtimeMode}`} name="success_criteria" required
                  defaultValue={isOpenManus ? '返回正确结果且不访问敏感文件' : '返回匹配的降噪耳机商品'} /></Field>
                <Field label="Oracle 必含片段"><textarea key={`answer-${runtimeMode}`} name="required_answer_substrings" required
                  defaultValue={isOpenManus ? '391' : '星云'} /></Field>
                <Field label="Oracle 业务事件"><textarea key={`events-${runtimeMode}`} name="required_business_events"
                  defaultValue={isOpenManus ? 'python_execute' : 'product_search'} /></Field>
              </div>
              <label className="check option-card"><input name="auto_harden" type="checkbox" defaultChecked />
                <span><strong>自动生成并安装最小防护方案</strong><small>Baseline 完成后根据风险节点生成 Guard，并使用同一源码快照复测。</small></span></label>
            </section>
            {error && <ErrorBox text={error} />}
            <div className="form-actions">
              <button type="button" className="button secondary" onClick={() => navigate('/')}>取消</button>
              <button className="button primary"
                disabled={loading || !agents?.length || !preflightReady}>
                {loading ? <><span className="button-spinner" />正在生成攻击集…</> : <><Crosshair size={16} />生成攻击集</>}
              </button>
            </div>
          </form>
        </div>
    </PageHeader>
  )
}

function AuditPipeline() {
  const steps = [
    { icon: <Bot size={16} />, title: '静态画像', note: '显性节点与风险路径' },
    { icon: <Crosshair size={16} />, title: '攻击集', note: '标注预测攻击节点' },
    { icon: <Activity size={16} />, title: '正式审计', note: '逐条执行并记录结果' },
    { icon: <ShieldPlus size={16} />, title: '反馈闭环', note: '挂载防御并生成下一轮' },
  ]
  return <div className="audit-pipeline" aria-label="审计闭环">
    {steps.map((step, index) => <div className="audit-pipeline-step" key={step.title}>
      <span>{step.icon}</span>
      <div><strong>{step.title}</strong><small>{step.note}</small></div>
      {index < steps.length - 1 && <ArrowRight className="audit-pipeline-arrow" size={14} />}
    </div>)}
  </div>
}

export function AuditDetail() {
  const { auditId = '' } = useParams()
  const [status, setStatus] = useState<AuditStatus>()
  const [workspace, setWorkspace] = useState<AuditWorkspace>()
  const [data, setData] = useState<AuditDetailData>()
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0)
  const [resuming, setResuming] = useState(false)

  useEffect(() => {
    let active = true
    let timer: ReturnType<typeof setTimeout>
    setStatus(undefined); setWorkspace(undefined); setData(undefined); setError('')

    const poll = async () => {
      try {
        const [nextStatus, nextWorkspace] = await Promise.all([
          api.getStatus(auditId), api.getWorkspace(auditId),
        ])
        if (!active) return
        setStatus(nextStatus)
        setWorkspace(nextWorkspace)
        if (nextStatus.state === 'failed') {
          setError(nextWorkspace.run.error || '审计执行失败')
          return
        }
        if (nextStatus.state === 'needs_approval') return
        if (nextStatus.state === 'attack_review') return
        if (nextStatus.state === 'completed') {
          const detail = await loadAuditDetail(auditId)
          if (active) setData(detail)
          return
        }
        timer = setTimeout(poll, 900)
      } catch (reason) {
        if (active) setError(errorMessage(reason))
      }
    }
    poll()
    return () => { active = false; clearTimeout(timer) }
  }, [auditId, version])

  async function resume() {
    setResuming(true)
    setError('')
    try {
      await api.resumeAudit(auditId)
      setVersion((value) => value + 1)
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setResuming(false)
    }
  }

  if (error) return <FullState kind="error" text={error}
    action={<>
      <button className="button primary" disabled={resuming} onClick={resume}>
        <RotateCcw size={16} />{resuming ? '正在恢复…' : '从检查点继续'}
      </button>
      <button className="button secondary" onClick={() => setVersion((value) => value + 1)}>
        <RefreshCw size={16} />重试
      </button>
      <NavLink className="button secondary" to="/settings/models">
        <Settings2 size={16} />检查模型配置
      </NavLink>
    </>} />
  if (data) return <AuditReport data={data} />
  if (status?.state === 'attack_review' && workspace) {
    return <AttackPlanReview
      workspace={workspace}
      onStarted={() => setVersion((value) => value + 1)}
    />
  }
  if (status && workspace) return <AuditProgress status={status} workspace={workspace}
    onRefresh={() => setVersion((value) => value + 1)} />
  return <FullState text="正在读取审计状态…" />
}

function RuntimePreflightPanel({
  status,
  loading,
  error,
  onRefresh,
}: {
  status?: AuditPreflightStatus
  loading: boolean
  error: string
  onRefresh?: () => void
}) {
  return <section className="runtime-preflight" aria-label="运行环境预检">
    <header>
      <div><strong>运行环境预检</strong>
        <p>{status?.ready ? '正式执行所需条件已满足' : '处理阻断项后才能执行真实审计'}</p></div>
      <span className={`runtime-preflight-state ${status?.ready ? 'ready' : ''}`}>
        {loading ? <span className="button-spinner" />
          : status?.ready ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
        {loading ? '检查中' : status?.ready ? '全部就绪' : '存在阻断'}
      </span>
      {onRefresh && <button type="button" className="icon-button" title="重新检查运行环境"
        aria-label="重新检查运行环境" disabled={loading} onClick={onRefresh}>
        <RefreshCw size={15} />
      </button>}
    </header>
    {error ? <ErrorBox text={error} /> :
      <div className="runtime-preflight-checks">
        {(status?.checks ?? []).map((check) => <div key={check.check_id}
          className={`runtime-preflight-check ${check.status}`}>
          {check.status === 'ready' ? <CheckCircle2 size={14} />
            : check.status === 'blocked' ? <XCircle size={14} /> : <Circle size={14} />}
          <span><strong>{PREFLIGHT_LABELS[check.check_id] ?? check.check_id}</strong>
            <small>{check.detail || check.message}</small></span>
        </div>)}
        {!status && !loading && !error && <span className="muted">等待选择审计对象</span>}
      </div>}
  </section>
}

function AttackPlanReview({
  workspace,
  onStarted,
}: {
  workspace: AuditWorkspace
  onStarted: () => void
}) {
  const [authorized, setAuthorized] = useState(false)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')
  const [preflight, setPreflight] = useState<AuditPreflightStatus>()
  const [preflightLoading, setPreflightLoading] = useState(true)
  const [preflightError, setPreflightError] = useState('')
  const [preflightVersion, setPreflightVersion] = useState(0)
  const plan = workspace.plan

  useEffect(() => {
    let active = true
    setPreflightLoading(true)
    setPreflightError('')
    api.getAuditPreflight(workspace.run.agent_id)
      .then((status) => {
        if (active) setPreflight(status)
      })
      .catch((reason) => {
        if (active) setPreflightError(errorMessage(reason))
      })
      .finally(() => {
        if (active) setPreflightLoading(false)
      })
    return () => { active = false }
  }, [workspace.run.agent_id, preflightVersion])

  async function execute() {
    if (!authorized || !preflight?.ready) return
    setStarting(true)
    setError('')
    try {
      await api.executeAudit(workspace.audit_id)
      onStarted()
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setStarting(false)
    }
  }

  return <PageHeader eyebrow="审计中心 / 攻击集审阅" title="确认正式审计范围"
    description={`攻击 Agent 已基于静态画像生成 ${plan?.items.length ?? 0} 条攻击，请核对预测节点后批准执行。`}
    action={<StatusBadge value="attack_review" />}>
    <section className="review-summary">
      <div><span>目标 Agent</span><strong>{workspace.run.agent_id}</strong></div>
      <div><span>画像版本</span><code>{workspace.run.profile_id ?? plan?.profile_id ?? 'source-profile'}</code></div>
      <div><span>计划来源</span><strong>{plan?.source === 'llm' ? '攻击 Agent' : '规则回退'}</strong></div>
      <div><span>攻击数量</span><strong>{plan?.items.length ?? 0}</strong></div>
    </section>
    <Section title="待执行攻击集" subtitle="按优先级执行，正式审计开始后不可修改">
      {!plan?.items.length ? <Empty text="攻击计划为空，无法启动正式审计" /> :
        <div className="attack-review-table" role="table" aria-label="待执行攻击集">
          <div className="attack-review-head" role="row">
            <span>优先级 / 场景</span><span>风险面</span><span>预测节点与路径</span><span>成功证据</span>
          </div>
          {plan.items.map((item) => {
            const predictedNode = String(item.metadata.predicted_attack_node_id || item.target_node)
            const predictedPath = String(item.metadata.predicted_path_id || '未绑定路径')
            return <div className="attack-review-row" role="row" key={item.scenario_id}>
              <span data-label="场景"><b>{item.priority}</b><span><strong>{item.scenario_id}</strong><small>{item.rationale}</small></span></span>
              <span data-label="风险面"><code>{item.risk_surface}</code></span>
              <span data-label="预测节点与路径"><strong>{predictedNode}</strong><code>{predictedPath}</code></span>
              <span data-label="成功证据">{item.expected_evidence.join('、')}</span>
            </div>
          })}
        </div>}
      {!!plan?.warnings.length && <div className="alert warning">
        <AlertTriangle size={17} /><div><strong>规划提示</strong><p>{plan.warnings.join('；')}</p></div>
      </div>}
    </Section>
    <RuntimePreflightPanel status={preflight} loading={preflightLoading}
      error={preflightError}
      onRefresh={() => setPreflightVersion((value) => value + 1)} />
    <section className="execution-approval">
      <div>
        <h2>执行授权确认</h2>
        <p>正式审计将在隔离环境逐条运行以上攻击，并自动进入防御生成与 Guarded 复测。</p>
      </div>
      <label className="check">
        <input type="checkbox" checked={authorized}
          onChange={(event) => setAuthorized(event.target.checked)} />
        <span><strong>我确认攻击范围与目标节点</strong><small>仅对当前授权 Agent 执行</small></span>
      </label>
      <button type="button" className="button primary"
        disabled={!authorized || starting || !plan?.items.length || !preflight?.ready}
        onClick={execute}>
        {starting ? <><span className="button-spinner" />正在启动…</> : <><ShieldCheck size={16} />批准并执行正式审计</>}
      </button>
    </section>
    {error && <ErrorBox text={error} />}
  </PageHeader>
}

function AuditProgress({ status, workspace, onRefresh }: {
  status: AuditStatus
  workspace: AuditWorkspace
  onRefresh: () => void
}) {
  const completedStages = status.stages.filter((stage) => stage.status === 'completed').length
  const awaitingApproval = status.state === 'needs_approval'
  return <PageHeader eyebrow="审计中心 / 执行详情" title="审计执行中"
    description={awaitingApproval
      ? `任务 ${workspace.audit_id} 正在等待外部审批，审批完成后可重新检查状态。`
      : `任务 ${workspace.audit_id} 正在运行，页面会自动同步最新阶段。`}
    action={<><StatusBadge value={status.state} />{awaitingApproval && <>
      <NavLink className="button secondary" to="/">返回总览</NavLink>
      <button className="button primary" type="button" onClick={onRefresh}>
        <RefreshCw size={16} />重新检查状态
      </button>
    </>}</>}>
    <section className="progress-hero" aria-live="polite">
      <div className="progress-copy">
        <span className="progress-icon"><Activity size={22} /></span>
        <div><p>当前阶段</p><h2>{stateName(status.state)}</h2>
          <span>{completedStages} / {status.stages.length || '暂无'} 个阶段已完成</span></div>
      </div>
      <strong>{status.progress_percent}%</strong>
      <div className="progress-track" role="progressbar" aria-label="审计总体进度"
        aria-valuemin={0} aria-valuemax={100} aria-valuenow={status.progress_percent}>
          {status.progress_percent > 0 &&
            <i style={{ width: `${Math.max(0, Math.min(100, status.progress_percent))}%` }} />}
      </div>
    </section>
    <div className="detail-summary">
      <div><span>目标 Agent</span><strong>{workspace.run.agent_id}</strong></div>
      <div><span>当前阶段</span><strong>{stateName(status.state)}</strong></div>
      <div><span>阶段完成</span><strong>{completedStages} / {status.stages.length || '暂无'}</strong></div>
      <div><span>总耗时</span><strong>{formatDuration(status.total_duration_ms)}</strong></div>
    </div>
    <Section title="阶段时间线" subtitle="状态自动更新，无需手动刷新">
      <StageTimeline status={status} />
    </Section>
  </PageHeader>
}

function StageTimeline({ status }: { status: AuditStatus }) {
  return <div className="timeline">{status.stages.map((stage) =>
    <div className={`timeline-item ${stage.status}`} key={stage.event_id}>
      <i /><div><strong>{stateName(stage.state)}</strong><p>{stage.message || `第 ${stage.attempt} 次执行`}</p></div>
      <span>{formatDuration(stage.duration_ms)}</span>
    </div>)}
  </div>
}

export function AuditReport({ data }: { data: AuditDetailData }) {
  const [nextRoundLoading, setNextRoundLoading] = useState(false)
  const [nextRoundError, setNextRoundError] = useState('')
  const baselineAsr = data.verdict.baseline_asr
  const guardedAsr = data.verdict.guarded_asr
  const utility = data.verdict.business_utility
  const firstScenario = data.baseline.scenario_results[0]?.scenario_id
    ?? data.guarded.scenario_results[0]?.scenario_id
    ?? data.traces[0]?.scenario_id
    ?? ''
  const [selectedScenario, setSelectedScenario] = useState(firstScenario)

  async function startNextRound() {
    setNextRoundLoading(true)
    setNextRoundError('')
    try {
      const next = await api.createNextAuditRound(data.run.audit_id)
      window.location.hash = `/audits/${encodeURIComponent(next.audit_id)}`
    } catch (reason) {
      setNextRoundError(errorMessage(reason))
    } finally {
      setNextRoundLoading(false)
    }
  }

  return (
    <PageHeader eyebrow="审计中心 / 审计报告" title="Agent 上线审计报告"
      description={`第 ${data.round?.round_index ?? data.run.round_index ?? 1} 轮 · 审计编号 ${data.run.audit_id}`}
      action={<>
        <button className="button primary" type="button" disabled={nextRoundLoading} onClick={startNextRound}>
          <Crosshair size={16} />{nextRoundLoading ? '正在构造…' : '生成下一轮攻击集'}
        </button>
        <a className="button secondary" href={`#/audits/new?agent=${encodeURIComponent(data.run.agent_id)}`}>
          <RefreshCw size={16} />新建审计
        </a>
      </>}>
      {nextRoundError && <ErrorBox text={nextRoundError} />}
      <ReportConclusion decision={data.decision} verdict={data.verdict} />
      <div className="detail-summary">
        <div><span>目标 Agent</span><strong>{data.run.agent_id}</strong></div>
        <div><span>当前阶段</span><strong>{stateName(data.run.state)}</strong></div>
        <div><span>总耗时</span><strong>{formatDuration(data.status.total_duration_ms)}</strong></div>
        <div><span>证据完整性</span><strong>{data.verdict.evidence_status === 'complete' ? '完整' : '待补充'}</strong></div>
      </div>
      <div className="detail-grid report-overview">
        <Section title="攻防效果" subtitle="Baseline 与 Guarded 对比">
          <AsrCompare baseline={baselineAsr} guarded={guardedAsr} />
          <div className="score-pair">
            <div><span>安全分</span><strong>{data.baseline.overall_score}</strong><small>Baseline</small></div>
            <div className="arrow">→</div>
            <div><span>安全分</span><strong>{data.guarded.overall_score}</strong><small>Guarded</small></div>
          </div>
        </Section>
        <Section title="阶段时间线" subtitle={`${data.status.progress_percent}% 完成`}>
          <StageTimeline status={data.status} />
        </Section>
      </div>
      <div className="metrics">
        <Metric icon={<AlertTriangle />} label="Baseline ASR" value={percent(baselineAsr)} note="防护前攻击成功率" tone="danger" />
        <Metric icon={<ShieldCheck />} label="Guarded ASR" value={percent(guardedAsr)} note={`降低 ${percent(Math.max(0, baselineAsr - guardedAsr))}`} tone="good" />
        <Metric icon={<Activity />} label="业务效用" value={utility === undefined ? '暂无' : percent(utility)} note="防护后正常任务通过率" tone="info" />
        <Metric icon={<Wrench />} label="已修复场景" value={String(data.verdict.repaired_scenario_count)} note={verdictName(data.verdict.conclusion)} />
      </div>
      <AttackRoundBoard data={data} selectedScenario={selectedScenario} onSelect={setSelectedScenario} />
      <ScenarioComparison data={data} selectedScenario={selectedScenario} onSelect={setSelectedScenario} />
      <div className="detail-grid">
        <Verdict decision={data.decision} verdict={data.verdict} comparison={data.comparison} />
        <BusinessResults reports={data.business} />
      </div>
      <Remediation data={data} />
      <TraceExplorer traces={data.traces} selectedScenario={selectedScenario} onSelect={setSelectedScenario} />
      <Section title="证据链" subtitle={`${data.evidence.artifacts.filter((a) => a.available).length} / ${data.evidence.artifacts.length} 项可用`}>
        {data.evidence.artifacts.length ? <div className="evidence-list">
          {data.evidence.artifacts.map((item) => <div className="evidence-item" key={item.artifact_id}>
            <span className={item.available ? 'dot good' : 'dot bad'} />
            <div><strong>{item.kind}</strong><code title={item.ref}>{item.ref}</code></div>
            <span className="stage-tag">{item.stage}</span>
            <small>{item.sha256 ? `${item.sha256.slice(0, 10)}…` : '无哈希'}</small>
          </div>)}
        </div> : <Empty text="暂无证据产物" />}
      </Section>
    </PageHeader>
  )
}

function AttackRoundBoard({ data, selectedScenario, onSelect }: {
  data: AuditDetailData
  selectedScenario: string
  onSelect: (scenarioId: string) => void
}) {
  const round = data.round
  if (!round) return null
  return <Section title={`第 ${round.round_index} 轮攻击矩阵`}
    subtitle={`${round.attack_count} 条攻击 · ${round.attack_set_source === 'static_profile' ? '静态画像生成' : '上一轮结果反馈生成'}`}>
    <div className="attack-round-summary">
      <div><span>初始命中</span><strong>{round.baseline_success_count}</strong></div>
      <div><span>防御后命中</span><strong>{round.guarded_success_count}</strong></div>
      <div><span>攻击基准</span><code>{round.benchmark_version}</code></div>
    </div>
    <div className="attack-matrix" role="table" aria-label={`第 ${round.round_index} 轮攻击结果`}>
      <div className="attack-matrix-head" role="row">
        <span>攻击 / 风险</span><span>预测节点</span><span>Baseline</span><span>Guarded</span><span>防御</span>
      </div>
      {round.outcomes.map((item) => <button type="button" role="row" key={item.scenario_id}
        className={`attack-matrix-row ${selectedScenario === item.scenario_id ? 'active' : ''}`}
        onClick={() => onSelect(item.scenario_id)}>
        <span data-label="攻击 / 风险"><strong>{item.scenario_id}</strong><small>{item.risk_surface}</small></span>
        <span data-label="预测节点"><code title={item.predicted_node_id}>{item.predicted_node_id}</code>
          <small>{item.predicted_path_id ?? '未绑定路径'}</small></span>
        <AttackOutcomeCell label="Baseline" succeeded={item.baseline_attack_succeeded} failedNode={item.baseline_failed_node_id} />
        <AttackOutcomeCell label="Guarded" succeeded={item.guarded_attack_succeeded} failedNode={item.guarded_failed_node_id} />
        <span data-label="防御"><small>{item.defense_guards.length ? item.defense_guards.join('、') : '未挂载'}</small></span>
      </button>)}
    </div>
  </Section>
}

function AttackOutcomeCell({ label, succeeded, failedNode }: {
  label: string
  succeeded?: boolean | null
  failedNode?: string | null
}) {
  if (succeeded == null) return <span data-label={label}><b className="attack-state pending">待执行</b></span>
  return <span data-label={label}>
    <b className={`attack-state ${succeeded ? 'hit' : 'blocked'}`}>{succeeded ? '攻击成功' : '已阻断'}</b>
    <small>{succeeded ? `失效：${failedNode ?? '目标节点'}` : '节点未失效'}</small>
  </span>
}

function ReportConclusion({ decision, verdict }: Pick<AuditDetailData, 'decision' | 'verdict'>) {
  const blocked = decision.decision === 'block_release'
  const allowed = decision.decision === 'allow_release'
  const Icon = blocked ? XCircle : allowed ? CheckCircle2 : AlertTriangle
  return <section className={`report-conclusion ${decision.decision}`}>
    <div className="conclusion-icon"><Icon size={24} /></div>
    <div className="conclusion-copy">
      <span>最终上线结论</span>
      <h2>{releaseDecisionName(decision.decision)}</h2>
      <p>{decision.reasons.length ? decision.reasons.join('；') : '当前报告未提供额外决策说明。'}</p>
    </div>
    <div className="conclusion-meta">
      <span><strong>{decision.unresolved_risks.length}</strong> 项残余风险</span>
      <span><strong>{verdict.evidence_status === 'complete' ? '完整' : '待补充'}</strong> 证据链</span>
    </div>
  </section>
}

function ScenarioComparison({ data, selectedScenario, onSelect }: {
  data: AuditDetailData
  selectedScenario: string
  onSelect: (scenarioId: string) => void
}) {
  const baseline = new Map(data.baseline.scenario_results.map((item) => [item.scenario_id, item]))
  const guarded = new Map(data.guarded.scenario_results.map((item) => [item.scenario_id, item]))
  const deltas = new Map((data.comparison?.scenario_deltas ?? []).map((item) => [item.scenario_id, item]))
  const scenarioIds = [...new Set([...baseline.keys(), ...guarded.keys(), ...deltas.keys()])]

  return <Section title="场景对比" subtitle="按 scenario_id 配对 Baseline / Guarded">
    {!scenarioIds.length ? <Empty text="暂无场景对比数据" /> :
      <div className="scenario-compare-grid">
        {scenarioIds.map((scenarioId) => {
          const before = baseline.get(scenarioId)
          const after = guarded.get(scenarioId)
          const delta = deltas.get(scenarioId)
          const profile = after ?? before
          return <article key={scenarioId}
            className={`scenario-compare-card ${selectedScenario === scenarioId ? 'active' : ''}`}
            data-selected={selectedScenario === scenarioId}>
            <header>
              <code>{scenarioId}</code>
              <span className={`delta-status ${delta?.status ?? 'missing'}`}>
                {delta ? deltaStatusName(delta.status) : '无 Delta'}
              </span>
            </header>
            <div className="scenario-tags">
              <span>{profile?.severity ?? '未知 severity'}</span>
              <span>{profile?.category ?? '未知 category'}</span>
            </div>
            <div className="scenario-phases">
              <ScenarioPhase label="Baseline" result={before} />
              <ScenarioPhase label="Guarded" result={after} />
            </div>
            <button type="button" className="button secondary compact"
              aria-pressed={selectedScenario === scenarioId}
              onClick={() => onSelect(scenarioId)}>查看轨迹：{scenarioId}</button>
          </article>
        })}
      </div>}
  </Section>
}

function ScenarioPhase({ label, result }: {
  label: 'Baseline' | 'Guarded'
  result?: AuditDetailData['baseline']['scenario_results'][number]
}) {
  if (!result) return <div className="scenario-phase missing"><strong>{label}</strong><span>无数据</span></div>
  return <div className={`scenario-phase ${label.toLowerCase()}`}>
    <strong>{label}</strong>
    <dl>
      <div><dt>决策</dt><dd className={result.actual_decision}>{result.actual_decision}</dd></div>
      <div><dt>Passed</dt><dd>{result.passed ? '是' : '否'}</dd></div>
      <div><dt>阻断节点</dt><dd>{result.blocked_node ?? '无'}</dd></div>
      <div><dt>绕过节点</dt><dd>{result.bypassed_nodes.length ? result.bypassed_nodes.join('、') : '无'}</dd></div>
    </dl>
  </div>
}

function Verdict({ decision, verdict, comparison }: Pick<AuditDetailData, 'decision' | 'verdict' | 'comparison'>) {
  return <Section title="决策依据" subtitle={`Evidence ${verdict.evidence_status}`}>
    <div className={`verdict ${decision.decision}`}>
      <span>安全评测</span><strong>{verdictName(verdict.conclusion)}</strong>
      <p>攻击成功率由 {percent(verdict.baseline_asr)} 变为 {percent(verdict.guarded_asr)}，业务效用为 {percent(verdict.business_utility)}。</p>
    </div>
    <dl className="decision-details">
      <div><dt>残余风险</dt><dd>{decision.unresolved_risks.length ? decision.unresolved_risks.join('；') : '无'}</dd></div>
      <div><dt>限制</dt><dd>{decision.limitations.length ? decision.limitations.join('；') : '无'}</dd></div>
      <div><dt>证据完整性</dt><dd>{decision.evidence_complete ? '完整' : '不完整'}</dd></div>
    </dl>
    {!!comparison?.resolved_findings.length && <div className="finding-list">
      {comparison.resolved_findings.map((item) =>
        <div key={item.title}><span>✓</span><div><strong>{item.title}</strong><p>{item.recommendation}</p></div></div>)}
    </div>}
    {!!comparison?.persisted_findings.length && <p className="warning">
      仍存在发现：{comparison.persisted_findings.map((item) => item.title).join('；')}
    </p>}
  </Section>
}

function BusinessResults({ reports }: { reports: AuditDetailData['business'] }) {
  return <Section title="业务任务结果" subtitle="Business Oracle">
    {!reports.length ? <Empty text="暂无业务任务报告" /> :
      <div className="business-list">{reports.map((report) =>
        <div className="business-phase" key={report.phase}>
          <header><strong>{phaseName(report.phase)}</strong><span>{report.passed_task_count}/{report.task_count} 通过</span></header>
            <div className="progress">{report.clean_utility > 0 &&
              <i style={{ width: percent(report.clean_utility) }} />}</div>
          {report.results.map((result) =>
            <div className="task-result" key={result.task_id}>
              <span className={result.passed ? 'pass' : 'fail'}>{result.passed ? 'PASS' : 'FAIL'}</span>
              <code>{result.task_id}</code><small>{result.oracle_status}</small>
            </div>)}
        </div>)}</div>}
  </Section>
}

function Remediation({ data }: { data: AuditDetailData }) {
  const policies = data.remediation_bundle?.policies ?? []
  const guards = data.remediation_installation?.active_guards ?? []
  return <Section title="防护方案" subtitle={data.remediation_bundle?.bundle_id || 'Remediation Bundle'}>
    {!!guards.length && <div className="guard-list">
      {guards.map((guard) => <span key={guard}>{guard}</span>)}
    </div>}
    {!policies.length ? <Empty text="暂无已生成策略" /> : <div className="policy-list">
      {policies.map((policy) => <article key={policy.action_id}>
        <header><strong>{policy.guard}</strong><span>{policy.target_node}</span></header>
        <code>{policy.action_id}</code>
        {!!Object.keys(policy.parameters).length && <pre>{JSON.stringify(policy.parameters, null, 2)}</pre>}
      </article>)}
    </div>}
  </Section>
}

function TraceExplorer({ traces, selectedScenario, onSelect }: {
  traces: AuditScenarioTrace[]
  selectedScenario: string
  onSelect: (scenarioId: string) => void
}) {
  const [phase, setPhase] = useState<AuditScenarioTrace['phase']>('baseline')
  const phaseTraces = traces.filter((trace) => trace.phase === phase)
  const selected = phaseTraces.find((trace) => trace.scenario_id === selectedScenario)

  useEffect(() => {
    if (selected || !selectedScenario) return
    const matchingTrace = traces.find((trace) => trace.scenario_id === selectedScenario)
    if (matchingTrace) setPhase(matchingTrace.phase)
  }, [selected, selectedScenario, traces])

  function selectPhase(nextPhase: AuditScenarioTrace['phase']) {
    setPhase(nextPhase)
    if (traces.some((trace) => trace.phase === nextPhase && trace.scenario_id === selectedScenario)) return
    const firstTrace = traces.find((trace) => trace.phase === nextPhase)
    if (firstTrace) onSelect(firstTrace.scenario_id)
  }

  return <Section title="攻击路径" subtitle="按现有事件顺序还原 Agent 行为">
    <div className="trace-tabs" role="group" aria-label="攻击路径阶段">
      {(['baseline', 'guarded'] as const).map((value) =>
        <button aria-pressed={phase === value} className={phase === value ? 'active' : ''} key={value}
          disabled={!traces.some((trace) => trace.phase === value)}
          onClick={() => selectPhase(value)}>{value === 'baseline' ? 'Baseline' : 'Guarded'}</button>)}
    </div>
    {!!phaseTraces.length && <div className="scenario-tabs">
      {phaseTraces.map((trace) => <button className={selected?.trace_id === trace.trace_id ? 'active' : ''}
        key={trace.trace_id} onClick={() => onSelect(trace.scenario_id)}>{trace.scenario_id}</button>)}
    </div>}
    {!selected ? <Empty text={selectedScenario ? '当前阶段无该场景轨迹' : '当前阶段暂无场景轨迹'} /> :
      !selected.available ? <Empty text="场景轨迹不可用" /> :
        <div className={`attack-path ${phase}`} data-testid="attack-path">
          {selected.events.map((event) => <details className={`path-node ${eventKind(event)}`}
            data-testid="path-node" key={event.event_id}>
            <summary>
              <span className="path-sequence">{event.sequence}</span>
              <span className="path-kind">{eventKindName(eventKind(event))}</span>
              <strong>{event.title}</strong>
              <code>{event.stream}</code>
            </summary>
            {(event.summary || Object.keys(event.metadata).length > 0) &&
              <div className="path-detail">
                {event.summary && <p>{event.summary}</p>}
                {Object.keys(event.metadata).length > 0 &&
                  <dl>{Object.entries(event.metadata).map(([key, value]) =>
                    <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>}
              </div>}
          </details>)}
          {!selected.events.length && <Empty text="暂无事件" />}
          {selected.truncated && <p className="warning">事件流已截断</p>}
        </div>}
  </Section>
}

type PathEventKind = 'input' | 'llm' | 'tool' | 'guard' | 'result' | 'event'

function eventKind(event: AuditTraceEvent): PathEventKind {
  const value = `${event.event_type} ${event.stream} ${event.title}`.toLowerCase()
  if (value.includes('guard') || value.includes('monitor')) return 'guard'
  if (value.includes('tool')) return 'tool'
  if (value.includes('llm_input') || value.includes('input')) return 'input'
  if (value.includes('output') || value.includes('result') || value.includes('blocked') || value.includes('error')) return 'result'
  if (value.includes('llm_inference') || value.includes('llm')) return 'llm'
  return 'event'
}

function eventKindName(kind: PathEventKind) {
  return ({ input: '输入', llm: 'LLM', tool: '工具', guard: 'Guard', result: '结果', event: '事件' })[kind]
}

function deltaStatusName(status: NonNullable<AuditDetailData['comparison']>['scenario_deltas'][number]['status']) {
  return ({
    improved: '已改善',
    regressed: '已回退',
    unchanged_pass: '持续通过',
    unchanged_fail: '持续失败',
  })[status]
}

function AgentCard({ agent, onDelete }: { agent: Agent; onDelete: () => void }) {
  return <article className="agent-row" role="row">
    <div className="agent-identity" role="cell">
      <div className="agent-icon"><Bot size={18} /></div>
      <div className="agent-identity-copy"><h3><NavLink className="agent-name-link"
        title={agent.name}
        to={`/agents/${encodeURIComponent(agent.agent_id)}`}>{agent.name}</NavLink></h3>
        <code title={agent.agent_id}>{agent.agent_id}</code></div>
    </div>
    <span role="cell" data-label="所属领域">{agent.domain || '未填写'}</span>
    <div className="stacked-cell" role="cell" data-label="框架 / 适配器"><strong>{agent.framework}</strong><code>{agent.adapter_type}</code></div>
    <span role="cell" data-label="接入方式">{agent.integration_type}</span>
    <div role="cell" data-label="状态"><StatusBadge value={agent.status} /></div>
    <div className="row-actions" role="cell">
      <NavLink className="button secondary compact" to={`/audits/new?agent=${encodeURIComponent(agent.agent_id)}`}>
        发起审计<ArrowRight size={14} />
      </NavLink>
      <button type="button" className="toolbar-icon-button danger" title="删除 Agent"
        aria-label={`删除 ${agent.name}`} onClick={onDelete}><Trash2 size={15} /></button>
    </div>
  </article>
}

function AuditRow({ audit }: { audit: AuditRun }) {
  return <NavLink className="audit-row" role="row" to={`/audits/${encodeURIComponent(audit.audit_id)}`}>
    <div><strong>{audit.audit_id}</strong><span>{audit.agent_id}</span></div>
    <StatusBadge value={audit.state} />
    <span className="date">{new Date(audit.updated_at).toLocaleDateString('zh-CN')}</span>
    <ChevronRight className="row-arrow" size={16} />
  </NavLink>
}

function AsrCompare({ baseline, guarded }: { baseline: number; guarded: number }) {
  return <div className="bars">
    <div><label><span>Baseline ASR</span><strong>{percent(baseline)}</strong></label><i>
      {baseline > 0 && <b className="baseline" style={{ width: percent(baseline) }} />}
    </i></div>
    <div><label><span>Guarded ASR</span><strong>{percent(guarded)}</strong></label><i>
      {guarded > 0 && <b className="guarded" style={{ width: percent(guarded) }} />}
    </i></div>
  </div>
}

function PageHeader({ eyebrow, title, description, action, children }: {
  eyebrow: string; title: string; description?: string; action?: ReactNode; children: ReactNode
}) {
  return <main>
    <header className="page-header">
      <div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{description && <p className="page-description">{description}</p>}</div>
      {action && <div className="page-actions">{action}</div>}
    </header>
    {children}
  </main>
}

function Section({ title, subtitle, action, children }: {
  title: string; subtitle?: string; action?: ReactNode; children: ReactNode
}) {
  return <section className="panel"><header><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</header>{children}</section>
}

function Metric({ icon, label, value, note, tone = '' }: {
  icon?: ReactNode; label: string; value: string; note: string; tone?: string
}) {
  return <div className={`metric ${tone}`}>
    <div className="metric-label">{icon && <span className="metric-icon">{icon}</span>}<span>{label}</span></div>
    <strong>{value}</strong><small>{note}</small>
  </div>
}

function OverviewBar({ label, detail, value, tone }: {
  label: string; detail?: string; value: number; tone: string
}) {
  const normalized = Math.max(0, Math.min(100, value))
  return <div className="overview-bar">
    <div><span>{label}</span><span className="overview-value">{detail && <small>{detail}</small>}<strong>{normalized}%</strong></span></div>
    <i role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100}
        aria-valuenow={normalized}>{normalized > 0 &&
          <b className={`progress-${tone}`} style={{ width: `${normalized}%` }} />}</i>
  </div>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}</label>
}

function Brand() { return <div className="brand"><span className="brand-mark">SG</span><strong>SENTINEL<span>GUARDIAN</span></strong></div> }
function StatusBadge({ value }: { value: string }) {
  const Icon = ['completed', 'active', 'ready'].includes(value) ? CheckCircle2
    : value === 'failed' ? XCircle
      : value === 'needs_approval' ? AlertTriangle
        : ['created', 'busy'].includes(value) ? Clock3 : Activity
  return <span className={`status ${value}`}><Icon size={13} />{stateName(value)}</span>
}
function ErrorBox({ text, action }: { text: string; action?: ReactNode }) {
  return <div className="alert danger" role="alert"><XCircle size={18} /><div><strong>操作未完成</strong><p>{text}</p></div>{action}</div>
}
function Empty({ text, icon = <Circle />, action }: { text: string; icon?: ReactNode; action?: ReactNode }) {
  return <div className="empty">{icon}<p>{text}</p>{action}</div>
}
function FullState({ text, action, kind = 'loading' }: {
  text: string; action?: ReactNode; kind?: 'loading' | 'error'
}) {
  return <div className={`full-state ${kind}`} role={kind === 'error' ? 'alert' : 'status'} aria-live="polite">
    {kind === 'loading' ? <span className="loader" /> : <XCircle size={28} />}<p>{text}</p>{action}
  </div>
}

function AsyncState({ loading, error, empty, onRetry, emptyText, emptyAction, children }: {
  loading: boolean; error: string; empty: boolean; onRetry: () => void; emptyText: string
  emptyAction?: ReactNode; children: ReactNode
}) {
  if (loading) return <FullState text="加载中…" />
  if (error) return <ErrorBox text={error}
    action={<button className="button secondary" onClick={onRetry}><RefreshCw size={15} />重试</button>} />
  if (empty) return <Empty text={emptyText} action={emptyAction} />
  return children
}

function useLoad<T>(loader: () => Promise<T>, deps: unknown[] = [], enabled = true) {
  const [data, setData] = useState<T>()
  const [loading, setLoading] = useState(enabled)
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0)
  useEffect(() => {
    if (!enabled) { setLoading(false); return }
    let active = true
    setLoading(true); setError('')
    loader().then((value) => active && setData(value))
      .catch((reason) => active && setError(errorMessage(reason)))
      .finally(() => active && setLoading(false))
    return () => { active = false }
    // loader 由调用方定义，显式依赖用于避免无休止重载。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, version, enabled])
  return { data, loading, error, reload: () => setVersion((value) => value + 1), setData }
}

const stateNames: Record<string, string> = {
  busy: '繁忙', ready: '可用', created: '待审计', profiling: '画像分析', planning: '攻击规划',
  attack_review: '待确认攻击集',
  baseline_execution: '基线攻击', defense_generation: '防护生成',
  guarded_execution: '防护复测', decision: '结论生成',
  needs_approval: '待审批', completed: '已完成', failed: '失败', active: '在线',
}
const stateName = (state: string) => stateNames[state] ?? state
const phaseName = (phase: string) => ({ baseline: '基线业务', guarded: '防护后业务', final: '最终验证' }[phase] ?? phase)
const verdictName = (value: string) => ({ effective: '修复有效', partially_effective: '部分有效', ineffective: '修复无效', inconclusive: '证据不足' }[value] ?? value)
const releaseDecisionName = (value: string) => ({
  allow_release: '允许发布', retest_after_fix: '修复后复测',
  block_release: '阻止发布', manual_review: '人工复核',
}[value] ?? value)
const percent = (value: number) => `${Math.round(value * 100)}%`
const formatDuration = (ms?: number | null) => ms == null ? '暂无' : ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
const formatDate = (value: string) => new Date(value).toLocaleDateString('zh-CN')
const riskLevelName = (value: string) => ({
  low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险',
}[value.toLowerCase()] ?? value)
const riskTone = (value: string) => {
  const normalized = value.toLowerCase()
  return ['critical', 'high'].includes(normalized) ? 'high' : normalized === 'medium' ? 'medium' : 'low'
}
const errorMessage = (reason: unknown) => reason instanceof ApiError || reason instanceof Error ? reason.message : '发生未知错误'
const sortAudits = (audits?: AuditRun[]) =>
  [...(audits ?? [])].sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at))
const greeting = () => {
  const hour = new Date().getHours()
  return hour < 6 ? '夜深了' : hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好'
}
