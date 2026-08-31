import type {
  Agent, AgentImageImportResult, AgentImageUploadInput, AgentProfile, AuditDetail, AuditRun, AuditStatus,
  AuditPreflightStatus, AuditTaskInput, AuthResponse, AuditWorkspace, BusinessReport, EvaluationVerdict,
  Evidence, ImageAgentProfile, ImageProfileCreation, ImageProfileStatus,
  ModelRuntimeConfiguration, ModelRuntimeRole, ModelRuntimeStatus,
  OpenManusRuntimeConfiguration, OpenManusRuntimeStatus, User,
} from './types'

const TOKEN_KEY = 'sentinel.auth.token'
const unauthorizedListeners = new Set<() => void>()

export function onUnauthorized(listener: () => void) {
  unauthorizedListeners.add(listener)
  return () => { unauthorizedListeners.delete(listener) }
}

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY) ?? sessionStorage.getItem(TOKEN_KEY),
  set(token: string, persistent = false) {
    this.clear()
    ;(persistent ? localStorage : sessionStorage).setItem(TOKEN_KEY, token)
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(TOKEN_KEY)
  },
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = tokenStore.get()
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const detail = body.detail
    const message = typeof detail === 'string'
      ? detail
      : detail?.message ?? body.message ?? `请求失败 (${response.status})`
    if (response.status === 401) {
      tokenStore.clear()
      unauthorizedListeners.forEach((listener) => listener())
    }
    throw new ApiError(response.status, message)
  }
  return response.status === 204 ? undefined as T : response.json()
}

const auditPath = (id: string, suffix = '') =>
  `/v1/audits/${encodeURIComponent(id)}${suffix}`

export const api = {
  health: () => request<{ status: string }>('/v1/health'),
  login: (account: string, password: string, remember_me: boolean) =>
    request<AuthResponse>('/v1/auth/login', {
      method: 'POST', body: JSON.stringify({ account, password, remember_me }),
    }),
  register: (username: string, email: string, password: string) =>
    request<AuthResponse>('/v1/auth/register', {
      method: 'POST', body: JSON.stringify({ username, email, password }),
    }),
  me: () => request<{ user: User }>('/v1/auth/me'),
  logout: () => request<void>('/v1/auth/logout', { method: 'POST' }),
  listAgents: () => request<Agent[]>('/v1/agents'),
  deleteAgent: (id: string) =>
    request<{ schema_version: 'agent-delete-response-v0.1'; agent_id: string; deleted: boolean }>(
      `/v1/agents/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    ),
  registerDemoAgent: () => request<Agent>('/v1/demo/agents/ecommerce', { method: 'POST' }),
  uploadAgentImage: (
    input: AgentImageUploadInput,
    onProgress: (percent: number) => void,
  ) => new Promise<AgentImageImportResult>((resolve, reject) => {
    const params = new URLSearchParams({
      domain: input.domain,
      expected_frameworks: input.expectedFrameworks.join(','),
    })
    if (input.agentId) params.set('agent_id', input.agentId)
    if (input.name) params.set('name', input.name)
    const probeModule = input.probeModule?.trim()
    if (probeModule) params.set('probe_module', probeModule)
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `/v1/agents/import-image?${params.toString()}`)
    xhr.setRequestHeader('Content-Type', 'application/x-tar')
    const token = tokenStore.get()
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100))
    }
    xhr.onerror = () => reject(new Error('镜像上传失败，请检查服务连接'))
    xhr.onload = () => {
      const body = JSON.parse(xhr.responseText || '{}')
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(100)
        resolve(body as AgentImageImportResult)
        return
      }
      if (xhr.status === 401) {
        tokenStore.clear()
        unauthorizedListeners.forEach((listener) => listener())
      }
      const detail = body.detail
      reject(new ApiError(
        xhr.status,
        typeof detail === 'string'
          ? detail
          : detail?.message ?? body.message ?? `请求失败 (${xhr.status})`,
      ))
    }
    xhr.send(input.file)
  }),
  listAudits: () => request<AuditRun[]>('/v1/audits'),
  createAudit: (input: AuditTaskInput) =>
    request<AuditRun>('/v1/audits?prepare_only=true', { method: 'POST', body: JSON.stringify(input) }),
  executeAudit: (id: string) =>
    request<AuditRun>(auditPath(id, '/execute?background=true'), { method: 'POST' }),
  resumeAudit: (id: string) =>
    request<AuditRun>(auditPath(id, '/resume?background=true'), { method: 'POST' }),
  createNextAuditRound: (id: string) =>
    request<AuditRun>(auditPath(id, '/next-round?prepare_only=true'), { method: 'POST' }),
  getOpenManusRuntimeStatus: () =>
    request<OpenManusRuntimeStatus>('/v1/runtime/openmanus/status'),
  configureOpenManusRuntime: (configuration: OpenManusRuntimeConfiguration) =>
    request<OpenManusRuntimeStatus>('/v1/runtime/openmanus/config', {
      method: 'POST',
      body: JSON.stringify(configuration),
    }),
  getModelRuntimeStatuses: () =>
    request<ModelRuntimeStatus[]>('/v1/runtime/models/status'),
  getAuditPreflight: (agentId: string) =>
    request<AuditPreflightStatus>(
      `/v1/runtime/audit-preflight/${encodeURIComponent(agentId)}`,
    ),
  testModelRuntimeConfiguration: (
    role: ModelRuntimeRole,
    configuration: ModelRuntimeConfiguration,
  ) =>
    request<ModelRuntimeStatus>(`/v1/runtime/models/${encodeURIComponent(role)}/test`, {
      method: 'POST',
      body: JSON.stringify(configuration),
    }),
  getAgent: (id: string) => request<Agent>(`/v1/agents/${encodeURIComponent(id)}`),
  getAgentProfile: (id: string) =>
    request<AgentProfile>(`/v1/agents/${encodeURIComponent(id)}/profile`),
  createAgentProfile: (id: string) =>
    request<ImageProfileCreation>(`/v1/agents/${encodeURIComponent(id)}/profiles`, { method: 'POST' }),
  getLatestAgentProfile: (id: string) =>
    request<ImageAgentProfile>(`/v1/agents/${encodeURIComponent(id)}/profiles/latest`),
  getAgentProfileStatus: (id: string, analysisId: string, signal?: AbortSignal) =>
    request<ImageProfileStatus>(
      `/v1/agents/${encodeURIComponent(id)}/profiles/${encodeURIComponent(analysisId)}/status`,
      { signal },
    ),
  retryAgentProfile: (id: string, analysisId: string) =>
    request<ImageProfileStatus>(
      `/v1/agents/${encodeURIComponent(id)}/profiles/${encodeURIComponent(analysisId)}/retry`,
      { method: 'POST' },
    ),
  getAudit: (id: string) => request<AuditRun>(auditPath(id)),
  getStatus: (id: string) => request<AuditStatus>(auditPath(id, '/status')),
  getPlan: (id: string) => request<Record<string, unknown>>(auditPath(id, '/plan')),
  getVerdict: (id: string) => request<EvaluationVerdict>(auditPath(id, '/verdict')),
  getEvidence: (id: string) => request<Evidence>(auditPath(id, '/evidence')),
  getBusiness: (id: string, phase: BusinessReport['phase']) =>
    request<BusinessReport>(auditPath(id, `/business/${phase}`)),
  getWorkspace: (id: string) => request<AuditWorkspace>(auditPath(id, '/workspace')),
}

export async function loadAuditDetail(id: string): Promise<AuditDetail> {
  const [run, status, plan, verdict, evidence, workspace, ...business] =
    await Promise.all([
      api.getAudit(id),
      api.getStatus(id),
      api.getPlan(id),
      api.getVerdict(id).catch((reason) => {
        if (reason instanceof ApiError && reason.status === 404) return null
        throw reason
      }),
      api.getEvidence(id),
      api.getWorkspace(id),
      ...(['baseline', 'guarded', 'final'] as const).map((phase) =>
        api.getBusiness(id, phase).catch((reason) => {
          if (reason instanceof ApiError && reason.status === 404) return null
          throw reason
        })),
    ])
  if (!workspace.baseline_report || !workspace.guarded_report) {
    throw new Error('已完成审计缺少防护前或防护后报告')
  }
  if (!workspace.decision) {
    throw new Error('已完成审计缺少正式决策')
  }
  const businessReports = business.filter(
    (item): item is BusinessReport => item !== null,
  )
  const resolvedVerdict: EvaluationVerdict = verdict ?? {
    audit_id: id,
    agent_id: workspace.run.agent_id,
    baseline_asr: Number(workspace.baseline_report.attack_success_rate) || 0,
    guarded_asr: Number(workspace.guarded_report.attack_success_rate) || 0,
    business_utility: businessReports.find(
      (item) => item.phase === 'final',
    )?.clean_utility ?? Math.max(
      0,
      1 - (Number(workspace.guarded_report.false_positive_rate) || 0),
    ),
    repaired_scenario_count: workspace.comparison?.scenario_deltas.filter(
      (item) => item.status === 'improved',
    ).length ?? 0,
    conclusion: workspace.decision.decision === 'allow_release'
      ? 'effective'
      : workspace.decision.decision === 'retest_after_fix'
        ? 'partially_effective'
        : workspace.decision.decision === 'block_release'
          ? 'ineffective'
          : 'inconclusive',
    evidence_status: workspace.decision.evidence_complete
      ? 'complete'
      : 'incomplete',
  }
  return {
    run, status, plan, verdict: resolvedVerdict, evidence,
    baseline: workspace.baseline_report,
    guarded: workspace.guarded_report,
    comparison: workspace.comparison,
    decision: workspace.decision,
    business: businessReports,
    remediation_bundle: workspace.remediation_bundle,
    remediation_installation: workspace.remediation_installation,
    traces: workspace.traces ?? [],
    round: workspace.round,
  }
}
