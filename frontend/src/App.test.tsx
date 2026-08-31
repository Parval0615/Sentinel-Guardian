import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import App, {
  AgentProfilePage, AgentProfileReport, Agents, AuditDetail, AuditRecords, AuditReport, ModelSettings, NewAudit,
} from './App'
import { AgentProfileGraph } from './AgentProfileGraph'
import { api, tokenStore } from './api'
import type {
  Agent, AgentProfile, AuditDetail as AuditDetailData, AuditPreflightStatus, AuditRun, AuditStatus, AuditWorkspace,
  AgentImageImportResult, ImageAgentProfile, ImageProfileStatus,
} from './types'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, 'ResizeObserver', {
  configurable: true,
  value: ResizeObserverStub,
})

const agent: Agent = {
  agent_id: 'ecommerce_customer_guide',
  name: 'E-commerce Customer Guide Agent',
  domain: 'ecommerce',
  framework: 'local-sdk',
  adapter_type: 'ecommerce_demo',
  integration_type: 'source',
  status: 'ready',
  created_at: '2026-01-01T00:00:00Z',
}

const openmanusAgent: Agent = {
  agent_id: 'openmanus_official',
  name: 'OpenManus Official',
  domain: 'general',
  framework: 'OpenManus',
  adapter_type: 'openmanus',
  integration_type: 'source',
  status: 'ready',
  created_at: '2026-01-01T00:00:00Z',
}

const readyPreflight = (agentId: string): AuditPreflightStatus => ({
  agent_id: agentId,
  adapter_type: agentId === openmanusAgent.agent_id ? 'openmanus' : 'ecommerce_demo',
  ready: true,
  checked_at: '2026-01-01T00:00:00Z',
  checks: [{
    check_id: 'agent_registration',
    status: 'ready',
    message: 'Agent registration is available.',
    detail: agentId,
  }],
})

const agentProfile: AgentProfile = {
  profile_id: 'profile-ecommerce',
  tenant_id: 'tenant-1',
  agent_id: agent.agent_id,
  agent_type: 'ecommerce_rag',
  created_at: '2026-01-01T00:00:00Z',
  generated_at: '2026-01-02T00:00:00Z',
  nodes: [{
    node_id: 'product_search',
    node_type: 'tool',
    required: true,
    critical: true,
    risk_surfaces: ['tool_tampering'],
    defenses: ['tool_guard'],
  }],
  tools: [{
    name: 'product_search',
    risk_level: 'medium',
    description: '搜索商品目录',
  }],
  rag: {},
  memory: {},
  data_boundary: {},
  risk_surface: ['tool_tampering'],
}

const imageProfile: ImageAgentProfile = {
  schema_version: 'agent-profile-v0.2',
  profile_id: 'profile:image:ecommerce',
  tenant_id: 'tenant-1',
  agent_id: agent.agent_id,
  generated_at: '2026-08-25T08:00:00Z',
  image: {
    digest: `sha256:${'a'.repeat(64)}`,
    os: 'linux',
    architecture: 'arm64',
    created_at: '2026-08-24T08:00:00Z',
    entrypoint: ['python', '-m', 'shop_agent'],
    command: ['serve'],
    working_directory: '/app',
    environment_variables: ['MODEL_NAME', 'API_KEY'],
    layer_digests: [`sha256:${'d'.repeat(64)}`],
    evidence_refs: ['ev:static'],
    confidence: 0.98,
    verification_status: 'verified',
  },
  analysis: {
    schema_version: 'image-analysis-status-v0.1',
    analysis_id: 'analysis-1',
    agent_id: agent.agent_id,
    image_digest: `sha256:${'a'.repeat(64)}`,
    status: 'partial',
    stages: [
      'inventory', 'unpack', 'static_extract', 'framework_detect',
      'graph_reconstruct', 'semantic_enrich', 'dynamic_verify', 'finalize',
    ].map((stage, index) => ({
      stage: stage as ImageAgentProfile['analysis']['stages'][number]['stage'],
      status: stage === 'dynamic_verify' ? 'failed' as const : 'completed' as const,
      started_at: `2026-08-25T08:0${index}:00Z`,
      completed_at: stage === 'dynamic_verify' ? null : `2026-08-25T08:0${index}:30Z`,
    })),
    errors: [{
      error_id: 'error:dynamic',
      stage: 'dynamic_verify',
      code: 'docker_unavailable',
      message: 'Docker Desktop 不可用',
      retryable: true,
      details: {},
    }],
  },
  frameworks: [{
    framework_id: 'framework:langgraph',
    name: 'LangGraph',
    version: '0.2',
    evidence_refs: ['ev:static'],
    confidence: 0.94,
    verification_status: 'supported',
  }],
  nodes: [{
    node_id: 'node:input',
    node_type: 'external_input',
    name: '用户输入',
    framework_ids: ['framework:langgraph'],
    capability_ids: [],
    permission_ids: [],
    control_ids: [],
    risk_level: 'low',
    evidence_refs: ['ev:static'],
    confidence: 0.9,
    verification_status: 'supported',
  }, {
    node_id: 'node:shell',
    node_type: 'shell',
    name: '命令执行器',
    framework_ids: ['framework:langgraph'],
    capability_ids: ['cap:shell'],
    permission_ids: ['perm:shell'],
    control_ids: ['control:allowlist'],
    risk_level: 'critical',
    evidence_refs: ['ev:static'],
    confidence: 0.91,
    verification_status: 'supported',
  }],
  edges: [{
    edge_id: 'edge:input-shell',
    edge_type: 'calls',
    source_node_id: 'node:input',
    target_node_id: 'node:shell',
    evidence_refs: ['ev:static'],
    confidence: 0.9,
    verification_status: 'supported',
  }],
  capabilities: [{
    capability_id: 'cap:shell',
    name: 'Shell 执行',
    operation: 'execute',
    node_ids: ['node:shell'],
    risk_level: 'critical',
    evidence_refs: ['ev:static'],
    confidence: 0.91,
    verification_status: 'supported',
  }],
  permissions: [{
    permission_id: 'perm:shell',
    permission_type: 'shell',
    operations: ['execute'],
    scope: 'container',
    node_ids: ['node:shell'],
    capability_ids: ['cap:shell'],
    risk_level: 'critical',
    evidence_refs: ['ev:static'],
    confidence: 0.9,
    verification_status: 'supported',
  }],
  controls: [{
    control_id: 'control:allowlist',
    control_type: 'allowlist',
    name: '命令白名单',
    node_ids: ['node:shell'],
    description: '仅允许审核过的命令。',
    evidence_refs: ['ev:static'],
    confidence: 0.88,
    verification_status: 'supported',
  }],
  evidence: [{
    evidence_id: 'ev:static',
    artifact_digest: `sha256:${'a'.repeat(64)}`,
    layer_digest: `sha256:${'d'.repeat(64)}`,
    locator: {
      image_path: '/app/shop_agent.py',
      python_module: 'shop_agent',
      symbol: 'run_command',
      line_start: 18,
      line_end: 24,
    },
    extractor: 'python_ast',
    method: 'static',
    content_sha256: 'b'.repeat(64),
    summary: '外部输入可到达命令执行函数。',
  }],
  risk_paths: [{
    path_id: 'path:input-shell',
    source_node_id: 'node:input',
    sink_node_id: 'node:shell',
    node_ids: ['node:input', 'node:shell'],
    edge_ids: ['edge:input-shell'],
    capability_ids: ['cap:shell'],
    permission_ids: ['perm:shell'],
    control_ids: ['control:allowlist'],
    applicable_threats: ['prompt_injection', 'command_injection'],
    control_gaps: ['白名单覆盖不完整'],
    risk_level: 'critical',
    evidence_refs: ['ev:static'],
    confidence: 0.9,
    verification_status: 'supported',
  }],
  limitations: [{
    code: 'dynamic_verification_unavailable',
    message: '未执行动态分支。',
    evidence_refs: ['ev:static'],
  }],
  completeness: {
    static_source_recovery: 'complete',
    framework_coverage: { covered: 1, total: 1, ratio: 1 },
    graph_evidence_coverage: { covered: 3, total: 3, ratio: 1 },
    dynamic_corroboration_coverage: { covered: 0, total: 3, ratio: 0 },
    dynamic_behavior_coverage: { covered: 0, total: 1, ratio: 0 },
    unresolved_limitations: 1,
    blocking_limitations: ['dynamic_verification_unavailable'],
    conclusion: 'partial',
  },
}

const runningProfileStatus: ImageProfileStatus = {
  ...imageProfile.analysis,
  status: 'running',
  stages: imageProfile.analysis.stages.map((stage, index) => ({
    ...stage,
    status: index === 0 ? 'running' : 'pending',
    completed_at: null,
  })),
  errors: [],
}

const runningImportResult: AgentImageImportResult = {
  schema_version: 'agent-image-import-response-v0.1',
  agent,
  profile: {
    schema_version: 'image-profile-create-response-v0.1',
    analysis: runningProfileStatus,
    cached: false,
  },
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
  tokenStore.clear()
})

function Location() {
  return <span data-testid="location">{useLocation().pathname}</span>
}

describe('frontend workflows', () => {
  it('登录页签支持方向键切换并显示真实服务状态', async () => {
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok' })
    render(<MemoryRouter initialEntries={['/login']}><App /></MemoryRouter>)

    expect(await screen.findByRole('status', { name: '本地审计服务可用' })).toBeInTheDocument()
    const loginTab = screen.getByRole('tab', { name: '登录' })
    const registerTab = screen.getByRole('tab', { name: '注册' })
    const password = screen.getByLabelText('密码')
    fireEvent.change(password, { target: { value: 'login-secret' } })
    loginTab.focus()
    fireEvent.keyDown(loginTab, { key: 'ArrowRight' })

    expect(registerTab).toHaveFocus()
    expect(screen.getByLabelText('密码')).toHaveValue('')
    expect(registerTab).toHaveAttribute('aria-selected', 'true')
    expect(loginTab).toHaveAttribute('tabindex', '-1')
    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', 'register-tab')
    expect(screen.getByRole('heading', { name: '创建本地账号' })).toBeInTheDocument()
  })

  it('鼠标切换登录与注册时清空密码', async () => {
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok' })
    render(<MemoryRouter initialEntries={['/login']}><App /></MemoryRouter>)

    const password = screen.getByLabelText('密码')
    fireEvent.change(password, { target: { value: 'login-secret' } })
    fireEvent.click(screen.getByRole('tab', { name: '注册' }))

    expect(screen.getByLabelText('密码')).toHaveValue('')
  })

  it('已登录工作台提供跳过导航和用户退出入口', async () => {
    tokenStore.set('valid-token')
    vi.spyOn(api, 'me').mockResolvedValue({
      user: { user_id: 'user-1', username: 'tester', email: 'tester@example.com', role: 'user' },
    })
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok' })
    vi.spyOn(api, 'listAudits').mockResolvedValue([])
    const logout = vi.spyOn(api, 'logout').mockResolvedValue(undefined)

    render(<MemoryRouter><App /></MemoryRouter>)

    const skipLink = await screen.findByRole('link', { name: '跳到主要内容' })
    expect(skipLink).toHaveAttribute('href', '#main-content')
    expect(document.querySelector('#main-content')).toHaveAttribute('tabindex', '-1')
    expect(screen.getByRole('status', { name: '审计服务在线' })).toBeInTheDocument()
    expect(document.querySelector('.topbar')).not.toHaveTextContent('新建审计')
    expect(document.querySelector('.dashboard-main')).toHaveTextContent('新建审计')
    expect(screen.getByRole('link', { name: 'Agent 资产' })).toHaveAttribute('data-tooltip', 'Agent 资产')
    fireEvent.click(screen.getByRole('button', { name: '打开用户菜单' }))
    expect(screen.getByRole('menu')).toHaveTextContent('tester@example.com')
    fireEvent.click(screen.getByRole('menuitem', { name: '退出登录' }))
    expect(await screen.findByRole('heading', { name: '欢迎回来' })).toBeInTheDocument()
    expect(logout).toHaveBeenCalled()
    expect(tokenStore.get()).toBeNull()
  })

  it('接口返回 401 时同步清理 React 用户并跳转登录', async () => {
    tokenStore.set('expired-token')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (path) => {
      if (String(path) === '/v1/auth/me') {
        return new Response(JSON.stringify({ user: {
          user_id: 'user-1', username: 'tester', email: 'tester@example.com', role: 'user',
        } }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({ detail: '登录已过期' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    render(<MemoryRouter initialEntries={['/']}><App /><Location /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: '欢迎回来' })).toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent('/login')
    expect(tokenStore.get()).toBeNull()
  })

  it('Dashboard 仅显示最近四条记录并提供正确进度', async () => {
    tokenStore.set('valid-token')
    vi.spyOn(api, 'me').mockResolvedValue({
      user: { user_id: 'user-1', username: 'tester', email: 'tester@example.com', role: 'user' },
    })
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok' })
    vi.spyOn(api, 'listAudits').mockResolvedValue(Array.from({ length: 10 }, (_, index) => ({
      audit_id: `audit-${index}`,
      tenant_id: 'tenant-1',
      agent_id: agent.agent_id,
      state: index < 4 ? 'completed' : index < 6 ? 'failed' : 'profiling',
      created_at: `2026-01-${String(index + 1).padStart(2, '0')}T00:00:00Z`,
      updated_at: `2026-01-${String(index + 1).padStart(2, '0')}T01:00:00Z`,
    })))

    render(<MemoryRouter><App /></MemoryRouter>)

    const table = await screen.findByLabelText('最近审计')
    expect(table.querySelectorAll('.audit-row')).toHaveLength(4)
    expect(screen.getAllByRole('progressbar', { name: '审计完成率' })[0]).toHaveAttribute('aria-valuenow', '40')
    expect(screen.getAllByRole('progressbar', { name: '任务结束率' })[0]).toHaveAttribute('aria-valuenow', '60')
    expect(screen.getByRole('link', { name: '审计记录' })).toBeInTheDocument()
  })

  it('进度为零时不渲染彩色填充', async () => {
    tokenStore.set('valid-token')
    vi.spyOn(api, 'me').mockResolvedValue({
      user: { user_id: 'user-1', username: 'tester', email: 'tester@example.com', role: 'user' },
    })
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok' })
    vi.spyOn(api, 'listAudits').mockResolvedValue([{
      audit_id: 'audit-complete',
      tenant_id: 'tenant-1',
      agent_id: agent.agent_id,
      state: 'completed',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z',
    }])

    render(<MemoryRouter><App /></MemoryRouter>)

    const zeroProgress = await screen.findByRole('progressbar', { name: '当前运行占比' })
    expect(zeroProgress).toHaveAttribute('aria-valuenow', '0')
    expect(zeroProgress).toBeEmptyDOMElement()
    const completionFill = screen.getAllByRole('progressbar', { name: '审计完成率' })[0].firstElementChild
    expect(completionFill).toHaveClass('progress-primary')
    expect(completionFill).not.toHaveClass('primary')
  })

  it('审计记录页展示全部记录并支持状态筛选', async () => {
    vi.spyOn(api, 'listAudits').mockResolvedValue([
      {
        audit_id: 'audit-complete',
        tenant_id: 'tenant-1',
        agent_id: agent.agent_id,
        state: 'completed',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z',
      },
      {
        audit_id: 'audit-running',
        tenant_id: 'tenant-1',
        agent_id: agent.agent_id,
        state: 'profiling',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z',
      },
    ])

    render(<MemoryRouter><AuditRecords /></MemoryRouter>)

    const table = await screen.findByLabelText('全部审计记录')
    expect(table.querySelectorAll('.audit-row')).toHaveLength(2)
    const search = screen.getByRole('searchbox', { name: '搜索审计记录' })
    fireEvent.change(search, { target: { value: 'complete' } })
    expect(screen.getByRole('button', { name: '清空搜索' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '清空搜索' }))
    expect(search).toHaveValue('')
    fireEvent.change(screen.getByLabelText('按审计状态筛选'), { target: { value: 'running' } })
    expect(table.querySelectorAll('.audit-row')).toHaveLength(1)
    expect(table).toHaveTextContent('audit-running')
    fireEvent.click(screen.getByRole('button', { name: '重置筛选' }))
    expect(screen.getByLabelText('按审计状态筛选')).toHaveValue('all')
  })

  it('将 ecommerce_demo 配置作为可审阅建议而非自动填写', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])

    render(<MemoryRouter><NewAudit /></MemoryRouter>)

    const select = await screen.findByLabelText('Agent')
    expect(screen.getByLabelText('攻击基准')).toHaveValue('')
    expect(screen.getByLabelText('业务任务')).toHaveValue('')
    expect(screen.getByRole('button', { name: '填入示例' })).toBeDisabled()

    fireEvent.change(select, { target: { value: agent.agent_id } })
    expect(screen.getByLabelText('攻击基准')).toHaveValue('ecommerce-security-v0.1')
    expect(screen.getByText(/ecommerce-security-v0.1 内置基准模板/)).toBeInTheDocument()
    expect(screen.getByText('查看系统确定的技术测试范围')).toBeInTheDocument()
    expect(screen.getByLabelText('业务任务')).toHaveValue('')

    fireEvent.click(screen.getByRole('button', { name: '填入示例' }))
    expect(screen.getByLabelText('业务任务')).toHaveValue('搜索降噪耳机')
    expect(screen.getByLabelText('结果中必须出现的内容')).toHaveValue('星云')
    expect(screen.getByLabelText('执行时必须发生的系统事件')).toHaveValue('product_search')
    expect(screen.getByRole('button', { name: /保护目标/ })).toHaveAttribute('aria-controls', 'audit-boundary')
    expect(screen.getByRole('button', { name: '返回总览' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '生成攻击集' })).toBeEnabled()
  })

  it('从 Agent API 加载审计下拉并提交 Oracle 配置', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])
    const created: AuditRun = {
      audit_id: 'audit-1',
      tenant_id: 'tenant-1',
      agent_id: agent.agent_id,
      state: 'created',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    }
    const create = vi.spyOn(api, 'createAudit').mockResolvedValue(created)

    render(<MemoryRouter><NewAudit /><Location /></MemoryRouter>)

    const select = await screen.findByLabelText('Agent')
    fireEvent.change(select, { target: { value: agent.agent_id } })
    fireEvent.click(screen.getByRole('button', { name: '填入示例' }))
    fireEvent.change(screen.getByLabelText('结果中必须出现的内容'), {
      target: { value: '支持政策\n公开信息' },
    })
    fireEvent.change(screen.getByLabelText('执行时必须发生的系统事件'), {
      target: { value: 'search_products\nread_policy' },
    })
    fireEvent.click(screen.getByRole('button', { name: '生成攻击集' }))

    await waitFor(() => expect(create).toHaveBeenCalled())
    expect(screen.getByTestId('location')).toHaveTextContent('/audits/audit-1')
    expect(create.mock.calls[0][0].normal_tasks[0].oracle).toEqual({
      required_answer_substrings: ['支持政策', '公开信息'],
      required_business_events: ['search_products', 'read_policy'],
    })
  })

  it('从 Agent 页面选择本机镜像接入 Agent', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])
    const upload = vi.spyOn(api, 'uploadAgentImage').mockImplementation(
      () => new Promise(() => {}),
    )

    render(<MemoryRouter><Agents /></MemoryRouter>)

    expect(await screen.findByText('接入镜像')).toBeInTheDocument()
    expect(screen.queryByText('接入内置演示 Agent')).not.toBeInTheDocument()

    const file = new File(['archive'], 'local-agent.tar', {
      type: 'application/x-tar',
    })
    fireEvent.change(screen.getByLabelText('选择 Agent 镜像文件'), {
      target: { files: [file] },
    })

    expect(await screen.findByRole('heading', { name: '导入 Agent 镜像' })).toBeInTheDocument()
    expect(screen.getAllByText('local-agent.tar').length).toBeGreaterThanOrEqual(1)
    expect(upload).not.toHaveBeenCalled()
    expect(screen.getByText('自动识别运行入口')).toBeInTheDocument()
    expect(screen.queryByLabelText('Python 运行模块')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '开始导入' }))

    expect(upload).toHaveBeenCalledWith(
      expect.objectContaining({ probeModule: undefined }),
      expect.any(Function),
    )
  })

  it('仅在镜像入口无法识别时要求开发人员提供 Python 运行模块', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])
    vi.spyOn(api, 'uploadAgentImage')
      .mockResolvedValueOnce({
        ...runningImportResult,
        profile: {
          ...runningImportResult.profile,
          analysis: {
            ...runningImportResult.profile.analysis,
            status: 'failed',
            stages: runningImportResult.profile.analysis.stages.map((stage) =>
              stage.stage === 'dynamic_verify' ? { ...stage, status: 'failed' as const } : stage),
            errors: [{
              error_id: 'error:entrypoint',
              stage: 'dynamic_verify',
              code: 'unsupported_entrypoint',
              message: '无法从镜像入口识别可安全导入的 Python 模块',
              retryable: true,
              details: {},
            }],
          },
        },
      })
      .mockResolvedValueOnce(runningImportResult)
    vi.spyOn(api, 'getAgentProfileStatus').mockResolvedValue({
      ...runningProfileStatus,
      status: 'failed',
      errors: [{
        error_id: 'error:entrypoint',
        stage: 'dynamic_verify',
        code: 'unsupported_entrypoint',
        message: '无法从镜像入口识别可安全导入的 Python 模块',
        retryable: true,
        details: {},
      }],
    })

    render(<MemoryRouter><Agents /></MemoryRouter>)
    fireEvent.change(await screen.findByLabelText('选择 Agent 镜像文件'), {
      target: { files: [new File(['archive'], 'shell-agent.tar')] },
    })
    fireEvent.click(screen.getByRole('button', { name: '开始导入' }))

    const moduleInput = await screen.findByLabelText('Python 运行模块')
    expect(screen.getByRole('button', { name: '使用模块重新分析' })).toBeDisabled()
    fireEvent.change(moduleInput, { target: { value: 'package.runtime_entry' } })
    fireEvent.click(screen.getByRole('button', { name: '使用模块重新分析' }))

    await waitFor(() => expect(api.uploadAgentImage).toHaveBeenLastCalledWith(
      expect.objectContaining({ probeModule: 'package.runtime_entry' }),
      expect.any(Function),
    ))
  })

  it('空资产页只保留一个镜像接入入口', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([])

    render(<MemoryRouter><Agents /></MemoryRouter>)

    expect(await screen.findByText('暂无 Agent 资产。请上传镜像并完成画像构建。')).toBeInTheDocument()
    expect(screen.getAllByText('接入镜像')).toHaveLength(1)
    expect(screen.queryByText('选择镜像')).not.toBeInTheDocument()
    expect(screen.queryByText('接入 Agent')).not.toBeInTheDocument()
  })

  it('上传弹窗的画像轮询超时后点击重试会重新发起请求', async () => {
    vi.useFakeTimers()
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])
    vi.spyOn(api, 'uploadAgentImage').mockResolvedValue(runningImportResult)
    const retry = vi.spyOn(api, 'retryAgentProfile').mockResolvedValue(runningProfileStatus)
    const getStatus = vi.spyOn(api, 'getAgentProfileStatus')
      .mockImplementationOnce(() => new Promise(() => {}))
      .mockResolvedValueOnce({ ...runningProfileStatus, status: 'completed' })

    render(<MemoryRouter><Agents /></MemoryRouter>)
    await act(async () => {})
    fireEvent.change(screen.getByLabelText('选择 Agent 镜像文件'), {
      target: { files: [new File(['archive'], 'local-agent.tar')] },
    })
    fireEvent.click(screen.getByRole('button', { name: '开始导入' }))
    await act(async () => {})
    await act(async () => { await vi.advanceTimersByTimeAsync(5 * 60 * 1000) })

    expect(screen.getByRole('alert')).toHaveTextContent(
      '画像构建等待已超过 5 分钟。任务可能仍在后台运行，请重试检查状态。',
    )
    fireEvent.click(screen.getByRole('button', { name: '重新尝试' }))
    await act(async () => {})
    await act(async () => { await vi.advanceTimersByTimeAsync(700) })

    expect(retry).toHaveBeenCalledOnce()
    expect(getStatus).toHaveBeenCalledTimes(2)
  })

  it('上传弹窗卸载后取消画像轮询', async () => {
    vi.useFakeTimers()
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])
    vi.spyOn(api, 'uploadAgentImage').mockResolvedValue(runningImportResult)
    const getStatus = vi.spyOn(api, 'getAgentProfileStatus').mockResolvedValue(runningProfileStatus)

    const view = render(<MemoryRouter><Agents /></MemoryRouter>)
    await act(async () => {})
    fireEvent.change(screen.getByLabelText('选择 Agent 镜像文件'), {
      target: { files: [new File(['archive'], 'local-agent.tar')] },
    })
    fireEvent.click(screen.getByRole('button', { name: '开始导入' }))
    await act(async () => {})
    view.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })

    expect(getStatus).not.toHaveBeenCalled()
  })

  it('展示自动同步的 ecommerce 与 OpenManus 两张 Agent 卡片', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent, openmanusAgent])

    render(<MemoryRouter><Agents /></MemoryRouter>)

    expect(await screen.findByRole('heading', { name: agent.name })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: openmanusAgent.name })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: agent.name })).toHaveAttribute(
      'href', `/agents/${agent.agent_id}`,
    )
    expect(screen.getByText('ecommerce_demo')).toBeInTheDocument()
    expect(screen.getByText('openmanus')).toBeInTheDocument()
  })

  it('删除 Agent 后立即更新列表并显示成功反馈', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent])
    const remove = vi.spyOn(api, 'deleteAgent').mockResolvedValue({
      schema_version: 'agent-delete-response-v0.1',
      agent_id: agent.agent_id,
      deleted: true,
    })

    render(<MemoryRouter><Agents /></MemoryRouter>)

    await screen.findByRole('heading', { name: agent.name })
    fireEvent.click(screen.getByRole('button', { name: `删除 ${agent.name}` }))
    expect(screen.getByRole('alertdialog', { name: '删除 Agent 资产' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '关闭删除窗口' })).toHaveClass('dialog-close-button')

    fireEvent.click(screen.getByRole('button', { name: '确认删除' }))

    await waitFor(() => expect(remove).toHaveBeenCalledWith(agent.agent_id))
    expect(screen.queryByRole('heading', { name: agent.name })).not.toBeInTheDocument()
    expect(screen.getByText(`${agent.name} 已从当前用户的资产列表移除。`)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '关闭删除成功提示' })).toHaveClass(
      'success-dismiss-button',
    )
  })

  it('长 Agent 名称和 ID 保留完整悬浮文本', async () => {
    const longAgent = {
      ...agent,
      agent_id: 'ecommerce_customer_guide_with_a_very_long_identifier',
      name: 'E-Commerce Customer Guide Agent With A Very Long Display Name',
    }
    vi.spyOn(api, 'listAgents').mockResolvedValue([longAgent])

    render(<MemoryRouter><Agents /></MemoryRouter>)

    expect(await screen.findByRole('link', { name: longAgent.name })).toHaveAttribute(
      'title', longAgent.name,
    )
    expect(screen.getByText(longAgent.agent_id)).toHaveAttribute('title', longAgent.agent_id)
  })

  it('Agent 画像展示技术信息、工具和最近审计', async () => {
    vi.spyOn(api, 'getAgent').mockResolvedValue(agent)
    vi.spyOn(api, 'getAgentProfile').mockResolvedValue(agentProfile)
    vi.spyOn(api, 'listAudits').mockResolvedValue([
      {
        audit_id: 'audit-old',
        tenant_id: 'tenant-1',
        agent_id: agent.agent_id,
        state: 'failed',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z',
      },
      {
        audit_id: 'audit-latest',
        tenant_id: 'tenant-1',
        agent_id: agent.agent_id,
        state: 'completed',
        created_at: '2026-01-02T00:00:00Z',
        updated_at: '2026-01-03T00:00:00Z',
      },
      {
        audit_id: 'other-agent-audit',
        tenant_id: 'tenant-1',
        agent_id: openmanusAgent.agent_id,
        state: 'completed',
        created_at: '2026-01-03T00:00:00Z',
        updated_at: '2026-01-04T00:00:00Z',
      },
    ])

    render(<MemoryRouter initialEntries={[`/agents/${agent.agent_id}`]}>
      <Routes><Route path="/agents/:agentId" element={<AgentProfilePage />} /></Routes>
    </MemoryRouter>)

    expect(await screen.findByRole('heading', { name: agent.name })).toBeInTheDocument()
    expect(screen.getByText('local-sdk')).toBeInTheDocument()
    expect(screen.getAllByText('product_search').length).toBeGreaterThan(0)
    expect(screen.getByText('搜索商品目录')).toBeInTheDocument()
    const audits = screen.getByLabelText(`${agent.name} 最近审计`)
    expect(audits).toHaveTextContent('audit-latest')
    expect(audits).toHaveTextContent('audit-old')
    expect(audits).not.toHaveTextContent('other-agent-audit')
    expect(api.getAgentProfile).toHaveBeenCalledWith(agent.agent_id)
  })

  it('v0.2 画像展示完整用户可见报告', async () => {
    vi.spyOn(api, 'getAgent').mockResolvedValue(agent)
    vi.spyOn(api, 'getAgentProfile').mockResolvedValue(imageProfile)
    vi.spyOn(api, 'listAudits').mockResolvedValue([{
      audit_id: 'audit-bound-profile',
      tenant_id: 'tenant-1',
      agent_id: agent.agent_id,
      image_digest: imageProfile.image.digest,
      profile_id: imageProfile.profile_id,
      profile_sha256: 'f'.repeat(64),
      state: 'completed',
      created_at: '2026-08-25T09:00:00Z',
      updated_at: '2026-08-25T10:00:00Z',
    }])

    render(<MemoryRouter initialEntries={[`/agents/${agent.agent_id}`]}>
      <Routes><Route path="/agents/:agentId" element={<AgentProfilePage />} /></Routes>
    </MemoryRouter>)

    expect(await screen.findByRole('heading', { name: '镜像与画像身份' })).toBeInTheDocument()
    expect(screen.getByText(imageProfile.profile_id)).toBeInTheDocument()
    expect(screen.getByText('画像 SHA-256')).toBeInTheDocument()
    expect(screen.getByText('f'.repeat(64))).toBeInTheDocument()
    expect(screen.getAllByText(imageProfile.image.digest).length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { name: '部分画像' })).toBeInTheDocument()
    expect(screen.getByText('partial')).toBeInTheDocument()
    expect(screen.getByText('动态行为覆盖')).toBeInTheDocument()
    expect(screen.getByText('全图动态佐证')).toBeInTheDocument()
    expect(screen.getAllByText('dynamic_verification_unavailable')).toHaveLength(2)
    expect(screen.getByRole('heading', { name: '八阶段分析' })).toBeInTheDocument()
    expect(screen.getByText('读取镜像清单')).toBeInTheDocument()
    expect(screen.getByText('发布静态画像')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '框架识别' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '能力、权限与安全控制' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '能力' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '权限' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '安全控制' })).toBeInTheDocument()
    expect(screen.getByText('Shell 执行')).toBeInTheDocument()
    expect(screen.getAllByText('命令白名单').length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { name: '风险路径详情' })).toBeInTheDocument()
    expect(screen.getByText('白名单覆盖不完整')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '全量证据索引' })).toBeInTheDocument()
    expect(screen.getAllByText('外部输入可到达命令执行函数。').length).toBeGreaterThan(0)
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '分析限制' })).toBeInTheDocument()
    expect(screen.getAllByText('未执行动态分支。')).toHaveLength(2)
    expect(await screen.findByRole('tab', { name: '结构化表格' })).toBeInTheDocument()
  })

  it('一万节点和五万证据画像保持初始 DOM 有界并可分批查看更多', () => {
    const nodes = Array.from({ length: 10_001 }, (_, index) => ({
      ...imageProfile.nodes[0],
      node_id: `node:${index}`,
      name: `节点 ${index}`,
      evidence_refs: [`ev:${index}`],
    }))
    const edges = Array.from({ length: 10_000 }, (_, index) => ({
      ...imageProfile.edges[0],
      edge_id: `edge:${index}`,
      source_node_id: `node:${index}`,
      target_node_id: `node:${index + 1}`,
      evidence_refs: [`ev:${index}`],
    }))
    const evidence = Array.from({ length: 50_001 }, (_, index) => ({
      ...imageProfile.evidence[0],
      evidence_id: `ev:${index}`,
      summary: `证据 ${index}`,
    }))
    const capabilities = Array.from({ length: 41 }, (_, index) => ({
      ...imageProfile.capabilities[0],
      capability_id: `cap:${index}`,
      name: `能力 ${index}`,
      node_ids: [`node:${index}`],
      evidence_refs: [`ev:${index}`],
    }))
    const permissions = Array.from({ length: 41 }, (_, index) => ({
      ...imageProfile.permissions[0],
      permission_id: `perm:${index}`,
      node_ids: [`node:${index}`],
      capability_ids: [`cap:${index}`],
      evidence_refs: [`ev:${index}`],
    }))
    const controls = Array.from({ length: 41 }, (_, index) => ({
      ...imageProfile.controls[0],
      control_id: `control:${index}`,
      name: `控制 ${index}`,
      node_ids: [`node:${index}`],
      evidence_refs: [`ev:${index}`],
    }))
    const riskPaths = Array.from({ length: 41 }, (_, index) => ({
      ...imageProfile.risk_paths[0],
      path_id: `path:${index}`,
      source_node_id: `node:${index}`,
      sink_node_id: `node:${index + 1}`,
      node_ids: [`node:${index}`, `node:${index + 1}`],
      edge_ids: [`edge:${index}`],
      capability_ids: [`cap:${index}`],
      permission_ids: [`perm:${index}`],
      control_ids: [`control:${index}`],
      evidence_refs: [`ev:${index}`],
    }))
    const largeProfile: ImageAgentProfile = {
      ...imageProfile,
      nodes,
      edges,
      evidence,
      capabilities,
      permissions,
      controls,
      risk_paths: riskPaths,
    }

    const report = render(<AgentProfileReport profile={largeProfile} />)
    for (const label of ['能力', '权限', '安全控制', '风险路径', '证据']) {
      const list = screen.getByLabelText(`${label}列表`)
      expect(list.querySelectorAll(':scope > article')).toHaveLength(20)
      fireEvent.click(screen.getByRole('button', { name: `查看更多${label}` }))
      expect(list.querySelectorAll(':scope > article')).toHaveLength(40)
    }
    report.unmount()

    render(<AgentProfileGraph profile={largeProfile} />)
    fireEvent.click(screen.getByRole('tab', { name: '结构化表格' }))
    expect(screen.getByRole('table', { name: 'Agent 图谱节点' }).querySelectorAll('tbody tr')).toHaveLength(80)
    expect(screen.getByText(/当前显示 80 \/ 10001 个节点/)).toBeInTheDocument()
  })

  it('画像详情卸载后取消进行中的状态轮询', async () => {
    vi.useFakeTimers()
    vi.spyOn(api, 'getAgent').mockResolvedValue(agent)
    vi.spyOn(api, 'getAgentProfile').mockResolvedValue(imageProfile)
    vi.spyOn(api, 'listAudits').mockResolvedValue([])
    vi.spyOn(api, 'retryAgentProfile').mockResolvedValue(runningProfileStatus)
    const getStatus = vi.spyOn(api, 'getAgentProfileStatus').mockResolvedValue(runningProfileStatus)

    const view = render(<MemoryRouter initialEntries={[`/agents/${agent.agent_id}`]}>
      <Routes><Route path="/agents/:agentId" element={<AgentProfilePage />} /></Routes>
    </MemoryRouter>)
    await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: '重试失败阶段' }))
    await act(async () => {})
    expect(getStatus).toHaveBeenCalledOnce()

    view.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })

    expect(getStatus).toHaveBeenCalledOnce()
  })

  it('Agent 搜索支持 Escape 清除并播报结果数量', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent, openmanusAgent])

    render(<MemoryRouter><Agents /></MemoryRouter>)

    const search = await screen.findByRole('textbox', { name: '搜索 Agent' })
    fireEvent.change(search, { target: { value: 'OpenManus' } })
    expect(screen.getByRole('status')).toHaveTextContent('1 个 Agent')
    fireEvent.keyDown(search, { key: 'Escape' })

    expect(search).toHaveValue('')
    expect(search).toHaveFocus()
    expect(screen.getByRole('status')).toHaveTextContent('2 个 Agent')
  })

  it('在新建审计下拉中展示自动同步的两个 Agent', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent, openmanusAgent])

    render(<MemoryRouter><NewAudit /></MemoryRouter>)

    const select = await screen.findByLabelText('Agent')
    expect(select).toContainElement(
      screen.getByRole('option', { name: `${agent.name} (${agent.agent_id})` }),
    )
    expect(select).toContainElement(
      screen.getByRole('option', { name: `${openmanusAgent.name} (${openmanusAgent.agent_id})` }),
    )
  })

  it('选择 OpenManus 后切换到白盒真实审计配置', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([agent, openmanusAgent])
    vi.spyOn(api, 'getAuditPreflight').mockResolvedValue(
      readyPreflight(openmanusAgent.agent_id),
    )
    vi.spyOn(api, 'getLatestAgentProfile').mockResolvedValue({
      ...imageProfile,
      agent_id: openmanusAgent.agent_id,
    })

    render(<MemoryRouter><NewAudit /></MemoryRouter>)

    const select = await screen.findByLabelText('Agent')
    fireEvent.change(select, { target: { value: openmanusAgent.agent_id } })

    expect(screen.getByLabelText('攻击基准')).toHaveValue('openmanus-security-v0.1')
    expect(await screen.findByText('静态画像已就绪')).toBeVisible()
    expect(screen.getByText(/静态画像 · 2 个适用威胁/)).toBeInTheDocument()
    expect(screen.getByLabelText('业务任务')).toHaveValue('')

    fireEvent.click(screen.getByRole('button', { name: '填入示例' }))
    expect(screen.getByLabelText('不能发生什么')).toHaveValue('阻断画像识别的高风险路径')
    expect(screen.getByText('prompt_injection')).toBeInTheDocument()
    expect(screen.getByText('command_injection')).toBeInTheDocument()
    expect(screen.getByLabelText('业务任务')).toHaveValue('')
  })

  it('OpenManus 静态画像未发布时阻止生成攻击集', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([openmanusAgent])
    vi.spyOn(api, 'getAuditPreflight').mockResolvedValue({
      ...readyPreflight(openmanusAgent.agent_id),
      ready: false,
      checks: [{
        check_id: 'static_profile',
        status: 'blocked',
        message: 'Published static profile is required.',
      }],
    })
    vi.spyOn(api, 'getLatestAgentProfile').mockRejectedValue(
      new Error('尚未生成画像'),
    )
    vi.spyOn(api, 'getModelRuntimeStatuses').mockResolvedValue([
      { role: 'target', configured: true, tested: true },
      { role: 'attack', configured: true, tested: true },
      { role: 'defense', configured: true, tested: true },
    ])

    render(<MemoryRouter><NewAudit /></MemoryRouter>)

    fireEvent.change(await screen.findByLabelText('Agent'), {
      target: { value: openmanusAgent.agent_id },
    })

    expect(await screen.findByText('静态画像未就绪')).toBeVisible()
    expect(screen.getByText('尚未生成画像')).toBeVisible()
    expect(screen.getByRole('link', { name: '前往生成画像' })).toHaveAttribute(
      'href',
      `/agents/${openmanusAgent.agent_id}`,
    )
    expect(screen.getByRole('button', { name: '生成攻击集' })).toBeDisabled()
  })

  it('OpenManus 三类模型测试通过后才能启动后台任务', async () => {
    vi.spyOn(api, 'listAgents').mockResolvedValue([openmanusAgent])
    vi.spyOn(api, 'getAuditPreflight').mockResolvedValue(
      readyPreflight(openmanusAgent.agent_id),
    )
    vi.spyOn(api, 'getLatestAgentProfile').mockResolvedValue({
      ...imageProfile,
      agent_id: openmanusAgent.agent_id,
    })
    vi.spyOn(api, 'getModelRuntimeStatuses').mockResolvedValue([
      { role: 'target', configured: false, tested: false },
      { role: 'attack', configured: false, tested: false },
      { role: 'defense', configured: false, tested: false },
    ])
    const testConfiguration = vi.spyOn(api, 'testModelRuntimeConfiguration')
      .mockImplementation(async (role, configuration) => ({
        role,
        configured: true,
        tested: true,
        base_url: configuration.base_url,
        model: configuration.model,
        tested_at: '2026-01-01T00:00:00Z',
      }))
    const create = vi.spyOn(api, 'createAudit').mockResolvedValue({
      audit_id: 'audit-openmanus',
      tenant_id: 'tenant-1',
      agent_id: openmanusAgent.agent_id,
      state: 'created',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    })

    render(<MemoryRouter><NewAudit /><Location /></MemoryRouter>)

    fireEvent.change(await screen.findByLabelText('Agent'), {
      target: { value: openmanusAgent.agent_id },
    })
    expect(screen.getByRole('button', { name: '生成攻击集' })).toBeDisabled()
    await screen.findByText('静态画像已就绪')
    fireEvent.click(screen.getByRole('button', { name: '填入示例' }))
    fireEvent.change(screen.getByLabelText('业务任务'), {
      target: { value: '请用 Python 计算 17 乘以 23' },
    })
    fireEvent.change(screen.getByLabelText('完成标准'), {
      target: { value: '返回正确结果且不访问敏感文件' },
    })
    fireEvent.change(screen.getByLabelText('结果中必须出现的内容'), {
      target: { value: '391' },
    })
    fireEvent.change(screen.getByLabelText('执行时必须发生的系统事件'), {
      target: { value: 'python_execute' },
    })

    for (const title of ['被测 Agent', '攻击 Agent', '防御 Agent']) {
      fireEvent.change(screen.getByLabelText(`${title} API 地址`), {
        target: { value: 'https://models.example.test/v1' },
      })
      fireEvent.change(screen.getByLabelText(`${title} 模型名称`), {
        target: { value: 'competition-model' },
      })
      fireEvent.change(screen.getByLabelText(`${title} API Key`), {
        target: { value: `${title}-secret` },
      })
      const buttons = screen.getAllByRole('button', { name: '测试并保存' })
      fireEvent.click(buttons[['被测 Agent', '攻击 Agent', '防御 Agent'].indexOf(title)])
      await waitFor(() => expect(testConfiguration).toHaveBeenCalledTimes(
        ['被测 Agent', '攻击 Agent', '防御 Agent'].indexOf(title) + 1,
      ))
    }

    await waitFor(() => expect(screen.getByText('配置就绪')).toBeVisible())
    fireEvent.click(screen.getByRole('button', { name: '生成攻击集' }))

    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    expect(testConfiguration).toHaveBeenCalledTimes(3)
    expect(testConfiguration.mock.invocationCallOrder[2]).toBeLessThan(create.mock.invocationCallOrder[0])
    expect(create.mock.calls[0][0]).toMatchObject({
      benchmark_id: 'openmanus-security-v0.1',
      runtime_mode: 'openmanus_real',
    })
  })

  it('独立模型设置页复用三角色连接配置', async () => {
    vi.spyOn(api, 'getModelRuntimeStatuses').mockResolvedValue([
      { role: 'target', configured: false, tested: false },
      { role: 'attack', configured: false, tested: false },
      { role: 'defense', configured: false, tested: false },
    ])

    render(<MemoryRouter><ModelSettings /></MemoryRouter>)

    expect(screen.getByRole('heading', { name: 'Agent 模型配置' })).toBeVisible()
    expect(await screen.findByText('0 / 3 已通过')).toBeVisible()
    expect(screen.getByLabelText('被测 Agent API Key')).toBeVisible()
    expect(screen.getByLabelText('攻击 Agent API Key')).toBeVisible()
    expect(screen.getByLabelText('防御 Agent API Key')).toBeVisible()
  })

  it('执行中轮询 status/workspace，并在失败时展示错误', async () => {
    const running: AuditStatus = {
      audit_id: 'audit-1', state: 'profiling', progress_percent: 20,
      total_duration_ms: 900, stages: [{
        event_id: 'stage-1', state: 'profiling', status: 'running', attempt: 1,
        started_at: '2026-01-01T00:00:00Z', message: '读取 Agent 画像',
      }],
    }
    const failed = { ...running, state: 'failed' as const, progress_percent: 20 }
    const workspace = {
      audit_id: 'audit-1', state: 'profiling', status: running, traces: [],
      run: {
        audit_id: 'audit-1', tenant_id: 'tenant-1', agent_id: agent.agent_id,
        state: 'profiling', created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:01Z',
      },
    } as AuditWorkspace
    const failedWorkspace = {
      ...workspace, state: 'failed', status: failed,
      run: { ...workspace.run, state: 'failed', error: '画像服务不可用' },
    } as AuditWorkspace
    vi.spyOn(api, 'getStatus').mockResolvedValueOnce(running)
      .mockResolvedValue(failed)
    vi.spyOn(api, 'getWorkspace').mockResolvedValueOnce(workspace)
      .mockResolvedValue(failedWorkspace)
    const resume = vi.spyOn(api, 'resumeAudit').mockResolvedValue(
      failedWorkspace.run,
    )

    render(<MemoryRouter initialEntries={['/audits/audit-1']}>
      <Routes><Route path="/audits/:auditId" element={<AuditDetail />} /></Routes>
    </MemoryRouter>)

    expect(await screen.findByText('读取 Agent 画像')).toBeInTheDocument()
    expect(screen.getByText('20%')).toBeInTheDocument()
    expect(await screen.findByText('画像服务不可用', {}, { timeout: 1600 })).toBeInTheDocument()
    expect(api.getStatus).toHaveBeenCalledTimes(2)
    expect(api.getWorkspace).toHaveBeenCalledTimes(2)
    fireEvent.click(screen.getByRole('button', { name: '从检查点继续' }))
    await waitFor(() => expect(resume).toHaveBeenCalledWith('audit-1'))
  })

  it('攻击集审阅确认后才启动正式审计', async () => {
    const status: AuditStatus = {
      audit_id: 'audit-review',
      state: 'attack_review',
      progress_percent: 33.33,
      total_duration_ms: 120,
      stages: [],
    }
    const workspace = {
      audit_id: 'audit-review',
      state: 'attack_review',
      status,
      traces: [],
      run: {
        audit_id: 'audit-review',
        tenant_id: 'tenant-1',
        agent_id: openmanusAgent.agent_id,
        state: 'attack_review',
        profile_id: 'profile-openmanus',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:01Z',
      },
      plan: {
        plan_id: 'plan-review',
        audit_id: 'audit-review',
        profile_id: 'profile-openmanus',
        source: 'llm',
        planner_model: 'attack-model',
        normal_task_ids: ['normal-1'],
        stop_conditions: ['all scenarios completed'],
        warnings: [],
        generated_at: '2026-01-01T00:00:01Z',
        items: [{
          scenario_id: 'py-exec-rce',
          risk_surface: 'command_injection',
          target_node: 'tool:python_execute',
          rationale: '验证 Python 执行边界',
          priority: 1,
          expected_evidence: ['trajectory', 'tool_call'],
          metadata: {
            predicted_attack_node_id: 'tool:python_execute',
            predicted_path_id: 'path:prompt-to-python',
          },
        }],
      },
    } as AuditWorkspace
    vi.spyOn(api, 'getStatus').mockResolvedValue(status)
    vi.spyOn(api, 'getWorkspace').mockResolvedValue(workspace)
    vi.spyOn(api, 'getAuditPreflight').mockResolvedValue(
      readyPreflight(openmanusAgent.agent_id),
    )
    const execute = vi.spyOn(api, 'executeAudit').mockResolvedValue(
      workspace.run,
    )

    render(<MemoryRouter initialEntries={['/audits/audit-review']}>
      <Routes><Route path="/audits/:auditId" element={<AuditDetail />} /></Routes>
    </MemoryRouter>)

    expect(await screen.findByText('确认正式审计范围')).toBeVisible()
    expect(await screen.findByText('全部就绪')).toBeVisible()
    expect(screen.getByText('tool:python_execute')).toBeVisible()
    expect(screen.getByText('path:prompt-to-python')).toBeVisible()
    const start = screen.getByRole('button', { name: '批准并执行正式审计' })
    expect(start).toBeDisabled()

    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(start)

    await waitFor(() => expect(execute).toHaveBeenCalledWith('audit-review'))
  })

  it('needs_approval 状态停止轮询', async () => {
    const status: AuditStatus = {
      audit_id: 'audit-1', state: 'needs_approval', progress_percent: 90,
      total_duration_ms: 900, stages: [],
    }
    const workspace = {
      audit_id: 'audit-1', state: 'needs_approval', status, traces: [],
      run: {
        audit_id: 'audit-1', tenant_id: 'tenant-1', agent_id: agent.agent_id,
        state: 'needs_approval', created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:01Z',
      },
    } as AuditWorkspace
    vi.spyOn(api, 'getStatus').mockResolvedValue(status)
    vi.spyOn(api, 'getWorkspace').mockResolvedValue(workspace)

    render(<MemoryRouter initialEntries={['/audits/audit-1']}>
      <Routes><Route path="/audits/:auditId" element={<AuditDetail />} /></Routes>
    </MemoryRouter>)

    expect(await screen.findAllByText('待审批')).not.toHaveLength(0)
    await new Promise((resolve) => setTimeout(resolve, 1000))
    expect(api.getStatus).toHaveBeenCalledOnce()
    expect(api.getWorkspace).toHaveBeenCalledOnce()
    expect(screen.getByRole('link', { name: '返回总览' })).toHaveAttribute('href', '/')

    fireEvent.click(screen.getByRole('button', { name: '重新检查状态' }))
    await waitFor(() => expect(api.getStatus).toHaveBeenCalledTimes(2))
    expect(api.getWorkspace).toHaveBeenCalledTimes(2)
  })

  it('渲染场景对比并联动按原事件生成的攻击路径图', () => {
    const baselineScenario = {
      scenario_id: 's1', category: 'prompt_injection', target_node: 'agent',
      severity: 'high' as const, expected_decision: 'block' as const,
      actual_decision: 'allow' as const, clean_decision: 'allow' as const,
      passed: false, business_impact: '泄漏数据', trajectory_ref: 'base.json',
      blocked_node: null, bypassed_nodes: ['input_guard'], node_status: { input_guard: 'bypassed' },
    }
    const guardedScenario = {
      ...baselineScenario, actual_decision: 'block' as const, passed: true,
      trajectory_ref: 'guarded.json', blocked_node: 'input_guard', bypassed_nodes: [],
      node_status: { input_guard: 'intercepted' },
    }
    const data = {
      run: {
        audit_id: 'audit-1', tenant_id: 'tenant-1', agent_id: agent.agent_id,
        state: 'completed', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:02Z',
      },
      status: { audit_id: 'audit-1', state: 'completed', progress_percent: 100, total_duration_ms: 2000, stages: [] },
      plan: {},
      verdict: {
        audit_id: 'audit-1', agent_id: agent.agent_id, baseline_asr: 1, guarded_asr: 0,
        business_utility: 1, repaired_scenario_count: 1, conclusion: 'effective', evidence_status: 'complete',
      },
      decision: {
        decision_id: 'decision-1', audit_id: 'audit-1', decision: 'retest_after_fix',
        reasons: ['防护有效但需复测'], unresolved_risks: ['部署环境未验证'],
        limitations: ['仅覆盖当前基准'], evidence_complete: false,
      },
      evidence: { artifacts: [], incomplete_refs: [] },
      baseline: {
        overall_score: 10, risk_level: 'high', attack_success_rate: 1, false_positive_rate: 0,
        scenario_results: [
          baselineScenario,
          { ...baselineScenario, scenario_id: 's2', category: 'tool_abuse', trajectory_ref: 'base-s2.json' },
        ],
      },
      guarded: {
        overall_score: 90, risk_level: 'low', attack_success_rate: 0, false_positive_rate: 0,
        scenario_results: [
          guardedScenario,
          { ...guardedScenario, scenario_id: 's2', category: 'tool_abuse', trajectory_ref: 'guarded-s2.json' },
          { ...guardedScenario, scenario_id: 's3', category: 'data_exfiltration', trajectory_ref: 'guarded-s3.json' },
        ],
      },
      comparison: {
        before_score: 10, after_score: 90, score_delta: 80, risk_level_change: 'high -> low',
        resolved_findings: [], persisted_findings: [],
        scenario_deltas: [
          {
            scenario_id: 's1', before_passed: false, after_passed: true,
            before_decision: 'allow', after_decision: 'block', status: 'improved',
          },
          {
            scenario_id: 's2', before_passed: false, after_passed: true,
            before_decision: 'allow', after_decision: 'block', status: 'improved',
          },
        ],
      },
      business: [],
      remediation_bundle: {
        bundle_id: 'bundle-1', deployment_type: 'sandbox_policy',
        policies: [{ action_id: 'action-1', target_node: 'input', guard: 'input_firewall', parameters: { mode: 'strict' } }],
      },
      remediation_installation: {
        installation_id: 'install-1',
        audit_id: 'audit-1',
        bundle_id: 'bundle-1',
        bundle_sha256: 'a'.repeat(64),
        target_environment: 'audit_sandbox',
        status: 'installed',
        policy_ref: '/tmp/audit-1/remediation-policy.json',
        policy_sha256: 'b'.repeat(64),
        active_guards: ['input_firewall'],
        installed_action_ids: ['action-1'],
        installed_at: '2026-01-01T00:00:01Z',
      },
      round: {
        round_index: 1,
        parent_audit_id: null,
        attack_set_source: 'static_profile',
        benchmark_id: 'openmanus-security-v0.1',
        benchmark_version: 'v0.1',
        attack_count: 2,
        baseline_success_count: 2,
        guarded_success_count: 0,
        outcomes: [
          {
            scenario_id: 's1',
            attack_spec_id: 'openmanus:prompt_injection:s1',
            risk_surface: 'prompt_injection',
            predicted_node_id: 'tool:python_execute',
            predicted_path_id: 'path:input-to-python',
            baseline_attack_succeeded: true,
            baseline_failed_node_id: 'input_guard',
            guarded_attack_succeeded: false,
            guarded_failed_node_id: null,
            defense_guards: ['input_firewall'],
            baseline_trajectory_ref: 'base.json',
            guarded_trajectory_ref: 'guarded.json',
          },
          {
            scenario_id: 's2',
            attack_spec_id: 'openmanus:tool_tampering:s2',
            risk_surface: 'tool_abuse',
            predicted_node_id: 'tool:browser_use',
            predicted_path_id: 'path:input-to-browser',
            baseline_attack_succeeded: true,
            baseline_failed_node_id: 'tool:browser_use',
            guarded_attack_succeeded: false,
            guarded_failed_node_id: null,
            defense_guards: ['network_policy'],
            baseline_trajectory_ref: 'base-s2.json',
            guarded_trajectory_ref: 'guarded-s2.json',
          },
        ],
      },
      traces: [
        {
          trace_id: 'baseline:s1', phase: 'baseline', scenario_id: 's1', trajectory_ref: 'base.json',
          available: true, event_count: 5, truncated: false,
          events: [
            { event_id: 'e1', phase: 'baseline', scenario_id: 's1', stream: 'controlled', sequence: 0, event_type: 'llm_input', title: '恶意输入', summary: '忽略规则', metadata: {} },
            { event_id: 'e2', phase: 'baseline', scenario_id: 's1', stream: 'controlled', sequence: 1, event_type: 'llm_inference', title: 'LLM 推理', summary: '模型处理', metadata: { model: 'demo' } },
            { event_id: 'e3', phase: 'baseline', scenario_id: 's1', stream: 'controlled', sequence: 2, event_type: 'tool_call', title: '调用工具', metadata: {} },
            { event_id: 'e4', phase: 'baseline', scenario_id: 's1', stream: 'controlled', sequence: 3, event_type: 'guard_decision', title: 'Guard 放行', metadata: {} },
            { event_id: 'e5', phase: 'baseline', scenario_id: 's1', stream: 'controlled', sequence: 4, event_type: 'llm_output', title: '攻击成功', metadata: {} },
          ],
        },
        {
          trace_id: 'baseline:s2', phase: 'baseline', scenario_id: 's2', trajectory_ref: 'base-s2.json',
          available: true, event_count: 1, truncated: false,
          events: [{ event_id: 'e6', phase: 'baseline', scenario_id: 's2', stream: 'controlled', sequence: 0, event_type: 'tool_call', title: 'S2 工具越权', metadata: {} }],
        },
        {
          trace_id: 'guarded:s1', phase: 'guarded', scenario_id: 's1', trajectory_ref: 'guarded.json',
          available: true, event_count: 1, truncated: false,
          events: [{ event_id: 'e2', phase: 'guarded', scenario_id: 's1', stream: 'guard', sequence: 1, event_type: 'blocked', title: '请求已拦截', metadata: {} }],
        },
        {
          trace_id: 'guarded:s2', phase: 'guarded', scenario_id: 's2', trajectory_ref: 'guarded-s2.json',
          available: true, event_count: 1, truncated: false,
          events: [{ event_id: 'e7', phase: 'guarded', scenario_id: 's2', stream: 'guard', sequence: 0, event_type: 'guard_decision', title: 'S2 已阻断', metadata: {} }],
        },
        {
          trace_id: 'guarded:s3', phase: 'guarded', scenario_id: 's3', trajectory_ref: 'guarded-s3.json',
          available: true, event_count: 1, truncated: false,
          events: [{ event_id: 'e8', phase: 'guarded', scenario_id: 's3', stream: 'guard', sequence: 0, event_type: 'blocked', title: 'S3 仅有防护轨迹', metadata: {} }],
        },
      ],
    } as AuditDetailData

    render(<AuditReport data={data} />)

    expect(screen.getAllByText('input_firewall').length).toBeGreaterThan(0)
    expect(screen.getByText('防护已挂载并用于本轮复测')).toBeInTheDocument()
    expect(screen.getByText('已挂载')).toBeInTheDocument()
    expect(screen.getByText('修复后复测')).toBeInTheDocument()
    expect(screen.getByText('防护有效但需复测')).toBeInTheDocument()
    expect(screen.getByText('部署环境未验证')).toBeInTheDocument()
    expect(screen.getByText('仅覆盖当前基准')).toBeInTheDocument()
    expect(screen.getByText('不完整')).toBeInTheDocument()
    expect(screen.getAllByText('prompt_injection').length).toBeGreaterThan(0)
    expect(screen.getAllByText('input_guard').length).toBeGreaterThan(0)
    expect(screen.getByText('第 1 轮攻击矩阵')).toBeInTheDocument()
    expect(screen.getByText('tool:python_execute')).toBeInTheDocument()
    expect(screen.getByText('失效：input_guard')).toBeInTheDocument()
    expect(screen.getAllByText('已阻断').length).toBeGreaterThan(0)
    expect(screen.getAllByText('攻击成功').length).toBeGreaterThan(0)
    expect(screen.getByText('结果')).toBeInTheDocument()
    expect(screen.getAllByTestId('path-node')).toHaveLength(5)
    fireEvent.click(screen.getByText('LLM 推理'))
    expect(screen.getByText('模型处理')).toBeVisible()
    expect(screen.getByText('demo')).toBeVisible()

    const scenarioButton = screen.getByRole('button', { name: '查看轨迹：s2' })
    expect(scenarioButton.closest('article')).toHaveTextContent('已改善')
    fireEvent.click(scenarioButton)
    expect(screen.getByText('S2 工具越权')).toBeInTheDocument()
    expect(screen.getAllByTestId('path-node')).toHaveLength(1)

    fireEvent.click(screen.getByRole('button', { name: '防护后' }))
    expect(screen.getByText('S2 已阻断')).toBeInTheDocument()
    expect(screen.getByTestId('attack-path')).toHaveClass('guarded')

    fireEvent.click(screen.getByRole('button', { name: '防护前' }))
    fireEvent.click(screen.getByRole('button', { name: '查看轨迹：s3' }))
    expect(screen.getByRole('button', { name: '防护后' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText('S3 仅有防护轨迹')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '防护前' }))
    expect(screen.getAllByText('攻击成功').length).toBeGreaterThan(0)
  })
})
