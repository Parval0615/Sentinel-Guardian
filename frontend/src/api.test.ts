import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, loadAuditDetail, onUnauthorized, tokenStore } from './api'

const completedWorkspace = {
  baseline_report: { scenario_results: [] },
  guarded_report: { scenario_results: [] },
  decision: {
    decision_id: 'decision-1',
    audit_id: 'audit-1',
    decision: 'allow_release',
    reasons: ['验证通过'],
    unresolved_risks: [],
    limitations: [],
    evidence_complete: true,
  },
}

describe('typed API client', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    tokenStore.clear()
  })

  it('持久化 token 并为受保护请求添加 Bearer header', async () => {
    tokenStore.set('test-token', true)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await api.listAudits()

    expect(localStorage.getItem('sentinel.auth.token')).toBe('test-token')
    expect(fetch).toHaveBeenCalledWith('/v1/audits', expect.objectContaining({
      headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
    }))
  })

  it('401 同步清理 token 并通知 React 会话', async () => {
    tokenStore.set('expired-token')
    const unauthorized = vi.fn()
    const unsubscribe = onUnauthorized(unauthorized)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ detail: '登录已过期' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(api.listAudits()).rejects.toMatchObject({ status: 401 })

    expect(tokenStore.get()).toBeNull()
    expect(unauthorized).toHaveBeenCalledOnce()
    unsubscribe()
  })

  it('请求审计详情约定的全部资源', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await Promise.all([
      api.getStatus('audit 1'),
      api.getPlan('audit 1'),
      api.getVerdict('audit 1'),
      api.getBusiness('audit 1', 'guarded'),
      api.getEvidence('audit 1'),
    ])

    const paths = mock.mock.calls.map(([path]) => path)
    expect(paths).toEqual(expect.arrayContaining([
      '/v1/audits/audit%201/status',
      '/v1/audits/audit%201/plan',
      '/v1/audits/audit%201/verdict',
      '/v1/audits/audit%201/business/guarded',
      '/v1/audits/audit%201/evidence',
    ]))
  })

  it('通过 Demo 接口接入内置 ecommerce_demo Agent', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ agent_id: 'ecommerce_customer_guide' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await api.registerDemoAgent()

    expect(mock).toHaveBeenCalledWith('/v1/demo/agents/ecommerce', expect.objectContaining({
      method: 'POST',
    }))
  })

  it('创建审计时先生成待审阅攻击集', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ audit_id: 'audit-202', state: 'created' }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(api.createAudit({} as never)).resolves.toEqual(
      expect.objectContaining({ audit_id: 'audit-202' }),
    )
    expect(mock).toHaveBeenCalledWith(
      '/v1/audits?prepare_only=true',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('从当前审计生成待审阅的下一轮攻击集', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ audit_id: 'audit-next', state: 'created' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await api.createNextAuditRound('audit 1')

    expect(mock).toHaveBeenCalledWith(
      '/v1/audits/audit%201/next-round?prepare_only=true',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('批准攻击集后启动后台正式审计', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        audit_id: 'audit-review',
        state: 'attack_review',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await api.executeAudit('audit review')

    expect(mock).toHaveBeenCalledWith(
      '/v1/audits/audit%20review/execute?background=true',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('从检查点后台恢复失败审计', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        audit_id: 'audit-failed',
        state: 'failed',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await api.resumeAudit('audit failed')

    expect(mock).toHaveBeenCalledWith(
      '/v1/audits/audit%20failed/resume?background=true',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('配置 OpenManus 运行凭据时不混入审计任务', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        configured: true,
        base_url: 'https://models.example.test',
        model: 'competition-model',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await api.configureOpenManusRuntime({
      api_key: 'secret',
      base_url: 'https://models.example.test/v1',
      model: 'competition-model',
    })

    expect(mock).toHaveBeenCalledWith(
      '/v1/runtime/openmanus/config',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          api_key: 'secret',
          base_url: 'https://models.example.test/v1',
          model: 'competition-model',
        }),
      }),
    )
  })

  it('测试指定 Agent 角色的模型配置', async () => {
    const response = {
      role: 'attack',
      configured: true,
      tested: true,
      base_url: 'https://models.example.test/v1',
      model: 'competition-model',
      tested_at: '2026-01-01T00:00:00Z',
    }
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(api.testModelRuntimeConfiguration('attack', {
      api_key: 'secret',
      base_url: 'https://models.example.test/v1',
      model: 'competition-model',
    })).resolves.toEqual(response)

    expect(mock).toHaveBeenCalledWith(
      '/v1/runtime/models/attack/test',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          api_key: 'secret',
          base_url: 'https://models.example.test/v1',
          model: 'competition-model',
        }),
      }),
    )
  })

  it('读取指定 Agent 的正式审计预检状态', async () => {
    const response = {
      agent_id: 'openmanus official',
      adapter_type: 'openmanus',
      ready: false,
      checked_at: '2026-01-01T00:00:00Z',
      checks: [{
        check_id: 'docker_daemon',
        status: 'blocked',
        message: 'Docker daemon is unavailable.',
      }],
    }
    const mock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(api.getAuditPreflight('openmanus official')).resolves.toEqual(
      response,
    )
    expect(mock).toHaveBeenCalledWith(
      '/v1/runtime/audit-preflight/openmanus%20official',
      expect.objectContaining({ headers: {} }),
    )
  })

  it('上传镜像时传递可选 Python 探针模块', async () => {
    let openedUrl = ''
    class MockXMLHttpRequest {
      status = 202
      responseText = JSON.stringify({
        schema_version: 'agent-image-import-response-v0.1',
      })
      upload = { onprogress: null }
      onerror: (() => void) | null = null
      onload: (() => void) | null = null

      open(_method: string, url: string) {
        openedUrl = url
      }

      setRequestHeader() {}

      send() {
        this.onload?.()
      }
    }
    vi.stubGlobal('XMLHttpRequest', MockXMLHttpRequest)

    await api.uploadAgentImage({
      file: new File(['archive'], 'openmanus.tar'),
      agentId: 'openmanus',
      name: 'OpenManus',
      domain: 'general',
      expectedFrameworks: ['OpenManus'],
      probeModule: 'redsentinel_runtime.profile_probe_entry',
    }, vi.fn())

    expect(openedUrl).toContain(
      'probe_module=redsentinel_runtime.profile_probe_entry',
    )
  })

  it('加载详情时不再请求 decision 资源', async () => {
    const mock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (path) =>
      new Response(JSON.stringify(String(path).endsWith('/workspace') ? completedWorkspace : {}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await loadAuditDetail('audit-1')

    const paths = mock.mock.calls.map(([path]) => path)
    expect(paths).not.toContain('/v1/audits/audit-1/decision')
    expect(paths).toContain('/v1/audits/audit-1/verdict')
  })

  it('从 workspace 接入正式决策并显式校验 Baseline/Guarded 报告', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (path) =>
      new Response(JSON.stringify(String(path).endsWith('/workspace')
        ? { ...completedWorkspace, guarded_report: null }
        : {}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(loadAuditDetail('audit-1')).rejects.toThrow(
      '已完成审计缺少 Baseline 或 Guarded 报告',
    )
  })

  it('业务报告 404 转为 null 并从详情中省略', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (path) => {
      const value = String(path)
      if (value.includes('/business/')) {
        return new Response(JSON.stringify({ detail: '不存在' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response(JSON.stringify(value.endsWith('/workspace') ? completedWorkspace : {}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    await expect(loadAuditDetail('audit-1')).resolves.toMatchObject({ business: [] })
  })

  it('verdict 摘要缺失时从工作区报告生成展示摘要', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (path) => {
      const value = String(path)
      if (value.endsWith('/verdict') || value.includes('/business/')) {
        return new Response(JSON.stringify({ detail: '不存在' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      const workspace = {
        ...completedWorkspace,
        run: { agent_id: 'agent-1' },
        baseline_report: {
          attack_success_rate: 0.75,
          scenario_results: [],
        },
        guarded_report: {
          attack_success_rate: 0.25,
          false_positive_rate: 0.1,
          scenario_results: [],
        },
        comparison: {
          scenario_deltas: [
            { status: 'improved' },
            { status: 'unchanged_fail' },
          ],
        },
      }
      return new Response(JSON.stringify(value.endsWith('/workspace')
        ? workspace
        : {}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    await expect(loadAuditDetail('audit-1')).resolves.toMatchObject({
      verdict: {
        agent_id: 'agent-1',
        baseline_asr: 0.75,
        guarded_asr: 0.25,
        business_utility: 0.9,
        repaired_scenario_count: 1,
        conclusion: 'effective',
        evidence_status: 'complete',
      },
    })
  })

  it('业务报告仅将 404 转为 null，其他错误继续抛出', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (path) => {
      const value = String(path)
      if (value.endsWith('/business/baseline')) {
        return new Response(JSON.stringify({ detail: '服务异常' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (value.includes('/business/')) {
        return new Response(JSON.stringify({ detail: '不存在' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response(JSON.stringify(value.endsWith('/workspace') ? completedWorkspace : {}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    await expect(loadAuditDetail('audit-1')).rejects.toMatchObject({ status: 500 })
  })
})
