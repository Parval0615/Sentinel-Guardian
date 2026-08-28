import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import dagre from '@dagrejs/dagre'
import {
  Background, MarkerType, Panel, ReactFlow, ReactFlowProvider, useReactFlow,
  type Edge, type Node,
} from '@xyflow/react'
import { Focus, Minus, Plus, RotateCcw } from 'lucide-react'
import '@xyflow/react/dist/style.css'
import type {
  ImageAgentProfile, ImageProfileEdge, ImageProfileNode, ProfileEvidenceItem,
  ProfileRiskLevel, ProfileRiskPath, ProfileVerificationStatus,
} from './types'

const NODE_WIDTH = 190
const NODE_HEIGHT = 76
const GRAPH_LIMIT = 80
const GRAPH_EDGE_LIMIT = 160
const riskOrder: Record<ProfileRiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 }

type Selection =
  | { kind: 'node'; value: ImageProfileNode }
  | { kind: 'edge'; value: ImageProfileEdge }

interface Filters {
  nodeType: string
  risk: string
  verification: string
  framework: string
}

const emptyFilters: Filters = { nodeType: 'all', risk: 'all', verification: 'all', framework: 'all' }

function highestRiskPath(paths: ProfileRiskPath[]) {
  return [...paths].sort((a, b) =>
    riskOrder[b.risk_level] - riskOrder[a.risk_level]
    || b.confidence - a.confidence
    || a.path_id.localeCompare(b.path_id),
  )[0]
}

function layoutGraph(nodes: Node[], edges: Edge[]) {
  const graph = new dagre.graphlib.Graph()
  graph.setDefaultEdgeLabel(() => ({}))
  graph.setGraph({ rankdir: 'LR', ranksep: 78, nodesep: 34, marginx: 28, marginy: 28 })
  nodes.forEach((node) => graph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }))
  edges.forEach((edge) => graph.setEdge(edge.source, edge.target))
  dagre.layout(graph)
  return nodes.map((node) => {
    const point = graph.node(node.id)
    return {
      ...node,
      position: { x: point.x - NODE_WIDTH / 2, y: point.y - NODE_HEIGHT / 2 },
    }
  })
}

function GraphControls() {
  const { fitView, zoomIn, zoomOut } = useReactFlow()
  return <Panel position="top-right" className="profile-graph-controls">
    <button type="button" aria-label="放大图谱" title="放大" onClick={() => zoomIn()}><Plus size={15} /></button>
    <button type="button" aria-label="缩小图谱" title="缩小" onClick={() => zoomOut()}><Minus size={15} /></button>
    <button type="button" aria-label="适配图谱视图" title="适配视图" onClick={() => fitView({ padding: 0.18 })}>
      <Focus size={15} />
    </button>
  </Panel>
}

function EvidenceList({ items }: { items: ProfileEvidenceItem[] }) {
  if (!items.length) return <p className="graph-detail-empty">没有可用证据引用。</p>
  return <div className="graph-evidence-list">
    {items.map((item) => <article key={item.evidence_id}>
      <header><strong>{item.method}</strong><code>{item.evidence_id}</code></header>
      <p>{item.summary || '未提供证据摘要'}</p>
      <dl>
        <div><dt>提取器</dt><dd>{item.extractor}</dd></div>
        <div><dt>来源</dt><dd>{evidenceSource(item)}</dd></div>
        <div><dt>内容哈希</dt><dd><code>{item.content_sha256.slice(0, 16)}…</code></dd></div>
      </dl>
    </article>)}
  </div>
}

function evidenceSource(item: ProfileEvidenceItem) {
  const { locator } = item
  const location = locator.image_path || locator.python_module || locator.package_metadata_key
    || locator.config_key || locator.event_id || '未知来源'
  const symbol = locator.symbol ? ` · ${locator.symbol}` : ''
  const lines = locator.line_start ? `:${locator.line_start}-${locator.line_end}` : ''
  return `${location}${symbol}${lines}`
}

function GraphDetail({ profile, selection }: { profile: ImageAgentProfile; selection?: Selection }) {
  if (!selection) {
    return <aside className="profile-graph-detail" aria-label="图谱对象详情">
      <div className="graph-detail-empty">选择节点或边以检查证据和权限。</div>
    </aside>
  }
  const item = selection.value
  const evidence = profile.evidence.filter((candidate) => item.evidence_refs.includes(candidate.evidence_id))
  const permissionIds = selection.kind === 'node'
    ? selection.value.permission_ids
    : [...new Set(profile.nodes
      .filter((node) => [selection.value.source_node_id, selection.value.target_node_id].includes(node.node_id))
      .flatMap((node) => node.permission_ids))]
  const permissions = profile.permissions.filter((permission) => permissionIds.includes(permission.permission_id))

  return <aside className="profile-graph-detail" aria-label="图谱对象详情" aria-live="polite">
    <header>
      <span>{selection.kind === 'node' ? '节点详情' : '边详情'}</span>
      <h3>{selection.kind === 'node' ? selection.value.name : selection.value.edge_type}</h3>
      <code>{selection.kind === 'node' ? selection.value.node_id : selection.value.edge_id}</code>
    </header>
    <dl className="graph-detail-facts">
      <div><dt>验证状态</dt><dd><Verification value={item.verification_status} /></dd></div>
      <div><dt>置信度</dt><dd>{Math.round(item.confidence * 100)}%</dd></div>
      {selection.kind === 'node'
        ? <><div><dt>节点类型</dt><dd>{selection.value.node_type}</dd></div>
          <div><dt>风险</dt><dd><Risk value={selection.value.risk_level} /></dd></div></>
        : <><div><dt>来源</dt><dd>{selection.value.source_node_id}</dd></div>
          <div><dt>目标</dt><dd>{selection.value.target_node_id}</dd></div>
          <div><dt>条件</dt><dd>{selection.value.condition || '无'}</dd></div></>}
      <div><dt>权限</dt><dd>{permissions.length ? permissions.map((permission) =>
        `${permission.permission_type} · ${permission.scope}`).join('；') : '未关联权限'}</dd></div>
    </dl>
    <section>
      <h4>证据与来源</h4>
      <EvidenceList items={evidence} />
    </section>
  </aside>
}

function Risk({ value }: { value: ProfileRiskLevel }) {
  return <span className={`graph-state risk-${value}`}>{riskName(value)}</span>
}

function Verification({ value }: { value: ProfileVerificationStatus }) {
  return <span className={`graph-state verification-${value}`}>{verificationName(value)}</span>
}

function ProfileTable({ nodes, edges, onSelect }: {
  nodes: ImageProfileNode[]
  edges: ImageProfileEdge[]
  onSelect: (selection: Selection) => void
}) {
  return <div className="profile-structure-tables">
    <section aria-labelledby="profile-node-table-title">
      <h3 id="profile-node-table-title">节点</h3>
      <table className="profile-data-table" aria-label="Agent 图谱节点">
        <thead><tr><th>名称 / ID</th><th>类型</th><th>风险</th><th>验证</th><th>置信度</th></tr></thead>
        <tbody>{nodes.map((node) => <tr key={node.node_id}>
          <td><button type="button" onClick={() => onSelect({ kind: 'node', value: node })}>
            <strong>{node.name}</strong><code>{node.node_id}</code>
          </button></td>
          <td data-label="类型">{node.node_type}</td>
          <td data-label="风险"><Risk value={node.risk_level} /></td>
          <td data-label="验证"><Verification value={node.verification_status} /></td>
          <td data-label="置信度">{Math.round(node.confidence * 100)}%</td>
        </tr>)}</tbody>
      </table>
    </section>
    <section aria-labelledby="profile-edge-table-title">
      <h3 id="profile-edge-table-title">关系</h3>
      <table className="profile-data-table edge-table" aria-label="Agent 图谱关系">
        <thead><tr><th>关系</th><th>来源</th><th>目标</th><th>验证</th><th>置信度</th></tr></thead>
        <tbody>{edges.map((edge) => <tr key={edge.edge_id}>
          <td><button type="button" onClick={() => onSelect({ kind: 'edge', value: edge })}>
            <strong>{edge.edge_type}</strong><code>{edge.edge_id}</code>
          </button></td>
          <td data-label="来源">{edge.source_node_id}</td>
          <td data-label="目标">{edge.target_node_id}</td>
          <td data-label="验证"><Verification value={edge.verification_status} /></td>
          <td data-label="置信度">{Math.round(edge.confidence * 100)}%</td>
        </tr>)}</tbody>
      </table>
    </section>
    {!nodes.length && <div className="graph-detail-empty">当前筛选条件下没有节点。</div>}
  </div>
}

export function AgentProfileGraph({ profile }: { profile: ImageAgentProfile }) {
  const defaultPath = useMemo(() => highestRiskPath(profile.risk_paths), [profile.risk_paths])
  const [view, setView] = useState<'graph' | 'table'>('graph')
  const [pathId, setPathId] = useState(defaultPath?.path_id ?? 'overview')
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [selection, setSelection] = useState<Selection | undefined>(() => {
    const sink = profile.nodes.find((node) => node.node_id === defaultPath?.sink_node_id)
    return sink ? { kind: 'node', value: sink } : undefined
  })

  const visible = useMemo(() => {
    const path = profile.risk_paths.find((item) => item.path_id === pathId)
    let candidateIds: Set<string>
    if (path) {
      candidateIds = new Set(path.node_ids.slice(0, GRAPH_LIMIT))
      profile.edges.forEach((edge) => {
        if (candidateIds.size < GRAPH_LIMIT
          && (candidateIds.has(edge.source_node_id) || candidateIds.has(edge.target_node_id))) {
          candidateIds.add(edge.source_node_id)
          if (candidateIds.size < GRAPH_LIMIT) candidateIds.add(edge.target_node_id)
        }
      })
    } else {
      candidateIds = new Set(profile.nodes
        .slice()
        .sort((a, b) => riskOrder[b.risk_level] - riskOrder[a.risk_level] || a.node_id.localeCompare(b.node_id))
        .slice(0, GRAPH_LIMIT)
        .map((node) => node.node_id))
    }
    const nodes = profile.nodes.filter((node) =>
      candidateIds.has(node.node_id)
      && (filters.nodeType === 'all' || node.node_type === filters.nodeType)
      && (filters.risk === 'all' || node.risk_level === filters.risk)
      && (filters.verification === 'all' || node.verification_status === filters.verification)
      && (filters.framework === 'all' || node.framework_ids.includes(filters.framework)))
    const nodeIds = new Set(nodes.map((node) => node.node_id))
    const edges = profile.edges.filter((edge) =>
      nodeIds.has(edge.source_node_id) && nodeIds.has(edge.target_node_id)
      && (filters.verification === 'all' || edge.verification_status === filters.verification))
      .slice(0, GRAPH_EDGE_LIMIT)
    return { nodes, edges, cropped: candidateIds.size < profile.nodes.length }
  }, [filters, pathId, profile])

  const flow = useMemo(() => {
    const path = profile.risk_paths.find((item) => item.path_id === pathId)
    const pathNodes = new Set(path?.node_ids ?? [])
    const pathEdges = new Set(path?.edge_ids ?? [])
    const nodes: Node[] = visible.nodes.map((node) => ({
      id: node.node_id,
      position: { x: 0, y: 0 },
      data: {
        label: <div className="profile-flow-label">
          <span>{node.node_type}</span><strong>{node.name}</strong>
          <small>{riskName(node.risk_level)} · {verificationName(node.verification_status)}</small>
        </div>,
      },
      ariaLabel: `${node.name}，${node.node_type}，${riskName(node.risk_level)}，${verificationName(node.verification_status)}`,
      className: [
        'profile-flow-node', `risk-${node.risk_level}`, `verification-${node.verification_status}`,
        pathNodes.has(node.node_id) ? 'on-risk-path' : '',
      ].filter(Boolean).join(' '),
      style: { width: NODE_WIDTH, height: NODE_HEIGHT },
    }))
    const edges: Edge[] = visible.edges.map((edge) => ({
      id: edge.edge_id,
      source: edge.source_node_id,
      target: edge.target_node_id,
      label: edge.edge_type,
      ariaLabel: `${edge.source_node_id} ${edge.edge_type} ${edge.target_node_id}`,
      focusable: true,
      markerEnd: { type: MarkerType.ArrowClosed, color: pathEdges.has(edge.edge_id) ? '#181818' : '#9b9b98' },
      className: pathEdges.has(edge.edge_id) ? 'profile-flow-edge on-risk-path' : 'profile-flow-edge',
    }))
    return { nodes: layoutGraph(nodes, edges), edges }
  }, [pathId, profile.risk_paths, visible])

  useEffect(() => {
    if (selection?.kind === 'node' && !visible.nodes.some((node) => node.node_id === selection.value.node_id)) {
      setSelection(undefined)
    }
  }, [selection, visible.nodes])

  function handleTabKey(event: KeyboardEvent<HTMLDivElement>) {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
    event.preventDefault()
    const next = event.key === 'ArrowLeft' || event.key === 'Home' ? 'graph' : 'table'
    setView(next)
    document.getElementById(`profile-${next}-tab`)?.focus()
  }

  const nodeTypes = [...new Set(profile.nodes.map((node) => node.node_type))].sort()
  const filtersActive = Object.values(filters).some((value) => value !== 'all')

  return <section className="profile-graph-section" aria-labelledby="profile-graph-title">
    <header className="profile-graph-header">
      <div><h2 id="profile-graph-title">Agent 图谱</h2>
        <p>{defaultPath ? `默认聚焦最高风险路径：${defaultPath.path_id}` : '当前画像没有已识别风险路径'}</p></div>
      <div className="profile-view-tabs" role="tablist" aria-label="画像视图" onKeyDown={handleTabKey}>
        {(['graph', 'table'] as const).map((item) => <button type="button" role="tab"
          id={`profile-${item}-tab`} aria-selected={view === item} tabIndex={view === item ? 0 : -1}
          aria-controls={`profile-${item}-panel`} key={item} onClick={() => setView(item)}>
          {item === 'graph' ? '图谱' : '结构化表格'}
        </button>)}
      </div>
    </header>
    <div className="profile-graph-filters" aria-label="图谱筛选">
      <label><span>风险路径</span><select aria-label="按风险路径裁剪" value={pathId} onChange={(event) => setPathId(event.target.value)}>
        <option value="overview">高风险概览（最多 {GRAPH_LIMIT} 节点）</option>
        {[...profile.risk_paths].sort((a, b) => riskOrder[b.risk_level] - riskOrder[a.risk_level])
          .map((path) => <option value={path.path_id} key={path.path_id}>{riskName(path.risk_level)} · {path.path_id}</option>)}
      </select></label>
      <label><span>节点类型</span><select aria-label="按节点类型筛选" value={filters.nodeType}
        onChange={(event) => setFilters((current) => ({ ...current, nodeType: event.target.value }))}>
        <option value="all">全部类型</option>{nodeTypes.map((value) => <option key={value}>{value}</option>)}
      </select></label>
      <label><span>风险</span><select aria-label="按风险级别筛选" value={filters.risk}
        onChange={(event) => setFilters((current) => ({ ...current, risk: event.target.value }))}>
        <option value="all">全部风险</option>{(['critical', 'high', 'medium', 'low'] as const)
          .map((value) => <option value={value} key={value}>{riskName(value)}</option>)}
      </select></label>
      <label><span>验证</span><select aria-label="按验证状态筛选" value={filters.verification}
        onChange={(event) => setFilters((current) => ({ ...current, verification: event.target.value }))}>
        <option value="all">全部状态</option>{(['verified', 'supported', 'inferred', 'rejected'] as const)
          .map((value) => <option value={value} key={value}>{verificationName(value)}</option>)}
      </select></label>
      <label><span>框架</span><select aria-label="按框架筛选" value={filters.framework}
        onChange={(event) => setFilters((current) => ({ ...current, framework: event.target.value }))}>
        <option value="all">全部框架</option>{profile.frameworks.map((framework) =>
          <option value={framework.framework_id} key={framework.framework_id}>{framework.name}</option>)}
      </select></label>
      <button type="button" className="toolbar-icon-button" disabled={!filtersActive}
        aria-label="重置图谱筛选" title="重置筛选" onClick={() => setFilters(emptyFilters)}><RotateCcw size={15} /></button>
    </div>
    {visible.cropped && <p className="graph-crop-note" role="status">
      已按风险路径或风险优先级裁剪大图，当前显示 {visible.nodes.length} / {profile.nodes.length} 个节点。
    </p>}
    <div className="profile-graph-layout">
      <div id={`profile-${view}-panel`} role="tabpanel" aria-labelledby={`profile-${view}-tab`} className="profile-graph-viewport">
        {!visible.nodes.length ? <div className="graph-detail-empty">当前筛选条件下没有图谱对象，请重置筛选。</div>
          : view === 'graph' ? <ReactFlowProvider><ReactFlow
            nodes={flow.nodes} edges={flow.edges} fitView fitViewOptions={{ padding: 0.18 }}
            minZoom={0.25} maxZoom={1.8} nodesDraggable={false} nodesConnectable={false}
            elementsSelectable onNodeClick={(_, node) => {
              const value = profile.nodes.find((item) => item.node_id === node.id)
              if (value) setSelection({ kind: 'node', value })
            }} onEdgeClick={(_, edge) => {
              const value = profile.edges.find((item) => item.edge_id === edge.id)
              if (value) setSelection({ kind: 'edge', value })
            }} aria-label="可交互 Agent 节点图">
            <Background color="#dededb" gap={20} size={1} />
            <GraphControls />
          </ReactFlow></ReactFlowProvider>
            : <ProfileTable nodes={visible.nodes} edges={visible.edges} onSelect={setSelection} />}
      </div>
      <GraphDetail profile={profile} selection={selection} />
    </div>
  </section>
}

const riskName = (value: ProfileRiskLevel) => ({
  low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险',
})[value]

const verificationName = (value: ProfileVerificationStatus) => ({
  verified: '已验证', supported: '有证据支持', inferred: '推断', rejected: '已否定',
})[value]
