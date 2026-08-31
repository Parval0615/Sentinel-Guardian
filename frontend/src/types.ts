export type AuditState =
  | 'created' | 'profiling' | 'planning' | 'attack_review' | 'baseline_execution'
  | 'defense_generation' | 'guarded_execution' | 'decision'
  | 'needs_approval' | 'completed' | 'failed' | 'busy'

export interface User {
  user_id: string
  username: string
  email: string
  role: 'user' | 'admin'
}

export interface AuthResponse {
  access_token: string
  token_type: 'bearer'
  expires_in: number
  user: User
}

export interface Agent {
  agent_id: string
  name: string
  domain: string
  framework: string
  adapter_type: string
  integration_type: string
  status: string
  created_at: string
  remarks?: string | null
  data_boundary?: Record<string, unknown>
}

export interface AgentTool {
  name: string
  risk_level: string
  description: string
}

export interface AgentProfileNode {
  node_id: string
  node_type: string
  required: boolean
  critical: boolean
  risk_surfaces: string[]
  defenses: string[]
}

export interface LegacyAgentProfile {
  profile_id: string
  tenant_id: string
  agent_id: string
  agent_type: string
  created_at: string
  nodes: AgentProfileNode[]
  tools: AgentTool[]
  rag: Record<string, unknown>
  memory: Record<string, unknown>
  data_boundary: Record<string, unknown>
  risk_surface: string[]
  generated_at: string
}

export type ProfileRiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type ProfileVerificationStatus = 'verified' | 'supported' | 'inferred' | 'rejected'
export type ProfileAnalysisStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed'
export type ProfileStageName =
  | 'inventory' | 'unpack' | 'static_extract' | 'framework_detect'
  | 'graph_reconstruct' | 'semantic_enrich' | 'dynamic_verify' | 'finalize'

export interface ProfileClaim {
  evidence_refs: string[]
  confidence: number
  verification_status: ProfileVerificationStatus
}

export interface ProfileAnalysisStage {
  stage: ProfileStageName
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  started_at?: string | null
  completed_at?: string | null
  checkpoint_ref?: string | null
}

export interface ProfileAnalysisError {
  error_id: string
  stage: ProfileStageName
  code: string
  message: string
  retryable: boolean
  details: Record<string, string | number | boolean | null>
}

export interface ImageProfileStatus {
  schema_version: 'image-analysis-status-v0.1'
  analysis_id: string
  agent_id: string
  image_digest: string
  status: ProfileAnalysisStatus
  stages: ProfileAnalysisStage[]
  errors: ProfileAnalysisError[]
}

export interface ProfileFramework extends ProfileClaim {
  framework_id: string
  name: string
  version?: string | null
}

export interface ImageProfileNode extends ProfileClaim {
  node_id: string
  node_type: string
  name: string
  framework_ids: string[]
  capability_ids: string[]
  permission_ids: string[]
  control_ids: string[]
  risk_level: ProfileRiskLevel
}

export interface ImageProfileEdge extends ProfileClaim {
  edge_id: string
  edge_type: string
  source_node_id: string
  target_node_id: string
  condition?: string | null
}

export interface ProfileCapability extends ProfileClaim {
  capability_id: string
  name: string
  operation: string
  node_ids: string[]
  risk_level: ProfileRiskLevel
}

export interface ProfilePermission extends ProfileClaim {
  permission_id: string
  permission_type: string
  operations: string[]
  scope: string
  node_ids: string[]
  capability_ids: string[]
  risk_level: ProfileRiskLevel
}

export interface ProfileControl extends ProfileClaim {
  control_id: string
  control_type: string
  name: string
  node_ids: string[]
  description: string
}

export interface ProfileRiskPath extends ProfileClaim {
  path_id: string
  source_node_id: string
  sink_node_id: string
  node_ids: string[]
  edge_ids: string[]
  capability_ids: string[]
  permission_ids: string[]
  control_ids: string[]
  applicable_threats: string[]
  control_gaps: string[]
  risk_level: ProfileRiskLevel
}

export interface ProfileEvidenceItem {
  evidence_id: string
  artifact_digest: string
  layer_digest?: string | null
  locator: {
    image_path?: string | null
    python_module?: string | null
    symbol?: string | null
    line_start?: number | null
    line_end?: number | null
    package_metadata_key?: string | null
    config_key?: string | null
    event_id?: string | null
  }
  extractor: string
  method: 'image_config' | 'package_metadata' | 'static' | 'framework' | 'semantic' | 'dynamic'
  trust_level?: 'static' | 'attested' | 'observed'
  content_sha256: string
  summary?: string | null
}

export interface ImageAgentProfile {
  schema_version: 'agent-profile-v0.2'
  profile_id: string
  profile_sha256?: string
  tenant_id: string
  agent_id: string
  generated_at: string
  image: ProfileClaim & {
    digest: string
    os: string
    architecture: string
    variant?: string | null
    created_at?: string | null
    entrypoint: string[]
    command: string[]
    working_directory: string
    environment_variables: string[]
    layer_digests: string[]
  }
  analysis: ImageProfileStatus
  frameworks: ProfileFramework[]
  nodes: ImageProfileNode[]
  edges: ImageProfileEdge[]
  capabilities: ProfileCapability[]
  permissions: ProfilePermission[]
  controls: ProfileControl[]
  evidence: ProfileEvidenceItem[]
  risk_paths: ProfileRiskPath[]
  limitations: Array<{ code: string; message: string; evidence_refs: string[] }>
  completeness?: {
    static_source_recovery: 'complete' | 'partial' | 'metadata_only' | 'bytecode_only' | 'none'
    framework_coverage: ProfileCoverageStatistic
    graph_evidence_coverage: ProfileCoverageStatistic
    dynamic_corroboration_coverage: ProfileCoverageStatistic
    dynamic_behavior_coverage: ProfileCoverageStatistic
    unresolved_limitations: number
    blocking_limitations: string[]
    conclusion: 'complete' | 'partial'
  }
}

export interface ProfileCoverageStatistic {
  covered: number
  total: number
  ratio: number
}

export interface ImageProfileCreation {
  schema_version: 'image-profile-create-response-v0.1'
  analysis: ImageProfileStatus
  cached: boolean
}

export interface AgentImageImportResult {
  schema_version: 'agent-image-import-response-v0.1'
  agent: Agent
  profile: ImageProfileCreation
}

export interface AgentImageUploadInput {
  file: File
  agentId?: string
  name?: string
  domain: string
  expectedFrameworks: string[]
  probeModule?: string
}

export type AgentProfile = LegacyAgentProfile | ImageAgentProfile

export function isImageAgentProfile(profile: AgentProfile): profile is ImageAgentProfile {
  return 'schema_version' in profile && profile.schema_version === 'agent-profile-v0.2'
}

export interface AuditRun {
  audit_id: string
  parent_audit_id?: string | null
  round_index?: number
  tenant_id: string
  agent_id: string
  image_digest?: string | null
  profile_id?: string | null
  profile_sha256?: string | null
  state: AuditState
  baseline_evaluation_id?: string | null
  guarded_evaluation_id?: string | null
  comparison_id?: string | null
  created_at: string
  updated_at: string
  error?: string | null
}

export interface AuditTaskInput {
  agent_id: string
  image_digest?: string
  profile_id?: string
  profile_sha256?: string
  benchmark_id: string
  benchmark_version?: string
  runtime_mode: 'sdk' | 'openmanus_real'
  security_goals: string[]
  authorized_risk_surfaces: string[]
  normal_tasks: Array<{
    task_id: string
    prompt: string
    success_criteria: string[]
    oracle: {
      required_answer_substrings: string[]
      required_business_events: string[]
    }
  }>
  seed: number
  auto_harden: boolean
}

export interface OpenManusRuntimeConfiguration {
  api_key: string
  base_url: string
  model: string
}

export interface OpenManusRuntimeStatus {
  configured: boolean
  base_url?: string | null
  model?: string | null
}

export type ModelRuntimeRole = 'target' | 'attack' | 'defense'

export interface ModelRuntimeConfiguration {
  api_key: string
  base_url: string
  model: string
}

export interface ModelRuntimeStatus {
  role: ModelRuntimeRole
  configured: boolean
  tested: boolean
  base_url?: string | null
  model?: string | null
  tested_at?: string | null
  error?: string | null
}

export interface AuditPreflightCheck {
  check_id: string
  status: 'ready' | 'blocked' | 'not_required'
  message: string
  detail?: string | null
}

export interface AuditPreflightStatus {
  agent_id: string
  adapter_type: string
  ready: boolean
  checked_at: string
  checks: AuditPreflightCheck[]
}

export interface Stage {
  event_id: string
  state: AuditState
  status: 'running' | 'completed' | 'failed' | 'skipped'
  attempt: number
  started_at: string
  completed_at?: string | null
  duration_ms?: number | null
  message?: string | null
}

export interface AuditStatus {
  audit_id: string
  state: AuditState
  progress_percent: number
  total_duration_ms: number
  stages: Stage[]
}

export interface Report {
  overall_score: number
  risk_level: string
  attack_success_rate: number
  false_positive_rate: number
  scenario_results: ScenarioResult[]
  deterministic_metrics?: {
    asr: number
    dsr: number
    fpr: number
  } | null
}

export interface ScenarioResult {
  scenario_id: string
  category: string
  target_node?: string | null
  severity: 'low' | 'medium' | 'high' | 'critical'
  expected_decision: 'allow' | 'block'
  actual_decision: 'allow' | 'block'
  clean_decision: 'allow' | 'block'
  passed: boolean
  business_impact: string
  trajectory_ref: string
  blocked_node?: string | null
  bypassed_nodes: string[]
  node_status: Record<string, unknown>
}

export interface Comparison {
  before_score: number
  after_score: number
  score_delta: number
  risk_level_change: string
  resolved_findings: Array<{ title: string; recommendation: string }>
  persisted_findings: Array<{ title: string; recommendation: string }>
  scenario_deltas: Array<{
    scenario_id: string
    before_passed?: boolean | null
    after_passed?: boolean | null
    before_decision?: string | null
    after_decision?: string | null
    status: 'improved' | 'regressed' | 'unchanged_pass' | 'unchanged_fail'
  }>
}

export interface EvaluationVerdict {
  audit_id: string
  agent_id: string
  baseline_asr: number
  guarded_asr: number
  business_utility: number
  repaired_scenario_count: number
  conclusion: 'effective' | 'partially_effective' | 'ineffective' | 'inconclusive'
  evidence_status: 'complete' | 'incomplete'
}

export interface ReleaseDecision {
  decision_id: string
  audit_id: string
  decision: 'allow_release' | 'retest_after_fix' | 'block_release' | 'manual_review'
  reasons: string[]
  unresolved_risks: string[]
  limitations: string[]
  evidence_complete: boolean
}

export interface Evidence {
  artifacts: Array<{
    artifact_id: string
    stage: string
    kind: string
    ref: string
    available: boolean
    sha256?: string | null
  }>
  incomplete_refs: string[]
}

export interface BusinessReport {
  phase: 'baseline' | 'guarded' | 'final'
  task_count: number
  passed_task_count: number
  clean_utility: number
  valid_completion_rate: number
  all_tasks_passed: boolean
  results: Array<{
    task_id: string
    execution_status: string
    oracle_status: string
    passed: boolean
    error?: string | null
  }>
}

export interface RemediationBundle {
  bundle_id: string
  deployment_type: 'sandbox_policy'
  policies: Array<{
    action_id: string
    target_node: string
    guard: string
    parameters: Record<string, unknown>
  }>
}

export interface RemediationInstallation {
  installation_id: string
  audit_id: string
  bundle_id: string
  bundle_sha256: string
  target_environment: 'audit_sandbox'
  status: 'installed'
  policy_ref: string
  policy_sha256: string
  active_guards: string[]
  installed_action_ids: string[]
  installed_at: string
}

export interface AuditTraceEvent {
  event_id: string
  phase: 'baseline' | 'guarded'
  scenario_id: string
  stream: string
  sequence: number
  event_type: string
  timestamp?: string | null
  title: string
  summary?: string | null
  metadata: Record<string, string>
}

export interface AuditScenarioTrace {
  trace_id: string
  phase: 'baseline' | 'guarded'
  scenario_id: string
  trajectory_ref: string
  available: boolean
  event_count: number
  truncated: boolean
  events: AuditTraceEvent[]
}

export interface AuditWorkspace {
  audit_id: string
  state: AuditState
  run: AuditRun
  status: AuditStatus
  plan?: AuditPlan | null
  baseline_report?: Report | null
  guarded_report?: Report | null
  comparison?: Comparison | null
  decision?: ReleaseDecision | null
  remediation_bundle?: RemediationBundle | null
  remediation_installation?: RemediationInstallation | null
  traces: AuditScenarioTrace[]
  round?: AuditRound | null
}

export interface AuditPlanItem {
  scenario_id: string
  risk_surface: string
  target_node: string
  rationale: string
  priority: number
  expected_evidence: string[]
  metadata: Record<string, unknown>
}

export interface AuditPlan {
  plan_id: string
  audit_id: string
  profile_id: string
  source: 'llm' | 'rule_fallback'
  planner_model?: string | null
  items: AuditPlanItem[]
  normal_task_ids: string[]
  stop_conditions: string[]
  warnings: string[]
  generated_at: string
}

export interface AuditAttackOutcome {
  scenario_id: string
  attack_spec_id: string
  risk_surface: string
  predicted_node_id: string
  predicted_path_id?: string | null
  baseline_attack_succeeded?: boolean | null
  baseline_failed_node_id?: string | null
  guarded_attack_succeeded?: boolean | null
  guarded_failed_node_id?: string | null
  defense_guards: string[]
  baseline_trajectory_ref?: string | null
  guarded_trajectory_ref?: string | null
}

export interface AuditRound {
  round_index: number
  parent_audit_id?: string | null
  attack_set_source: 'static_profile' | 'prior_round_feedback'
  benchmark_id: string
  benchmark_version: string
  attack_count: number
  baseline_success_count: number
  guarded_success_count: number
  outcomes: AuditAttackOutcome[]
}

export interface AuditDetail {
  run: AuditRun
  status: AuditStatus
  plan: Record<string, unknown>
  verdict: EvaluationVerdict
  decision: ReleaseDecision
  evidence: Evidence
  baseline: Report
  guarded: Report
  comparison?: Comparison | null
  business: BusinessReport[]
  remediation_bundle?: RemediationBundle | null
  remediation_installation?: RemediationInstallation | null
  traces: AuditScenarioTrace[]
  round?: AuditRound | null
}
