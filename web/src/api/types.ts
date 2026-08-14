// 与后端 JSON Schema 对齐的类型定义（ARCHITECTURE §3.3/3.4）

export interface User {
  id: number
  email: string
  role: string
  quota_audits: number
  created_at: string
}

export interface APIKey {
  id: number
  user_id: number
  key_prefix: string
  name: string
  revoked: boolean
  created_at: string
}

export interface CreateKeyResp {
  key: string
  key_prefix: string
  name: string
  id: number
  created_at: string
}

export interface AuthResp {
  token: string
  user: User
}

export interface Breakdown {
  dimension: string
  weight: number
  group_max_weight: number
  contrib: number
}

export interface ScoreResult {
  score: number
  level: string
  level_key: string
  icon: string
  breakdown: Breakdown[]
  bonus: number
  notes: string[]
  hit_categories: string[]
}

export interface Finding {
  rule_id: string
  rule_name: string
  category: string
  severity: string
  weight: number
  detection: string
  file: string
  line: number
  snippet: string
}

export interface LLMRule {
  id: string
  name: string
  category: string
  severity: string
  weight: number
  detection: string
  patterns: string[]
  rationale: string
  false_positive_note: string
}

export interface Report {
  tool: string
  version: string
  rules_version: string
  target: string
  scanned_files: number
  skipped_files: number
  skill_md: {
    file: string
    frontmatter: { name: string; description: string; 'allowed-tools'?: string[] }
    body_preview: string
  } | null
  score: ScoreResult
  findings: Finding[]
  llm_review_rules: LLMRule[]
}

export interface AuditResp {
  cached: boolean
  report: Report
  llm_results?: LLMResult[]
}

// LLM 语义分析判定结果（RS-018/RS-019）
export interface LLMResult {
  rule_id: string
  verdict: 'suspicious' | 'clean' | 'unknown'
  confidence: string
  reason: string
}

export interface AuditBrief {
  id: number
  skill_hash: string
  score?: number
  level_key: string
  created_at: string
}

export interface AuditListResp {
  audits: AuditBrief[]
}

export interface UsageItem {
  used: number
  quota: number
}

export interface UsageResp {
  static_audit: UsageItem
  llm_review: UsageItem
}

export interface KeyListResp {
  keys: APIKey[]
}
