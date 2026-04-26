// TypeScript type definitions for the audit report data
// These types mirror what the backend returns from POST /api/v1/audit.
// Defining them here means TypeScript will warn us if we try to access a field
// that doesn't exist, or if the backend changes its response shape.

export type Severity   = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type Source     = 'LLM' | 'SLITHER' | 'BOTH'
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

export interface Vulnerability {
  id: string
  title: string
  severity: Severity
  category: string
  swc_id: string | null
  affected_function: string
  affected_code_snippet: string
  line_numbers: number[]
  description: string
  exploitation_scenario: string | null
  recommendation: string | null
  confidence: Confidence
  source: Source
  slither_check?: string | null
}

export interface ContractInfo {
  solidity_version: string
  contract_names: string[]
  total_lines: number
  uses_inheritance: boolean
  uses_external_calls: boolean
  uses_assembly: boolean
}

export interface Statistics {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface ReportMeta {
  contract_name: string
  audit_timestamp: string
  started_at: string
  llm_model: string
  slither_available: boolean
  pipeline_errors: string[]
}

export interface AuditReport {
  meta: ReportMeta
  overall_risk: Severity
  summary: string
  contract_info: ContractInfo
  statistics: Statistics
  vulnerabilities: Vulnerability[]
  raw?: { //raw output used for debugging
    llm?: Record<string, unknown> | null
    slither?: Record<string, unknown> | null
  }
}