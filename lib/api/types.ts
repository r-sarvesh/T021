/**
 * Domain models for the Cyber Health Assess platform.
 *
 * These interfaces mirror the shape of the EXISTING backend responses.
 * The UI is written exclusively against these types so that the API
 * adapter (see `client.ts`) can be swapped from the placeholder data
 * source to real HTTP endpoints without touching component code.
 */

export type Role = 'admin' | 'analyst'

export interface User {
  id: string
  username: string
  name: string
  email: string
  role: Role
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unscored'

/** Whether a finding was successfully matched to supporting evidence. */
export type EvidenceStatus = 'backed' | 'none'

export type ScanStatus = 'queued' | 'processing' | 'completed' | 'failed'

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface Scan {
  id: string
  name: string
  filename: string
  importedBy: string
  importedAt: string
  status: ScanStatus
  hostCount: number
  findingCount: number
  highestSeverity: Severity | null
  severityCounts: SeverityCounts
  /** Number of findings matched to CVE/CIS evidence. */
  evidenceBacked: number
  /** Number of findings with no matched evidence. */
  evidenceMissing: number
}

export interface Host {
  id: string
  scanId: string
  ip: string
  hostname: string | null
  openPorts: number
  findingCount: number
  highestSeverity: Severity | null
  /** Backend-provided host risk score (0-100), or null if not provided. */
  riskScore: number | null
  severityCounts: SeverityCounts
  evidenceBacked: number
  evidenceMissing: number
}

export interface CveEvidence {
  id: string
  cvss: number
  cvssSeverity: Severity
  description: string
  affectedProduct: string | null
  knownExploited: boolean
  source: string
}

export interface CisEvidence {
  control: string
  title: string
  recommendation: string
  reasoning: string
}

export interface Finding {
  id: string
  scanId: string
  hostId: string
  host: string
  hostname: string | null
  port: number
  protocol: string
  service: string
  title: string
  description: string
  severity: Severity
  severityReasoning: string
  cvss: number | null
  cve: CveEvidence | null
  cis: CisEvidence | null
  evidenceStatus: EvidenceStatus
  remediation: string | null
}

export type AuditResult = 'success' | 'failure'

export type AuditAction =
  | 'login'
  | 'login_failed'
  | 'logout'
  | 'scan_import'
  | 'report_export'
  | 'scan_access'

export interface AuditEvent {
  id: string
  timestamp: string
  user: string
  role: Role
  action: AuditAction
  target: string
  result: AuditResult
  ip: string | null
}

export type ReportStatus = 'ready' | 'generating' | 'failed'

export interface Report {
  id: string
  scanId: string
  scanName: string
  generatedBy: string
  generatedAt: string
  status: ReportStatus
  sizeKb: number | null
}

export interface DashboardSummary {
  totalScans: number
  totalFindings: number
  severityCounts: SeverityCounts
  evidenceBacked: number
  evidenceMissing: number
  hostsAssessed: number
  /** Backend-provided overall risk band, or null if not provided. */
  overallRisk: { label: string; level: Severity } | null
}

/** Thrown by the adapter to give the UI structured, analyst-friendly errors. */
export interface ApiError {
  code:
    | 'invalid_credentials'
    | 'account_locked'
    | 'unauthorized'
    | 'invalid_scan'
    | 'service_unavailable'
    | 'report_failed'
    | 'not_found'
  message: string
}

export function isApiError(err: unknown): err is ApiError {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    'message' in err
  )
}
