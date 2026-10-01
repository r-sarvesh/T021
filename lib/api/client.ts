/**
 * ---------------------------------------------------------------------------
 * API ADAPTER
 * ---------------------------------------------------------------------------
 *
 * Single, isolated boundary between the UI and the backend. Every screen calls
 * these functions and nothing else — no component imports fixtures or fetches
 * directly. Today each function resolves from the placeholder dataset
 * (`fixtures.ts`) with simulated latency; to go live, replace each body with a
 * `fetch()` to the corresponding existing endpoint (noted per function) and
 * keep the same return types.
 *
 * The backend remains the source of truth for authentication, authorization,
 * scan processing, scoring, and evidence grounding. This layer never invents
 * findings, CVEs, scores, or evidence.
 */
import {
  auditEvents as auditFixture,
  demoAccounts,
  findings as findingsFixture,
  hosts as hostsFixture,
  reports as reportsFixture,
  scans as scansFixture,
} from './fixtures'
import type {
  AuditEvent,
  DashboardSummary,
  Finding,
  Host,
  Report,
  Scan,
  Severity,
  User,
} from './types'
import type { ApiError } from './types'

const LATENCY = 550

function delay<T>(value: T, ms = LATENCY): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms))
}

function fail(error: ApiError, ms = LATENCY): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(error), ms))
}

const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unscored: 0,
}

// ---------------------------------------------------------------------------
// Auth  →  POST /api/auth/login, POST /api/auth/logout, GET /api/auth/session
// ---------------------------------------------------------------------------

const failedAttempts = new Map<string, number>()
const LOCK_THRESHOLD = 3

export interface Session {
  user: User
  token: string
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://127.0.0.1:5000'

function authHeader(): Record<string, string> {
  if (typeof window === 'undefined') return {}
  const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function login(username: string, password: string): Promise<Session> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: body.error || 'invalid_credentials', message: body.message || 'Login failed' } as ApiError
  }
  const data = await res.json()
  const { user, token } = data as Session
  if (typeof window !== 'undefined' && token) {
    localStorage.setItem('auth_token', token)
    sessionStorage.setItem('auth_token', token)
  }
  // Clear any prior lock state
  failedAttempts.delete(username.trim().toLowerCase())
  return { user, token }
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: 'POST',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      credentials: 'include',
    })
  } catch {}
  if (typeof window !== 'undefined') {
    localStorage.removeItem('auth_token')
    sessionStorage.removeItem('auth_token')
  }
  return
}

export async function getSession(): Promise<Session | null> {
  const res = await fetch(`${API_BASE}/api/auth/session`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) return null
  return res.json()
}

// ---------------------------------------------------------------------------
// Dashboard  →  GET /api/dashboard/summary
// ---------------------------------------------------------------------------

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const res = await fetch(`${API_BASE}/api/dashboard/summary`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load dashboard' } as ApiError
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Scans  →  GET /api/scans, GET /api/scans/:id
// ---------------------------------------------------------------------------

export interface ScanFilters {
  search?: string
  status?: Scan['status'] | 'all'
  severity?: Severity | 'all'
  evidence?: 'all' | 'complete' | 'partial'
  sort?: 'recent' | 'severity' | 'findings'
}

export async function listScans(filters: ScanFilters = {}): Promise<Scan[]> {
  const params = new URLSearchParams()
  if (filters.search) params.set('search', filters.search)
  if (filters.status && filters.status !== 'all') params.set('status', filters.status)
  if (filters.severity && filters.severity !== 'all') params.set('severity', filters.severity)
  if (filters.evidence && filters.evidence !== 'all') params.set('evidence', filters.evidence)
  if (filters.sort) params.set('sort', filters.sort)
  const res = await fetch(`${API_BASE}/api/scans?${params.toString()}`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load scans' } as ApiError
  }
  return res.json()
}

export async function getScan(id: string): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(id)}`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'not_found', message: (body as any).message || 'Scan not found' } as ApiError
  }
  return res.json()
}

export async function getScanHosts(scanId: string): Promise<Host[]> {
  const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/hosts`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load hosts' } as ApiError
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Findings  →  GET /api/scans/:id/findings, GET /api/findings/:id
// ---------------------------------------------------------------------------

export interface FindingFilters {
  search?: string
  severity?: Severity | 'all'
  hostId?: string | 'all'
  evidence?: 'all' | 'backed' | 'none'
}

export async function listFindings(
  scanId: string,
  filters: FindingFilters = {},
): Promise<Finding[]> {
  const params = new URLSearchParams()
  if (filters.search) params.set('search', filters.search)
  if (filters.severity && filters.severity !== 'all') params.set('severity', filters.severity)
  if (filters.hostId && filters.hostId !== 'all') params.set('hostId', filters.hostId)
  if (filters.evidence && filters.evidence !== 'all') params.set('evidence', filters.evidence)
  const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/findings?${params.toString()}`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load findings' } as ApiError
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Import  →  POST /api/scans/import (multipart) + processing status stream
// ---------------------------------------------------------------------------

export interface ImportProgress {
  step: string
  percent: number
}

const IMPORT_STEPS = [
  'Uploading scan',
  'Processing hosts',
  'Analyzing findings',
  'Matching vulnerability evidence',
  'Preparing assessment',
]

function getAuthHeader(): Record<string, string> {
  if (typeof window === 'undefined') return {}
  // Primary: cha.session as stored by auth-provider.tsx
  try {
    const raw = localStorage.getItem('cha.session')
    if (raw) {
      const parsed = JSON.parse(raw) as { token?: string }
      if (parsed?.token) return { Authorization: `Bearer ${parsed.token}` }
    }
  } catch {}
  // Fallback: legacy auth_token keys (for direct API tests)
  const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/**
 * Kicks off backend processing for an uploaded Nmap XML file. The frontend
 * only relays progress reported by the backend pipeline — it does not parse
 * scans, assess severity, or ground evidence itself.
 */
export async function importScan(
  file: File,
  onProgress: (progress: ImportProgress) => void,
): Promise<{ scanId: string; reportId: string; report?: any }> {
  if (!file.name.toLowerCase().endsWith('.xml')) {
    return fail(
      {
        code: 'invalid_scan',
        message: 'The uploaded file could not be processed as a valid Nmap XML report.',
      },
      400,
    )
  }

  // Report progress while backend processes (backend is synchronous, so we simulate steps)
  let progressIdx = 0
  const progressInterval = setInterval(() => {
    if (progressIdx < IMPORT_STEPS.length) {
      onProgress({
        step: IMPORT_STEPS[progressIdx],
        percent: Math.round(((progressIdx + 1) / IMPORT_STEPS.length) * 100),
      })
      progressIdx++
    }
  }, 400)

  try {
    const form = new FormData()
    form.append('scan_file', file, file.name)
    // Also append as 'file' for compatibility with /api/scans/import
    form.append('file', file, file.name)

    const headers: Record<string, string> = { ...getAuthHeader() }

    const res = await fetch(`${API_BASE}/api/scans/import`, {
      method: 'POST',
      headers,
      body: form,
      credentials: 'include',
    })

    clearInterval(progressInterval)

    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      const msg = (body as any).message || (body as any).error || `Upload failed (${res.status})`
      // Map backend errors to ApiError codes
      const code = res.status === 413 ? 'invalid_scan' : res.status === 400 ? 'invalid_scan' : 'service_unavailable'
      return fail({ code, message: msg }, 0)
    }

    const data = await res.json()
    const reportId = (data as any).reportId || (data as any).report_id || (data as any).scanId as string
    if (!reportId) {
      return fail({ code: 'service_unavailable', message: 'No report ID returned' }, 0)
    }

    // Ensure we show 100% before fetching report
    onProgress({ step: IMPORT_STEPS[IMPORT_STEPS.length - 1], percent: 100 })

    // Fetch full report for inline view (instead of navigating) — use the live report export which has grounded+synthesized+quota+validation
    const reportRes = await fetch(`${API_BASE}/report/${reportId}/export`, {
      headers: getAuthHeader(),
      credentials: 'include',
    })
    if (reportRes.ok) {
      const report = await reportRes.json()
      return { scanId: reportId, reportId, report }
    }
    return { scanId: reportId, reportId }
  } catch (e: any) {
    clearInterval(progressInterval)
    return fail(
      { code: 'service_unavailable', message: e?.message || 'Upload failed' },
      0,
    )
  }
}

export async function getReport(reportId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/report/${reportId}/export`, {
    headers: getAuthHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    throw { code: 'not_found', message: 'Report not found' }
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Reports  →  GET /api/reports, POST /api/scans/:id/report (PDF generation)
// ---------------------------------------------------------------------------

export async function listReports(): Promise<Report[]> {
  const res = await fetch(`${API_BASE}/api/reports`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load reports' } as ApiError
  }
  return res.json()
}

export async function exportReport(scanId: string): Promise<{ reportId: string }> {
  const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/report`, {
    method: 'POST',
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'report_failed', message: (body as any).message || 'Report failed' } as ApiError
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Audit log  →  GET /api/audit (admin only, enforced by backend)
// ---------------------------------------------------------------------------

export interface AuditFilters {
  search?: string
  action?: AuditEvent['action'] | 'all'
  user?: string | 'all'
  result?: AuditEvent['result'] | 'all'
}

export async function listAuditEvents(
  role: User['role'],
  filters: AuditFilters = {},
): Promise<AuditEvent[]> {
  // Authorization is enforced server-side; the UI mirrors it defensively.
  if (role !== 'admin') {
    return fail({
      code: 'unauthorized',
      message: 'You do not have permission to access the audit log.',
    })
  }

  const headers: Record<string, string> = { ...authHeader(), ...getAuthHeader() }
  const res = await fetch(`${API_BASE}/api/audit`, {
    headers,
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const code = (body as any).error === 'unauthorized' ? 'unauthorized' : 'service_unavailable'
    const message = (body as any).message || (res.status === 403 ? 'You do not have permission to access the audit log.' : `Failed to load audit log (${res.status})`)
    throw { code, message } as ApiError
  }
  let result = (await res.json()) as AuditEvent[]
  const { search, action, user, result: resFilter } = filters

  if (search) {
    const q = search.toLowerCase()
    result = result.filter(
      (e) =>
        e.user.toLowerCase().includes(q) ||
        e.target.toLowerCase().includes(q) ||
        e.action.toLowerCase().includes(q),
    )
  }
  if (action && action !== 'all') result = result.filter((e) => e.action === action)
  if (user && user !== 'all') result = result.filter((e) => e.user === user)
  if (resFilter && resFilter !== 'all') result = result.filter((e) => e.result === resFilter)

  result.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  return result
}

export async function listAuditUsers(): Promise<string[]> {
  // Try live audit log first, fall back to fixtures for offline/demo
  try {
    const headers: Record<string, string> = { ...authHeader(), ...getAuthHeader() }
    const res = await fetch(`${API_BASE}/api/audit`, { headers, credentials: 'include' })
    if (res.ok) {
      const data = (await res.json()) as AuditEvent[]
      if (Array.isArray(data) && data.length > 0) {
        return Array.from(new Set(data.map((e) => e.user)))
      }
    }
  } catch {}
  return delay(Array.from(new Set(auditFixture.map((e) => e.user))))
}

// ---------------------------------------------------------------------------
// Demo / Benchmark  →  GET /demo/data, GET /benchmark/data (Flask JSON)
// ---------------------------------------------------------------------------

export async function getDemoFindings(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/demo/data`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load demo findings' } as ApiError
  }
  const data = await res.json()
  if (Array.isArray(data)) return data
  if (data && Array.isArray((data as any).all_scored_findings)) return (data as any).all_scored_findings
  if (data && Array.isArray((data as any).findings)) return (data as any).findings
  return data as any[]
}

export async function getBenchmarkData(): Promise<any> {
  const res = await fetch(`${API_BASE}/benchmark/data`, {
    headers: authHeader(),
    credentials: 'include',
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw { code: (body as any).error || 'service_unavailable', message: (body as any).message || 'Failed to load benchmark data' } as ApiError
  }
  return res.json()
}
