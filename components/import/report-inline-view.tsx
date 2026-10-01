'use client'

import { AlertTriangle, ShieldCheck, ShieldX, FileSearch, Download } from 'lucide-react'
import { SeverityBadge } from '@/components/severity-badge'
import { EvidenceBadge } from '@/components/evidence-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { formatDateTime } from '@/lib/format'
import type { Severity } from '@/lib/api/types'

interface ReportInlineViewProps {
  report: any // Detailed report JSON from GET /report/<id> or /report/<id>/export
}

function sevToLower(s: string): Severity {
  const m: Record<string, Severity> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'low',
    UNSCORED: 'unscored',
  }
  return m[s] || 'unscored'
}

export function ReportInlineView({ report }: ReportInlineViewProps) {
  const grounded: any[] = report.grounded || []
  const synthesized: any[] = report.synthesized || []
  const quota = report.quota_info || {}
  const flags: any[] = report.validation_flags || []
  const hostSummary: any[] = report.host_summary || report.scored?.host_risk_summary || []
  const isEmpty = report.is_empty_scan
  const isNoFindings = report.is_no_findings

  // Map synthesized by finding_ref for quick lookup
  const synByRef = new Map<string, any>()
  for (const s of synthesized) {
    if (s.finding_ref) synByRef.set(s.finding_ref, s)
  }

  const getFindingRef = (f: any) => `${f.host}:${f.port}/${f.protocol}/${f.service}/${f.nse_script || 'asset'}`

  return (
    <div className="flex flex-col gap-4">
      {/* Live marker — distinct from /demo */}
      <div className="rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 flex items-center gap-3">
        <div className="flex size-8 items-center justify-center rounded-full bg-primary/15 text-primary">
          <FileSearch className="size-4" />
        </div>
        <div>
          <p className="text-sm font-medium">Live scan — uploaded {report.filename} at {report.uploaded_at ? formatDateTime(report.uploaded_at) : ''}</p>
          <p className="text-xs text-muted-foreground font-mono">report_id {report.report_id} · {grounded.length} findings · {report.cve_records_total} CVE · {report.cis_matches_total} CIS</p>
        </div>
        <div className="ml-auto flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={async () => {
              const API = process.env.NEXT_PUBLIC_API_BASE || 'http://127.0.0.1:5000'
              const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token') : null
              const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
              try {
                const res = await fetch(`${API}/report/${report.report_id}/export`, { headers, credentials: 'include' })
                if (!res.ok) throw new Error(`Export failed ${res.status}`)
                const blob = await res.blob()
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `${report.report_id}_report.json`
                a.click()
                URL.revokeObjectURL(url)
              } catch {
                window.open(`${API}/report/${report.report_id}/export`, '_blank')
              }
            }}
          >
            <Download className="size-3.5" /> JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={async () => {
              const API = process.env.NEXT_PUBLIC_API_BASE || 'http://127.0.0.1:5000'
              const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token') : null
              const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
              try {
                const res = await fetch(`${API}/report/${report.report_id}/pdf`, { headers, credentials: 'include' })
                if (!res.ok) throw new Error(`PDF failed ${res.status}`)
                const ct = res.headers.get('Content-Type') || ''
                const blob = await res.blob()
                if (ct.includes('text/html')) {
                  const url = URL.createObjectURL(blob)
                  window.open(url, '_blank')
                  setTimeout(() => URL.revokeObjectURL(url), 60000)
                  return
                }
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `${report.report_id}_report.pdf`
                a.click()
                URL.revokeObjectURL(url)
              } catch {
                window.open(`${API}/report/${report.report_id}/pdf`, '_blank')
              }
            }}
          >
            <Download className="size-3.5" /> PDF
          </Button>
        </div>
      </div>

      {/* Quota banner */}
      {quota.quota_exceeded && (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertTitle>Gemini quota exceeded</AlertTitle>
          <AlertDescription>
            {quota.message} — top {quota.synthesized} highest-severity findings synthesized, {quota.skipped} labeled <code className="font-mono text-xs">not synthesized — daily quota reached</code>.
          </AlertDescription>
        </Alert>
      )}

      {/* Hallucination flags */}
      {flags.length > 0 && (
        <Alert variant="destructive">
          <ShieldX />
          <AlertTitle>Hallucination check flagged {flags.length} finding(s)</AlertTitle>
          <AlertDescription>
            Fabricated/unsupported CVE citations detected — see flagged rows below. Validated with same logic as benchmark exhibit.
          </AlertDescription>
        </Alert>
      )}
      {flags.map((flag: any) => (
        <Card key={flag.finding_ref} className="border-critical/30 bg-critical/5">
          <CardContent className="p-3">
            <div className="flex items-center gap-2 text-sm font-mono">
              <span className="font-medium">{flag.finding_ref}</span>
              <Badge variant="destructive">HALLUCINATED</Badge>
              <span className="text-muted-foreground text-xs">cited {flag.cited?.join(', ')} not in allowed {flag.allowed?.join(', ') || '(none)'}</span>
            </div>
            {flag.fabricated?.length > 0 && <p className="text-xs mt-1">Fabricated (invented, not in NVD/KB): <span className="font-mono">{flag.fabricated.join(', ')}</span></p>}
            {flag.unsupported?.length > 0 && <p className="text-xs mt-1">Unsupported (real CVE but not in retrieved context): <span className="font-mono">{flag.unsupported.join(', ')}</span></p>}
          </CardContent>
        </Card>
      ))}

      {/* Empty states */}
      {isEmpty && (
        <Card>
          <CardContent className="py-12 text-center">
            <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground mb-3">
              <ShieldX className="size-6" />
            </div>
            <p className="font-medium">No hosts found in this scan</p>
            <p className="text-sm text-muted-foreground mt-1">The uploaded Nmap file contained 0 hosts. Check that the scan actually discovered hosts (nmap -oX with correct targets) and re-upload.</p>
          </CardContent>
        </Card>
      )}
      {isNoFindings && !isEmpty && (
        <Card>
          <CardContent className="py-12 text-center">
            <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-verified/15 text-verified mb-3">
              <ShieldCheck className="size-6" />
            </div>
            <p className="font-medium">Scan completed, no notable findings</p>
            <p className="text-sm text-muted-foreground mt-1">No open ports or vulnerability findings after grounding. Hosts were found but nothing met the scoring threshold.</p>
          </CardContent>
        </Card>
      )}

      {!isEmpty && !isNoFindings && (
        <>
          {/* Host risk */}
          {hostSummary.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Host risk</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {hostSummary.map((h: any) => (
                  <div key={h.host} className="rounded-lg border border-border p-3 flex flex-col gap-2">
                    <div className="font-mono text-sm font-medium">{h.hostname || h.host}</div>
                    <div className="text-xs text-muted-foreground font-mono">{h.host} · {h.os_guess || 'OS unknown'} · {h.open_service_count} open</div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-lg font-semibold tabular-nums">{h.adjusted_risk_score}</span>
                      <SeverityBadge severity={sevToLower(h.risk_band)} />
                    </div>
                    <p className="text-xs text-muted-foreground">{h.criticality_reason}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Findings ledger with synthesis */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Findings — {grounded.length} (every claim either cited or explicitly ungrounded)</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[900px] text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs text-muted-foreground">
                      <th className="px-3 py-2 font-medium">Severity</th>
                      <th className="px-3 py-2 font-medium">Host</th>
                      <th className="px-3 py-2 font-medium">Service</th>
                      <th className="px-3 py-2 font-medium">Port</th>
                      <th className="px-3 py-2 font-medium">CVE refs</th>
                      <th className="px-3 py-2 font-medium">Grounding</th>
                      <th className="px-3 py-2 font-medium">Evidence / Synthesis</th>
                    </tr>
                  </thead>
                  <tbody>
                    {grounded
                      .slice()
                      .sort((a: any, b: any) => {
                        const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNSCORED: -1 }
                        return (rank[b.severity_band] ?? -1) - (rank[a.severity_band] ?? -1)
                      })
                      .map((f: any) => {
                        const ref = getFindingRef(f)
                        const syn = synByRef.get(ref)
                        const isFlagged = flags.some((fl: any) => fl.finding_ref === ref)
                        const cves = f.grounding_context?.cve_records || []
                        const ciss = f.grounding_context?.cis_matches || []
                        const hasEvidence = cves.length > 0 || ciss.length > 0
                        return (
                          <tr key={ref} className={isFlagged ? 'bg-critical/5' : 'border-b border-border/60 last:border-0 hover:bg-muted/20'}>
                            <td className="px-3 py-2 align-top">
                              <SeverityBadge severity={sevToLower(f.severity_band)} />
                              <div className="text-xs text-muted-foreground font-mono mt-1">{f.severity_score ?? '—'}</div>
                              {isFlagged && <Badge variant="destructive" className="mt-1 text-[10px]">HALLUCINATED</Badge>}
                            </td>
                            <td className="px-3 py-2 align-top">
                              <div className="font-mono text-xs">{f.host}</div>
                              <div className="text-xs text-muted-foreground">{f.hostname}</div>
                            </td>
                            <td className="px-3 py-2 align-top">
                              <div>{f.service || '—'}</div>
                              <div className="text-xs text-muted-foreground">{f.version || f.product || ''}</div>
                            </td>
                            <td className="px-3 py-2 align-top font-mono text-xs">{f.port}/{f.protocol}</td>
                            <td className="px-3 py-2 align-top">
                              {f.cve_refs?.length ? f.cve_refs.map((c: string) => <Badge key={c} variant="outline" className="mr-1 border-verified/30 bg-verified/10 text-verified">{c}</Badge>) : <span className="text-xs text-muted-foreground">— no CVE ref</span>}
                            </td>
                            <td className="px-3 py-2 align-top">
                              {hasEvidence ? (
                                <>
                                  <EvidenceBadge status="backed" />
                                  {cves.length > 0 && <span className="ml-1 text-xs">{cves.length} CVE</span>}
                                  {ciss.length > 0 && <span className="ml-1 text-xs">{ciss.length} CIS</span>}
                                </>
                              ) : (
                                <EvidenceBadge status="none" />
                              )}
                            </td>
                            <td className="px-3 py-2 align-top max-w-[320px]">
                              {f.nse_script && <div className="font-mono text-xs mb-1">{f.nse_script}</div>}
                              {/* Synthesis per finding */}
                              {syn ? (
                                syn.not_synthesized ? (
                                  <div className="rounded border border-border bg-muted/20 p-2 mt-1">
                                    <p className="text-xs font-medium">Not synthesized</p>
                                    <p className="text-xs text-muted-foreground">Daily quota reached — ranked outside top {synthesized.filter((s:any)=>!s.not_synthesized).length} by severity.</p>
                                  </div>
                                ) : syn.ok ? (
                                  <div className={`rounded border p-2 mt-1 ${isFlagged ? 'border-critical/30 bg-critical/5' : 'border-verified/30 bg-verified/5'}`}>
                                    <div className="flex items-center gap-2 mb-1">
                                      <Badge variant={isFlagged ? 'destructive' : 'outline'} className={isFlagged ? '' : 'border-verified/30 bg-verified/10 text-verified'}>{isFlagged ? 'FLAGGED' : 'GROUNDED'}</Badge>
                                      <span className="text-xs text-muted-foreground">Gemini synthesis</span>
                                    </div>
                                    <p className="text-xs leading-relaxed">{syn.parsed?.plain_language_explanation || syn.raw_output?.slice(0, 200)}</p>
                                    {syn.parsed?.cve_ids_mentioned?.length > 0 && <p className="text-xs mt-1">Cited: {syn.parsed.cve_ids_mentioned.join(', ')}</p>}
                                    {syn.parsed?.remediation_steps && <ul className="text-xs mt-1 list-disc pl-4">{syn.parsed.remediation_steps.map((s: string, i: number) => <li key={i}>{s}</li>)}</ul>}
                                  </div>
                                ) : (
                                  <div className="rounded border border-border bg-muted/20 p-2 mt-1">
                                    <p className="text-xs">Synthesis failed: {syn.error}</p>
                                  </div>
                                )
                              ) : null}
                              <details className="mt-1">
                                <summary className="text-xs text-muted-foreground cursor-pointer">Evidence</summary>
                                <div className="mt-1 text-xs space-y-1">
                                  {f.scoring_rationale && <p className="text-muted-foreground">Scoring: {f.scoring_rationale}</p>}
                                  {cves.map((rec: any) => (
                                    <div key={rec.id} className="border border-border rounded p-1.5 bg-card">
                                      <div className="font-mono font-medium">{rec.id} {rec.not_found ? '(NOT IN KB)' : `CVSS ${rec.cvss_v3_score} ${rec.cvss_severity}`}{rec.kev_listed ? ' KEV' : ''}</div>
                                      {!rec.not_found && <p className="text-muted-foreground">{rec.text?.slice(0, 120)}…</p>}
                                    </div>
                                  ))}
                                  {ciss.map((c: any) => (
                                    <div key={c.id} className="border border-border rounded p-1.5 bg-card">
                                      <div className="font-mono text-xs">{c.id} — {c.control_title}</div>
                                      <div className="text-muted-foreground">sim {c.similarity_score?.toFixed(3)}</div>
                                    </div>
                                  ))}
                                </div>
                              </details>
                            </td>
                          </tr>
                        )
                      })}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
