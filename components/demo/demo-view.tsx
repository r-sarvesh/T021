'use client'

import { getDemoFindings } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { SeverityBadge } from '@/components/severity-badge'
import { EvidenceBadge } from '@/components/evidence-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ErrorState, TableSkeleton } from '@/components/data-states'

function severityToLower(s: string): any {
  const m: Record<string, string> = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'low', UNSCORED: 'unscored' }
  return m[s] || 'unscored'
}

export function DemoView() {
  const demo = useAsync(() => getDemoFindings(), [])

  if (demo.loading) return <TableSkeleton rows={8} />
  if (demo.error) return <ErrorState message={demo.error.message} onRetry={demo.reload} />

  const findings: any[] = demo.data || []
  const total = findings.length
  // CVE matched records (non-not_found) and unique
  const cveRecords = findings.reduce((n: number, f: any) => {
    const recs = (f.grounding_context?.cve_records || []) as any[]
    return n + recs.filter((r) => !r.not_found && r.status !== 'not_found' && r.id).length
  }, 0)
  const cveUnique = new Set<string>()
  findings.forEach((f: any) => {
    const recs = (f.grounding_context?.cve_records || []) as any[]
    recs.forEach((r: any) => { if (!r.not_found && r.status !== 'not_found' && r.id) cveUnique.add(r.id) })
  })
  const cisGrounded = findings.filter((f: any) => (f.grounding_context?.cis_matches || []).length > 0).length
  const pipelineErrors = findings.filter(
    (f: any) => f.severity_band === 'UNSCORED' || ((f.grounding_context?.cve_records || []) as any[]).some((r: any) => r.not_found),
  ).length

  // host groups
  const hostsMap = new Map<string, any[]>()
  for (const f of findings) {
    const k = f.host || 'unknown'
    if (!hostsMap.has(k)) hostsMap.set(k, [])
    hostsMap.get(k)!.push(f)
  }
  const sortedHosts = [...hostsMap.entries()].sort((a, b) => {
    const order: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNSCORED: -1 }
    const worst = (list: any[]) => {
      let best = 'INFO', bestScore = -2
      for (const f of list) { const band = f.severity_band || 'INFO'; const s = order[band] ?? -1; if (s > bestScore) { bestScore = s; best = band } }
      return best
    }
    return (order[worst(b[1])] || 0) - (order[worst(a[1])] || 0)
  })

  return (
    <div className="flex flex-col gap-6">
      {/* stat bar - same fields as demo_dashboard.html stat-grid */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="font-mono text-2xl font-semibold tabular-nums">{total}</div>
            <div className="text-xs text-muted-foreground">total findings</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="font-mono text-2xl font-semibold tabular-nums">{cveRecords}</div>
            <div className="text-xs text-muted-foreground">CVEs matched (records)</div>
            <div className="font-mono text-[11px] text-muted-foreground">{cveUnique.size} unique: {[...cveUnique].join(', ') || '—'}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="font-mono text-2xl font-semibold tabular-nums">{cisGrounded}/{total}</div>
            <div className="text-xs text-muted-foreground">grounded in CIS evidence</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="font-mono text-2xl font-semibold tabular-nums">{pipelineErrors}</div>
            <div className="text-xs text-muted-foreground">pipeline errors (unscored / unresolved)</div>
          </CardContent>
        </Card>
      </div>

      {/* host-grouped findings */}
      {sortedHosts.map(([host, list]) => {
        const ex = list[0] || {}
        return (
          <Card key={host}>
            <CardHeader>
              <CardTitle className="text-sm">
                {ex.hostname || host} <span className="font-mono text-xs font-normal text-muted-foreground">· {host} · {list.length} findings</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {list
                .slice()
                .sort((a: any, b: any) => {
                  const order: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNSCORED: -1 }
                  const sa = order[a.severity_band] ?? -1, sb = order[b.severity_band] ?? -1
                  if (sb !== sa) return sb - sa
                  return (b.severity_score || 0) - (a.severity_score || 0)
                })
                .map((f: any) => {
                  const gc = f.grounding_context || { cve_records: [], cis_matches: [] }
                  const cveRecs = gc.cve_records || []
                  const cis = gc.cis_matches || []
                  const hasEvidence = cveRecs.filter((r: any) => !r.not_found).length + cis.length > 0
                  return (
                    <div key={`${f.host}:${f.port}/${f.service}/${f.nse_script || 'asset'}`} className="rounded-lg border border-border p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={severityToLower(f.severity_band || 'INFO')} />
                        {f.severity_score != null && <span className="font-mono text-xs text-muted-foreground">{Number(f.severity_score).toFixed(1)}</span>}
                        <Badge variant="outline" className="font-mono text-xs">{f.type || ''}</Badge>
                        <span className="font-mono text-xs">{f.port}/{f.protocol}</span>
                        {f.service && <span className="text-xs">service <strong className="font-mono">{f.service}</strong></span>}
                        {f.nse_script && <span className="text-xs">nse <strong className="font-mono">{f.nse_script}</strong></span>}
                      </div>
                      {f.scoring_rationale && <div className="mt-1 font-mono text-[11px] text-muted-foreground">Rationale: {f.scoring_rationale}</div>}
                      <div className="mt-2 flex flex-wrap items-center gap-1">
                        {f.cve_refs?.length ? f.cve_refs.map((c: string) => <Badge key={c} variant="outline" className="border-verified/30 bg-verified/10 text-verified">{c}</Badge>) : <span className="text-xs text-muted-foreground">— no CVE ref</span>}
                        {hasEvidence ? (
                          <>
                            {cveRecs.filter((r: any) => !r.not_found).length > 0 && <Badge variant="outline" className="border-verified/30 bg-verified/10 text-verified">{cveRecs.filter((r: any) => !r.not_found).length} CVE</Badge>}
                            {cis.length > 0 && <Badge variant="outline" className="border-verified/30 bg-verified/10 text-verified">{cis.length} CIS</Badge>}
                            <EvidenceBadge status="backed" className="ml-1" />
                          </>
                        ) : (
                          <EvidenceBadge status="none" />
                        )}
                      </div>
                      {/* LLM placeholder */}
                      {!f.llm_output && (
                        <div className="mt-2 rounded-md border border-dashed border-border bg-muted/20 p-2 text-xs text-muted-foreground">
                          Not wired yet — synthesize.py is out of scope for this view (no LLM narrative in JSON)
                        </div>
                      )}
                    </div>
                  )
                })}
            </CardContent>
          </Card>
        )
      })}

      {/* LLM synthesis placeholder matching Jinja */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">LLM synthesis — placeholder</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-border bg-muted/20 p-3 text-sm text-muted-foreground">
            <div className="font-medium text-foreground">Not wired yet</div>
            <div className="text-xs">synthesize.py is out of scope for this view</div>
            <p className="mt-1 text-xs">This dashboard renders only the grounded findings layer (rule-engine score + CVE/CIS evidence). When <code className="font-mono">synthesize.py</code> has produced <code className="font-mono">llm_output.jsonl</code>, this section will display per-finding narratives.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
