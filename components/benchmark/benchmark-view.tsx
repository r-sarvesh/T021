'use client'

import { getBenchmarkData } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ErrorState, TableSkeleton } from '@/components/data-states'

function fmt(num: number, den: number) {
  if (den === 0) return `0/0 N/A (abstention)`
  const pct = ((num / den) * 100).toFixed(1)
  return `${num}/${den} (${pct}%)`
}

export function BenchmarkView() {
  const bench = useAsync(() => getBenchmarkData(), [])

  if (bench.loading) return <TableSkeleton rows={10} />
  if (bench.error) return <ErrorState message={bench.error.message} onRetry={bench.reload} />

  const data: any = bench.data
  const side = data.side_by_side
  const scoredGrounded = side.scored_grounded
  const scoredUngrounded = side.scored_ungrounded
  const groundedRec = side.grounded
  const ungroundedRec = side.ungrounded
  const live = data.summary_live_small?.structured
  const corpus = data.summary_corpus?.structured

  const renderCard = (variant: 'grounded' | 'ungrounded', rec: any, scored: any) => {
    const isGrounded = variant === 'grounded'
    const hasBad = scored.has_bad_citation
    const isSupported = !hasBad
    const border = isGrounded ? (isSupported ? 'border-verified/30' : 'border-critical/30') : hasBad ? 'border-critical/30' : 'border-border'
    const bg = !isSupported ? 'bg-critical/5' : isGrounded ? 'bg-verified/5' : 'bg-card'
    const cveIds: string[] = rec.extracted_cve_ids || rec.parsed?.cve_ids_mentioned || []
    const allowed: string[] = scored.allowed_cve_ids || []
    const unsupported: string[] = scored.unsupported_cve_ids || []
    const fabricated: string[] = scored.fabricated_cve_ids || []
    return (
      <Card className={`${border} ${bg} border-l-4`}>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-mono uppercase">{variant}</span>
            <Badge variant={isSupported ? 'outline' : 'destructive'} className={isSupported ? 'border-verified/30 bg-verified/10 text-verified' : ''}>
              {isSupported ? 'SUPPORTED' : 'FLAGGED'}
            </Badge>
            <span className="text-xs font-normal text-muted-foreground">{isGrounded ? 'grounded — only retrieved CVEs may be cited' : 'ungrounded — no retrieval context'}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 text-sm">
          <div className="font-mono text-xs text-muted-foreground">
            Finding {rec.finding_ref} · {rec.severity_band} · retrieved: {rec.retrieved_cve_ids?.join(', ') || '(none)'}
          </div>
          <p className="text-sm leading-relaxed">{rec.parsed?.plain_language_explanation || rec.raw_output || ''}</p>
          <div className="flex flex-wrap gap-1">
            {cveIds.length ? cveIds.map((c) => (
              <span key={c} className="inline-flex items-center gap-1 rounded-md border border-verified/30 bg-verified/10 px-2 py-0.5 text-xs font-medium text-verified">
                {c}
                {fabricated.includes(c) && <Badge variant="destructive" className="ml-1 px-1 py-0 text-[9px]">fabricated_cve</Badge>}
                {unsupported.includes(c) && <Badge variant="destructive" className="ml-1 px-1 py-0 text-[9px]">unsupported_cve</Badge>}
              </span>
            )) : <span className="text-xs text-muted-foreground">— no CVE cited</span>}
          </div>
          <div className="font-mono text-xs text-muted-foreground">Allowed: {allowed.join(', ') || '(none — ungrounded)'} · Citation count: {scored.citation_count} · Bad: {scored.bad_citation_count}</div>
          {rec.parsed?.cis_controls_referenced && <div className="font-mono text-xs">CIS referenced: {rec.parsed.cis_controls_referenced.join(', ') || '—'}</div>}
          {rec.parsed?.remediation_steps && (
            <ul className="list-disc pl-5 text-xs">
              {rec.parsed.remediation_steps.map((s: string, i: number) => <li key={i}>{s}</li>)}
            </ul>
          )}
          <details>
            <summary className="cursor-pointer text-xs text-muted-foreground">Raw LLM JSON</summary>
            <pre className="mt-1 whitespace-pre-wrap rounded border border-border bg-muted/20 p-2 font-mono text-[11px]">{rec.raw_output || ''}</pre>
          </details>
        </CardContent>
      </Card>
    )
  }

  const renderSummaryTable = (title: string, summary: any) => {
    const g = summary.grounded, u = summary.ungrounded
    const Row = ({ label, variant, data, tone }: { label: string; variant: 'grounded' | 'ungrounded'; data: any; tone: string }) => (
      <div className="rounded-lg border border-border p-3 flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <Badge variant={variant === 'grounded' ? 'outline' : 'destructive'} className={variant === 'grounded' ? 'border-verified/30 bg-verified/10 text-verified' : ''}>{label}</Badge>
          <span className={`text-xs font-medium ${tone}`}>{variant}</span>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div><span className="text-muted-foreground">Per-finding any bad:</span> <span className="font-mono">{fmt(data.per_finding_any.num, data.per_finding_any.den)}</span></div>
          <div><span className="text-muted-foreground">Zero citations:</span> <span className="font-mono">{data.findings_zero_citations.num}/{data.findings_zero_citations.den}</span></div>
          <div><span className="text-muted-foreground">Per-finding fabricated:</span> <span className="font-mono">{fmt(data.per_finding_fabricated.num, data.per_finding_fabricated.den)}</span></div>
          <div><span className="text-muted-foreground">Per-citation bad:</span> <span className="font-mono">{fmt(data.per_citation_bad.num, data.per_citation_bad.den)}</span></div>
          <div><span className="text-muted-foreground">Per-finding unsupported:</span> <span className="font-mono">{fmt(data.per_finding_unsupported.num, data.per_finding_unsupported.den)}</span></div>
          <div><span className="text-muted-foreground">Per-citation unsupported:</span> <span className="font-mono">{fmt(data.per_citation_unsupported.num, data.per_citation_unsupported.den)}</span></div>
          <div className="col-span-2"><span className="text-muted-foreground">Per-citation fabricated:</span> <span className="font-mono">{fmt(data.per_citation_fabricated.num, data.per_citation_fabricated.den)}</span></div>
        </div>
      </div>
    )
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-xs">{title}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Row label="grounded" variant="grounded" data={g} tone="text-verified" />
          <Row label="ungrounded" variant="ungrounded" data={u} tone="text-critical" />
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="rounded-md border border-verified/30 bg-verified/5 p-3 text-sm">
        <span className="font-mono font-medium">Benchmark — real Gemini API calls</span> · grounded vs ungrounded prompt conditions · distinct from the live-pipeline retrieval view in <span className="font-mono">/demo</span> · source: <span className="font-mono">reports/llm_live_small.jsonl + reports/summary_live_small.txt</span> (live NVD API 2.0)
      </div>

      <div>
        <h3 className="text-sm font-semibold tracking-tight">Side-by-side — same finding, two prompt conditions</h3>
        <div className="mt-1 font-mono text-xs text-muted-foreground">
          Finding {side.finding_ref} · {side.severity_band} · smb-vuln-ms17-010 on 192.168.1.10:445 · retrieved: CVE-2017-0143
        </div>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        {renderCard('grounded', groundedRec, scoredGrounded)}
        {renderCard('ungrounded', ungroundedRec, scoredUngrounded)}
      </div>

      <div>
        <h3 className="text-sm font-semibold">Summary — hallucination rates (raw counts + %)</h3>
        <p className="text-xs text-muted-foreground">Always show raw counts alongside rates — split by fabricated_cve (invented ID) vs unsupported_cve (real ID, not in retrieved context)</p>
      </div>

      {live && renderSummaryTable('Live small validation — 2 findings (the CVE-2017-0144 case)', live)}
      {live && <div className="font-mono text-xs text-muted-foreground">Headline — per-finding: {live.headline_per_finding} · per-citation: {live.headline_per_citation} · source {data.summary_live_small.source_file}</div>}

      {corpus && renderSummaryTable('Full synthetic corpus — 58 findings (corpus-scale run)', corpus)}
      {corpus && <div className="font-mono text-xs text-muted-foreground">{(corpus as any).headline_detailed || `Headline — per-finding: ${corpus.headline_per_finding} · per-citation: ${corpus.headline_per_citation} · source ${data.summary_corpus.source_file}`}</div>}

      <Card>
        <CardHeader>
          <CardTitle className="text-xs">Verbatim — hallucination_summary.txt</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <pre className="whitespace-pre-wrap rounded border border-border bg-muted/20 p-3 font-mono text-[11px]">{data.summary_live_small.verbatim}</pre>
          <pre className="whitespace-pre-wrap rounded border border-border bg-muted/20 p-3 font-mono text-[11px]">{data.summary_corpus.verbatim}</pre>
        </CardContent>
      </Card>
    </div>
  )
}
