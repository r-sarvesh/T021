'use client'

import { getBenchmarkData } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { ErrorState, TableSkeleton } from '@/components/data-states'
import { StatCard } from '@/components/benchmark/stat-card'
import { CompareCard } from '@/components/benchmark/compare-card'
import { SummaryPanel } from '@/components/benchmark/summary-panel'
import { ratioPctText, type Ratio } from '@/components/benchmark/metric-row'

interface Condition {
  per_finding_any: Ratio
  per_finding_unsupported: Ratio
  per_finding_fabricated: Ratio
  per_citation_bad: Ratio
  per_citation_fabricated: Ratio
  findings_zero_citations: Ratio
  total_citations: number
}

function rawLine(c: Condition) {
  const any = c.per_finding_any
  const cit = c.per_citation_bad
  return `${any.num}/${any.den} findings · ${cit.num}/${cit.den} citations`
}

export function BenchmarkView() {
  const bench = useAsync(() => getBenchmarkData(), [])

  if (bench.loading) return <TableSkeleton rows={10} />
  if (bench.error) return <ErrorState message={bench.error.message} onRetry={bench.reload} />

  const data: any = bench.data
  const side = data.side_by_side
  const groundedRec: any = side.grounded
  const ungroundedRec: any = side.ungrounded
  const scoredGrounded: any = side.scored_grounded
  const scoredUngrounded: any = side.scored_ungrounded
  const live = data.summary_live_small?.structured
  const corpus = data.summary_corpus?.structured

  // Fabricated CVE citations across every loaded dataset (computed, never typed)
  const conditions: Condition[] = [
    live?.grounded,
    live?.ungrounded,
    corpus?.grounded,
    corpus?.ungrounded,
  ].filter(Boolean)
  const fabricatedTotal = conditions.reduce(
    (sum, c) => sum + (c.per_citation_fabricated?.num || 0),
    0,
  )
  const citationTotal = conditions.reduce((sum, c) => sum + (c.total_citations || 0), 0)
  const datasets = [live && 'live small', corpus && 'corpus'].filter(Boolean).join(' + ')

  const retrieved: string[] = groundedRec.retrieved_cve_ids || []
  const liveCaseId = scoredUngrounded.unsupported_cve_ids?.[0]

  return (
    <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-8">
      {/* Hero */}
      <section className="flex flex-col items-start gap-4">
        <span className="inline-flex w-fit items-center gap-2 rounded-full border border-good/30 bg-good/10 px-3 py-1 font-mono text-xs text-good">
          <span className="size-1.5 rounded-full bg-good" aria-hidden="true" />
          Real Gemini API calls · {data.meta.existence_mode_live_small}
        </span>
        <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">
          Same findings, two prompt conditions,{' '}
          <span className="bg-gradient-to-r from-good to-brand bg-clip-text text-transparent">
            every citation checked.
          </span>
        </h1>
        <p className="max-w-[72ch] text-sm leading-relaxed text-muted-foreground">
          {data.meta.label}
        </p>
      </section>

      {/* Headline stats */}
      {live && (
        <section aria-label="Headline statistics" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <StatCard
            tone="good"
            value={ratioPctText(live.grounded.per_finding_any)}
            label="Grounded bad-citation rate"
            raw={rawLine(live.grounded)}
          />
          <StatCard
            tone="bad"
            value={ratioPctText(live.ungrounded.per_finding_any)}
            label="Ungrounded bad-citation rate"
            raw={rawLine(live.ungrounded)}
          />
          <StatCard
            tone="brand"
            value={String(fabricatedTotal)}
            label="Fabricated CVEs"
            raw={`${fabricatedTotal}/${citationTotal} citations · ${datasets}`}
          />
        </section>
      )}

      {/* Side by side */}
      <section className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <h2 className="text-sm font-semibold tracking-tight">
            Side by side — same finding, two prompt conditions
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-lg border border-border bg-muted/40 px-2 py-1 font-mono text-xs break-all text-foreground">
              {side.finding_ref}
            </span>
            <span className="rounded-lg border border-high/40 bg-high/10 px-2 py-1 text-xs font-medium text-high">
              {side.severity_band}
            </span>
            <span className="text-[11px] text-muted-foreground">retrieved</span>
            {retrieved.map((cve: string) => (
              <span
                key={cve}
                className="rounded-lg border border-border bg-muted/40 px-2 py-1 font-mono text-xs text-foreground"
              >
                {cve}
              </span>
            ))}
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <CompareCard variant="grounded" record={groundedRec} scored={scoredGrounded} />
          <CompareCard variant="ungrounded" record={ungroundedRec} scored={scoredUngrounded} />
        </div>
      </section>

      {/* Hallucination rates */}
      <section className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold tracking-tight">Hallucination rates</h2>
          <p className="text-xs text-muted-foreground">
            Raw counts alongside rates — split by fabricated_cve (invented ID) vs unsupported_cve
            (real ID, not in retrieved context)
          </p>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          {live && (
            <SummaryPanel
              title={`Live small validation — ${live.grounded.per_finding_any.den} findings`}
              caseNote={liveCaseId ? `the ${liveCaseId} case` : undefined}
              sourceFile={data.summary_live_small?.source_file}
              structured={live}
            />
          )}
          {corpus && (
            <SummaryPanel
              title={`Full synthetic corpus — ${corpus.grounded.per_finding_any.den} findings (corpus-scale run)`}
              sourceFile={data.summary_corpus?.source_file}
              structured={corpus}
            />
          )}
        </div>
      </section>

      {/* Verbatim evidence (collapsed) */}
      <details className="rounded-2xl border border-border bg-card p-[22px]">
        <summary className="cursor-pointer text-xs font-medium text-foreground">
          Verbatim summary
        </summary>
        <div className="mt-3 flex flex-col gap-3">
          <pre className="overflow-x-auto rounded-lg border border-border bg-muted/20 p-3 font-mono text-[11px] break-words whitespace-pre-wrap">
            {data.summary_live_small?.verbatim}
          </pre>
          <pre className="overflow-x-auto rounded-lg border border-border bg-muted/20 p-3 font-mono text-[11px] break-words whitespace-pre-wrap">
            {data.summary_corpus?.verbatim}
          </pre>
        </div>
      </details>
    </div>
  )
}
