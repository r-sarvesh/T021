import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { MetricRow, type Ratio } from '@/components/benchmark/metric-row'

interface ConditionSummary {
  per_finding_any: Ratio
  per_finding_unsupported: Ratio
  per_finding_fabricated: Ratio
  per_citation_bad: Ratio
  findings_zero_citations: Ratio
  total_citations: number
}

interface StructuredSummary {
  grounded: ConditionSummary
  ungrounded: ConditionSummary
  headline_per_finding?: string
  headline_per_citation?: string
  headline_detailed?: string
}

/**
 * One dataset's hallucination panel: five metrics as grounded/ungrounded bar
 * pairs, an abstention note shown only when the ungrounded variant cited
 * nothing, and the source/headline strings read straight from the data.
 */
export function SummaryPanel({
  title,
  sourceFile,
  structured,
  caseNote,
}: {
  title: string
  sourceFile?: string
  structured: StructuredSummary
  caseNote?: string
}) {
  const g = structured.grounded
  const u = structured.ungrounded
  const abstention = u.total_citations === 0
  const headline =
    structured.headline_detailed ||
    (structured.headline_per_finding
      ? `Headline — per-finding: ${structured.headline_per_finding}` +
        (structured.headline_per_citation
          ? ` · per-citation: ${structured.headline_per_citation}`
          : '')
      : '')

  return (
    <Card className="rounded-2xl border border-border p-[22px] ring-0">
      <CardHeader className="px-0">
        <CardTitle className="text-sm font-semibold">
          {title}
          {caseNote ? (
            <span className="ml-1.5 font-normal text-muted-foreground"> — {caseNote}</span>
          ) : null}
        </CardTitle>
        {sourceFile ? (
          <div className="font-mono text-[11px] break-all text-muted-foreground">
            source {sourceFile}
          </div>
        ) : null}
      </CardHeader>

      <CardContent className="flex flex-col gap-0 px-0">
        <MetricRow label="Per-finding any bad" grounded={g.per_finding_any} ungrounded={u.per_finding_any} />
        <MetricRow
          label="Per-finding unsupported"
          grounded={g.per_finding_unsupported}
          ungrounded={u.per_finding_unsupported}
        />
        <MetricRow
          label="Per-finding fabricated"
          grounded={g.per_finding_fabricated}
          ungrounded={u.per_finding_fabricated}
        />
        <MetricRow label="Per-citation bad" grounded={g.per_citation_bad} ungrounded={u.per_citation_bad} />
        <MetricRow
          label="Findings with zero citations"
          grounded={g.findings_zero_citations}
          ungrounded={u.findings_zero_citations}
        />

        {abstention && (
          <div
            role="note"
            className="mt-3 rounded-lg border border-warn/40 bg-warn/10 p-3 text-xs leading-relaxed text-foreground"
          >
            <span className="font-medium text-warn">Note:</span> the ungrounded variant issued zero
            citations across all {u.per_finding_any.den} findings in this dataset, so its bad-citation
            rate reflects abstention, not accuracy. This corpus shows grounded precision, not the
            hallucination gap.
          </div>
        )}

        {headline && (
          <div className="mt-3 font-mono text-[11px] break-words text-muted-foreground">{headline}</div>
        )}
      </CardContent>
    </Card>
  )
}
