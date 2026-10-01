import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface Parsed {
  plain_language_explanation?: string
  remediation_steps?: string[]
  cis_controls_referenced?: string[]
  cve_ids_mentioned?: string[]
}

interface Record_ {
  finding_ref?: string
  severity_band?: string
  raw_output?: string
  parsed?: Parsed
  extracted_cve_ids?: string[]
}

interface Scored {
  has_bad_citation?: boolean
  allowed_cve_ids?: string[]
  unsupported_cve_ids?: string[]
  fabricated_cve_ids?: string[]
  citation_count?: number
  bad_citation_count?: number
}

/**
 * One side of the grounded/ungrounded comparison: narrative, CVE chips
 * (outlined green when supported, red + tagged when bad), a key/value block
 * of the raw citation accounting, remediation bullets and the collapsible
 * raw LLM JSON.
 */
export function CompareCard({
  variant,
  record,
  scored,
}: {
  variant: 'grounded' | 'ungrounded'
  record: Record_
  scored: Scored
}) {
  const isGrounded = variant === 'grounded'
  const bad = Boolean(scored.has_bad_citation)
  const supported = !bad

  const cited: string[] = record.extracted_cve_ids || record.parsed?.cve_ids_mentioned || []
  const allowed: string[] = scored.allowed_cve_ids || []
  const unsupported: string[] = scored.unsupported_cve_ids || []
  const fabricated: string[] = scored.fabricated_cve_ids || []
  const cis = record.parsed?.cis_controls_referenced
  const remediation = record.parsed?.remediation_steps

  return (
    <Card
      className={[
        'rounded-2xl border border-border p-[22px] ring-0 border-t-[3px]',
        isGrounded
          ? 'border-t-good bg-gradient-to-b from-good/[0.07] to-card'
          : 'border-t-bad bg-gradient-to-b from-bad/[0.07] to-card',
      ].join(' ')}
    >
      <CardHeader className="px-0">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-mono text-xs tracking-wide uppercase">{variant}</span>
          <Badge
            variant={supported ? 'outline' : 'destructive'}
            className={
              supported
                ? isGrounded
                  ? 'border-good/40 bg-good/10 text-good'
                  : 'border-good/40 bg-good/10 text-good'
                : ''
            }
          >
            {supported ? 'SUPPORTED' : 'FLAGGED'}
          </Badge>
          <span className="text-[11px] font-normal text-muted-foreground">
            {isGrounded
              ? 'grounded — only retrieved CVEs may be cited'
              : 'ungrounded — no retrieval context'}
          </span>
        </CardTitle>
      </CardHeader>

      <CardContent className="flex flex-col gap-3 px-0 text-sm">
        <p className="leading-relaxed text-foreground">
          {record.parsed?.plain_language_explanation || record.raw_output || ''}
        </p>

        {/* CVE chips */}
        <div className="flex flex-wrap gap-1.5">
          {cited.length ? (
            cited.map((c) => {
              const badCve = unsupported.includes(c) || fabricated.includes(c)
              return (
                <span
                  key={c}
                  className={[
                    'inline-flex items-center gap-1.5 rounded-lg border px-2 py-0.5 font-mono text-xs',
                    badCve
                      ? 'border-bad/50 bg-bad/10 text-bad'
                      : 'border-good/50 bg-good/10 text-good',
                  ].join(' ')}
                >
                  {c}
                  {fabricated.includes(c) && (
                    <span className="rounded border border-bad/40 px-1 font-sans text-[9px] font-medium">
                      fabricated_cve
                    </span>
                  )}
                  {unsupported.includes(c) && (
                    <span className="rounded border border-bad/40 px-1 font-sans text-[9px] font-medium">
                      unsupported_cve
                    </span>
                  )}
                </span>
              )
            })
          ) : (
            <span className="text-xs text-muted-foreground">— no CVE cited</span>
          )}
        </div>

        {/* Key / value citation accounting */}
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-border bg-muted/20 p-3 font-mono text-[11px]">
          <dt className="text-muted-foreground">Allowed CVEs</dt>
          <dd className="break-all text-foreground">
            {allowed.length ? allowed.join(', ') : '(none — ungrounded)'}
          </dd>
          <dt className="text-muted-foreground">Citation count / bad</dt>
          <dd className="text-foreground">
            {scored.citation_count ?? 0} / {scored.bad_citation_count ?? 0}
          </dd>
          {cis && (
            <>
              <dt className="text-muted-foreground">CIS referenced</dt>
              <dd className="break-all text-foreground">
                {cis.length ? cis.join(', ') : '—'}
              </dd>
            </>
          )}
        </dl>

        {/* Remediation bullets */}
        {remediation && remediation.length > 0 && (
          <div>
            <div className="mb-1 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">
              Remediation
            </div>
            <ul className="list-disc space-y-1 pl-5 text-xs text-foreground">
              {remediation.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Collapsible raw model output */}
        <details>
          <summary className="cursor-pointer text-xs text-muted-foreground">
            Raw LLM JSON
          </summary>
          <pre className="mt-1.5 overflow-x-auto rounded-lg border border-border bg-muted/20 p-2 font-mono text-[11px] break-words whitespace-pre-wrap">
            {record.raw_output || ''}
          </pre>
        </details>
      </CardContent>
    </Card>
  )
}
