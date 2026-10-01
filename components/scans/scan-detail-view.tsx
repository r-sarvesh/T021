'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, Search, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { getScan, getScanHosts, listFindings } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { SeverityBadge } from '@/components/severity-badge'
import { EvidenceBadge } from '@/components/evidence-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ErrorState, TableSkeleton } from '@/components/data-states'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { formatDateTime } from '@/lib/format'
import type { Finding } from '@/lib/api/types'

export function ScanDetailView({ scanId }: { scanId: string }) {
  const scan = useAsync(() => getScan(scanId), [scanId])
  const hosts = useAsync(() => getScanHosts(scanId), [scanId])
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [evidence, setEvidence] = useState<'all' | 'backed' | 'none'>('all')
  const findings = useAsync(() => listFindings(scanId, { search, severity, evidence }), [scanId, search, severity, evidence])

  if (scan.loading) {
    return <TableSkeleton rows={6} />
  }
  if (scan.error) {
    const isNotFound = (scan.error as any)?.code === 'not_found' || scan.error.message.includes('not found')
    if (isNotFound) {
      return (
        <Empty className="py-16">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <ShieldQuestion />
            </EmptyMedia>
            <EmptyTitle>Scan not found</EmptyTitle>
            <EmptyDescription>
              No scan with ID <span className="font-mono">{scanId}</span> exists. It may have been deleted or the ID is incorrect.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button render={<Link href="/scans" />}>
              <ArrowLeft data-icon="inline-start" />
              Back to scans
            </Button>
          </EmptyContent>
        </Empty>
      )
    }
    return <ErrorState message={scan.error.message} onRetry={scan.reload} />
  }

  const scanData = scan.data!

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" render={<Link href="/scans" />}>
          <ArrowLeft data-icon="inline-start" />
          Back to scans
        </Button>
      </div>

      <div className="flex flex-col gap-1">
        <h2 className="text-lg font-semibold tracking-tight">{scanData.name}</h2>
        <p className="text-sm text-muted-foreground font-mono">{scanData.filename} · Imported {formatDateTime(scanData.importedAt)} by {scanData.importedBy}</p>
      </div>

      {/* Host risk summary - reuse host cards styling from dashboard */}
      {hosts.loading ? (
        <TableSkeleton rows={3} />
      ) : hosts.error ? (
        <ErrorState message={hosts.error.message} onRetry={hosts.reload} />
      ) : hosts.data && hosts.data.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Host risk summary</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {hosts.data.map((host) => (
              <div key={host.id} className="rounded-lg border border-border p-3 flex flex-col gap-2">
                <div className="font-mono text-sm font-medium">{host.hostname || host.ip}</div>
                <div className="text-xs text-muted-foreground font-mono">{host.ip} · {host.openPorts} open ports · {host.findingCount} findings</div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-lg font-semibold tabular-nums">{host.riskScore ?? '—'}</span>
                  {host.highestSeverity && ['critical','high','medium','low'].includes(host.highestSeverity) && <SeverityBadge severity={host.highestSeverity as any} />}
                  {host.highestSeverity && !['critical','high','medium','low'].includes(host.highestSeverity) && <span className="text-xs text-muted-foreground capitalize">{host.highestSeverity}</span>}
                </div>
                <div className="flex gap-2 text-xs">
                  <EvidenceBadge status={host.evidenceBacked > 0 ? 'backed' : 'none'} />
                  <span className="text-muted-foreground">{host.evidenceBacked} backed, {host.evidenceMissing} unverified</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      {/* Findings toolbar - reuse scans-view filter styling */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search service · CVE · host · product…"
            className="pl-9"
            aria-label="Search findings"
          />
        </div>
        <Select value={severity} onValueChange={(v) => setSeverity(v as any)}>
          <SelectTrigger className="w-[150px]" aria-label="Filter by severity">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
        <Select value={evidence} onValueChange={(v) => setEvidence(v as any)}>
          <SelectTrigger className="w-[160px]" aria-label="Filter by evidence">
            <SelectValue placeholder="Evidence" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All evidence</SelectItem>
              <SelectItem value="backed">Evidence-backed</SelectItem>
              <SelectItem value="none">Unverified</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>

      {/* Findings — card per finding, no horizontal table */}
      <div className="flex flex-col gap-3">
        {findings.loading ? (
          <Card>
            <CardContent className="p-4">
              <TableSkeleton rows={3} />
            </CardContent>
          </Card>
        ) : findings.error ? (
          <Card>
            <CardContent className="p-4">
              <ErrorState message={findings.error.message} onRetry={findings.reload} />
            </CardContent>
          </Card>
        ) : findings.data && findings.data.length === 0 ? (
          <Card>
            <CardContent className="p-0">
              <Empty className="py-16">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <ShieldCheck />
                  </EmptyMedia>
                  <EmptyTitle>No findings match your filters</EmptyTitle>
                  <EmptyDescription>Adjust the filters above or import a new scan.</EmptyDescription>
                </EmptyHeader>
              </Empty>
            </CardContent>
          </Card>
        ) : (
          findings.data?.map((f: Finding, idx: number) => (
            <Card key={`${f.id}-${f.severity}-${idx}`} className="overflow-hidden">
              <CardContent className="p-4 flex flex-col gap-3">
                {/* Top strip: compact badges that wrap naturally */}
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  {f.cvss != null && <span className="font-mono text-xs text-muted-foreground">{f.cvss}</span>}
                  <span className="font-mono text-xs text-muted-foreground">·</span>
                  <span className="font-mono text-xs">{f.host}</span>
                  {f.hostname && <span className="text-xs text-muted-foreground truncate max-w-[160px]">{f.hostname}</span>}
                  <span className="text-xs text-muted-foreground">·</span>
                  <span className="text-xs">
                    {f.service || '—'} <span className="text-muted-foreground">{f.port}/{f.protocol}</span>
                  </span>
                  {f.cve ? (
                    <span className="inline-flex items-center gap-1 rounded-md border border-verified/30 bg-verified/10 px-2 py-0.5 text-xs font-medium text-verified">
                      {f.cve.id}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">— no CVE ref</span>
                  )}
                  <span className="ml-auto">
                    <EvidenceBadge status={f.evidenceStatus} />
                  </span>
                </div>
                {/* Full-width evidence/synthesis */}
                <div className="flex flex-col gap-2">
                  <p className="text-sm leading-relaxed">{f.description}</p>
                  {f.cve && (
                    <details className="rounded-md border border-border bg-muted/20 px-3 py-2">
                      <summary className="cursor-pointer text-xs font-medium">CVE evidence — {f.cve.id} CVSS {f.cve.cvss} {f.cve.cvssSeverity} {f.cve.knownExploited ? '· KEV' : ''}</summary>
                      <div className="mt-2 text-xs leading-relaxed space-y-1">
                        <p>{f.cve.description}</p>
                        <p className="font-mono text-[11px] text-muted-foreground">Source: {f.cve.source}</p>
                      </div>
                    </details>
                  )}
                  {f.cis && (
                    <details className="rounded-md border border-border bg-muted/20 px-3 py-2">
                      <summary className="cursor-pointer text-xs font-medium">CIS control — {f.cis.control} — {f.cis.title}</summary>
                      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{f.cis.recommendation}</p>
                    </details>
                  )}
                  {f.severityReasoning && <p className="font-mono text-[11px] text-muted-foreground">Reasoning: {f.severityReasoning}</p>}
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  )
}
