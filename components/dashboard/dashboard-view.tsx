'use client'

import Link from 'next/link'
import {
  Activity,
  Bug,
  Server,
  ShieldCheck,
  ShieldQuestion,
  Upload,
} from 'lucide-react'
import { getDashboardSummary, listScans } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { MetricCard } from '@/components/metric-card'
import { SeverityDistribution } from '@/components/severity-distribution'
import { EvidenceCoverage } from '@/components/evidence-coverage'
import { SeverityBadge } from '@/components/severity-badge'
import { ScanStatusBadge } from '@/components/scan-status-badge'
import { MetricSkeletonRow, ErrorState, TableSkeleton } from '@/components/data-states'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { formatRelative } from '@/lib/format'

export function DashboardView() {
  const summary = useAsync(() => getDashboardSummary(), [])
  const recent = useAsync(() => listScans({ sort: 'recent' }), [])

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Assessment overview</h2>
          <p className="text-sm text-muted-foreground">
            Current cybersecurity health across all completed scans.
          </p>
        </div>
        <Button render={<Link href="/import" />}>
          <Upload data-icon="inline-start" />
          Import Nmap scan
        </Button>
      </div>

      {/* Overview metrics */}
      {summary.loading ? (
        <MetricSkeletonRow />
      ) : summary.error ? (
        <ErrorState message={summary.error.message} onRetry={summary.reload} />
      ) : summary.data ? (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <MetricCard label="Total scans" value={summary.data.totalScans} icon={Activity} tone="primary" />
            <MetricCard label="Total findings" value={summary.data.totalFindings} icon={Bug} />
            <MetricCard label="Hosts assessed" value={summary.data.hostsAssessed} icon={Server} />
            <MetricCard
              label="Evidence-backed"
              value={summary.data.evidenceBacked}
              icon={ShieldCheck}
              tone="verified"
              hint={`${summary.data.evidenceMissing} unverified`}
            />
          </div>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <MetricCard
              label="Critical findings"
              value={summary.data.severityCounts.critical}
              tone="critical"
            />
            <MetricCard label="High findings" value={summary.data.severityCounts.high} tone="high" />
            <MetricCard
              label="Medium findings"
              value={summary.data.severityCounts.medium}
              tone="medium"
            />
            <MetricCard label="Low findings" value={summary.data.severityCounts.low} tone="low" />
          </div>

          {/* Health summary + distributions */}
          <div className="grid gap-3 lg:grid-cols-3">
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-sm">Security health</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {summary.data.overallRisk ? (
                  <div className="flex flex-col gap-2">
                    <span className="text-xs text-muted-foreground">Overall risk</span>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={summary.data.overallRisk.level} />
                      <span className="text-sm font-medium">{summary.data.overallRisk.label}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Overall risk score not provided by the backend.
                  </p>
                )}
                <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 p-3">
                  <span className="flex items-center gap-2 text-sm text-muted-foreground">
                    <ShieldCheck className="size-4 text-verified" aria-hidden="true" />
                    Critical exposure
                  </span>
                  <span className="font-mono text-lg font-semibold tabular-nums text-critical">
                    {summary.data.severityCounts.critical}
                  </span>
                </div>
                <EvidenceCoverage
                  backed={summary.data.evidenceBacked}
                  missing={summary.data.evidenceMissing}
                />
              </CardContent>
            </Card>

            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-sm">Severity distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <SeverityDistribution counts={summary.data.severityCounts} />
              </CardContent>
            </Card>

            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-sm">Evidence coverage</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-md border border-verified/25 bg-verified/10 p-3">
                    <div className="flex items-center gap-1.5 text-verified">
                      <ShieldCheck className="size-4" aria-hidden="true" />
                      <span className="text-xs font-medium">Backed</span>
                    </div>
                    <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-verified">
                      {summary.data.evidenceBacked}
                    </p>
                  </div>
                  <div className="rounded-md border border-border bg-muted/30 p-3">
                    <div className="flex items-center gap-1.5 text-muted-foreground">
                      <ShieldQuestion className="size-4" aria-hidden="true" />
                      <span className="text-xs font-medium">Unverified</span>
                    </div>
                    <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-muted-foreground">
                      {summary.data.evidenceMissing}
                    </p>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  Findings without matched CVE or CIS evidence are never hidden and never presented
                  as verified.
                </p>
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}

      {/* Recent scans */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-sm">Recent scans</CardTitle>
          <Button variant="ghost" size="sm" render={<Link href="/scans" />}>
            View all
          </Button>
        </CardHeader>
        <CardContent>
          {recent.loading ? (
            <TableSkeleton rows={5} />
          ) : recent.error ? (
            <ErrorState message={recent.error.message} onRetry={recent.reload} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">Scan</th>
                    <th className="pb-2 pr-4 font-medium">Imported</th>
                    <th className="pb-2 pr-4 font-medium">Hosts</th>
                    <th className="pb-2 pr-4 font-medium">Findings</th>
                    <th className="pb-2 pr-4 font-medium">Highest</th>
                    <th className="pb-2 pr-4 font-medium">Evidence</th>
                    <th className="pb-2 pr-4 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.data?.map((scan) => (
                    <tr
                      key={scan.id}
                      className="group border-b border-border/60 transition-colors last:border-0 hover:bg-muted/30"
                    >
                      <td className="py-2.5 pr-4">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="font-medium transition-colors group-hover:text-primary"
                        >
                          {scan.name}
                        </Link>
                        <p className="font-mono text-xs text-muted-foreground">{scan.filename}</p>
                      </td>
                      <td className="py-2.5 pr-4 text-muted-foreground">
                        {formatRelative(scan.importedAt)}
                      </td>
                      <td className="py-2.5 pr-4 font-mono tabular-nums">{scan.hostCount}</td>
                      <td className="py-2.5 pr-4 font-mono tabular-nums">{scan.findingCount}</td>
                      <td className="py-2.5 pr-4">
                        {scan.highestSeverity ? (
                          <SeverityBadge severity={scan.highestSeverity} />
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-2.5 pr-4">
                        {scan.status === 'completed' ? (
                          <EvidenceCoverage
                            backed={scan.evidenceBacked}
                            missing={scan.evidenceMissing}
                            compact
                          />
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-2.5 pr-4">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
