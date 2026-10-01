'use client'

import { useState } from 'react'
import Link from 'next/link'
import { Radar, Search, Upload } from 'lucide-react'
import { listScans, type ScanFilters } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { SeverityBadge } from '@/components/severity-badge'
import { EvidenceCoverage } from '@/components/evidence-coverage'
import { ScanStatusBadge } from '@/components/scan-status-badge'
import { ErrorState, TableSkeleton } from '@/components/data-states'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from '@/components/ui/empty'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { formatDateTime } from '@/lib/format'

export function ScansView() {
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<ScanFilters['status']>('all')
  const [severity, setSeverity] = useState<ScanFilters['severity']>('all')
  const [evidence, setEvidence] = useState<ScanFilters['evidence']>('all')
  const [sort, setSort] = useState<ScanFilters['sort']>('recent')

  const scans = useAsync(
    () => listScans({ search, status, severity, evidence, sort }),
    [search, status, severity, evidence, sort],
  )

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Scan library</h2>
          <p className="text-sm text-muted-foreground">
            Imported Nmap assessments across all monitored segments.
          </p>
        </div>
        <Button render={<Link href="/import" />}>
          <Upload data-icon="inline-start" />
          Import Nmap scan
        </Button>
      </div>

      {/* Filter bar */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-3">
          <div className="relative min-w-[200px] flex-1">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search scans by name or filename"
              className="pl-9"
              aria-label="Search scans"
            />
          </div>

          <Select value={status} onValueChange={(v) => setStatus(v as ScanFilters['status'])}>
            <SelectTrigger className="w-[150px]" aria-label="Filter by status">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="processing">Processing</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>

          <Select value={severity} onValueChange={(v) => setSeverity(v as ScanFilters['severity'])}>
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

          <Select value={evidence} onValueChange={(v) => setEvidence(v as ScanFilters['evidence'])}>
            <SelectTrigger className="w-[160px]" aria-label="Filter by evidence coverage">
              <SelectValue placeholder="Evidence" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">All coverage</SelectItem>
                <SelectItem value="complete">Fully backed</SelectItem>
                <SelectItem value="partial">Has unverified</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>

          <Select value={sort} onValueChange={(v) => setSort(v as ScanFilters['sort'])}>
            <SelectTrigger className="w-[150px]" aria-label="Sort scans">
              <SelectValue placeholder="Sort" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="recent">Most recent</SelectItem>
                <SelectItem value="severity">Highest severity</SelectItem>
                <SelectItem value="findings">Most findings</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {/* Results */}
      <Card>
        <CardContent className="p-0">
          {scans.loading ? (
            <div className="p-4">
              <TableSkeleton rows={6} />
            </div>
          ) : scans.error ? (
            <div className="p-4">
              <ErrorState message={scans.error.message} onRetry={scans.reload} />
            </div>
          ) : scans.data && scans.data.length === 0 ? (
            <Empty className="py-16">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Radar />
                </EmptyMedia>
                <EmptyTitle>No scans match your filters</EmptyTitle>
                <EmptyDescription>
                  Adjust the filters above, or import your first Nmap scan to begin your
                  cybersecurity assessment.
                </EmptyDescription>
              </EmptyHeader>
              <EmptyContent>
                <Button render={<Link href="/import" />}>
                  <Upload data-icon="inline-start" />
                  Import Nmap scan
                </Button>
              </EmptyContent>
            </Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs text-muted-foreground">
                    <th className="px-4 py-3 font-medium">Scan</th>
                    <th className="px-4 py-3 font-medium">Imported by</th>
                    <th className="px-4 py-3 font-medium">Imported</th>
                    <th className="px-4 py-3 font-medium">Hosts</th>
                    <th className="px-4 py-3 font-medium">Findings</th>
                    <th className="px-4 py-3 font-medium">Highest</th>
                    <th className="px-4 py-3 font-medium">Evidence</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.data?.map((scan) => (
                    <tr
                      key={scan.id}
                      className="group border-b border-border/60 transition-colors last:border-0 hover:bg-muted/30"
                    >
                      <td className="px-4 py-3">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="font-medium transition-colors group-hover:text-primary"
                        >
                          {scan.name}
                        </Link>
                        <p className="font-mono text-xs text-muted-foreground">{scan.filename}</p>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        {scan.importedBy === 'unknown' ? (
                          <span className="italic text-muted-foreground/70" title="imported before audit tracking was added">unknown</span>
                        ) : (
                          scan.importedBy
                        )}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        {formatDateTime(scan.importedAt)}
                      </td>
                      <td className="px-4 py-3 font-mono tabular-nums">{scan.hostCount}</td>
                      <td className="px-4 py-3 font-mono tabular-nums">{scan.findingCount}</td>
                      <td className="px-4 py-3">
                        {scan.highestSeverity ? (
                          <SeverityBadge severity={scan.highestSeverity} />
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
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
                      <td className="px-4 py-3">
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

      {scans.data && scans.data.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Showing {scans.data.length} scan{scans.data.length === 1 ? '' : 's'}.
        </p>
      )}
    </div>
  )
}
