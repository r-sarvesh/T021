import { cn } from '@/lib/utils'
import { severityLabel, severityOrder } from '@/lib/format'
import type { SeverityCounts } from '@/lib/api/types'

const barTone = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
}

export function SeverityDistribution({
  counts,
  className,
}: {
  counts: SeverityCounts
  className?: string
}) {
  const total = counts.critical + counts.high + counts.medium + counts.low

  return (
    <div className={cn('flex flex-col gap-4', className)}>
      {/* Stacked bar */}
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted/50" role="img" aria-label="Severity distribution">
        {total === 0 ? (
          <div className="h-full w-full bg-muted/50" />
        ) : (
          severityOrder.map((sev) => {
            const pct = (counts[sev] / total) * 100
            if (pct === 0) return null
            return <div key={sev} className={cn('h-full', barTone[sev])} style={{ width: `${pct}%` }} />
          })
        )}
      </div>

      {/* Legend */}
      <ul className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        {severityOrder.map((sev) => (
          <li key={sev} className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className={cn('size-2.5 rounded-sm', barTone[sev])} aria-hidden="true" />
              {severityLabel[sev]}
            </span>
            <span className="font-mono text-sm font-semibold tabular-nums">{counts[sev]}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
