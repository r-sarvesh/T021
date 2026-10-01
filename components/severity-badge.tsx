import { AlertCircle, AlertTriangle, Info, ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { severityLabel } from '@/lib/format'
import type { Severity } from '@/lib/api/types'

/**
 * Severity indicator. Severity is never communicated by color alone: every
 * badge carries an icon and a text label in addition to its color treatment.
 */
const config: Record<
  Severity,
  { icon: typeof ShieldAlert; className: string }
> = {
  critical: {
    icon: ShieldAlert,
    className: 'bg-critical/15 text-critical border-critical/30',
  },
  high: {
    icon: AlertTriangle,
    className: 'bg-high/15 text-high border-high/30',
  },
  medium: {
    icon: AlertCircle,
    className: 'bg-medium/15 text-medium border-medium/30',
  },
  low: {
    icon: Info,
    className: 'bg-low/15 text-low border-low/30',
  },
  unscored: {
    icon: Info,
    className: 'bg-muted text-muted-foreground border-border border-dashed',
  },
}

export function SeverityBadge({
  severity,
  className,
  showLabel = true,
}: {
  severity: Severity
  className?: string
  showLabel?: boolean
}) {
  const { icon: Icon, className: tone } = config[severity]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium',
        tone,
        className,
      )}
    >
      <Icon className="size-3.5" aria-hidden="true" />
      {showLabel && <span>{severityLabel[severity]}</span>}
      <span className="sr-only">severity: {severityLabel[severity]}</span>
    </span>
  )
}

/** Small colored dot + count, for compact severity distributions. */
export function SeverityDot({ severity }: { severity: Severity }) {
  const tone: Record<Severity, string> = {
    critical: 'bg-critical',
    high: 'bg-high',
    medium: 'bg-medium',
    low: 'bg-low',
    unscored: 'bg-muted-foreground',
  }
  return (
    <span
      className={cn('inline-block size-2 rounded-full', tone[severity])}
      aria-hidden="true"
    />
  )
}
