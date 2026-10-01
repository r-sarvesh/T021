import { ShieldCheck, ShieldQuestion } from 'lucide-react'
import { cn } from '@/lib/utils'

export function EvidenceCoverage({
  backed,
  missing,
  className,
  compact = false,
}: {
  backed: number
  missing: number
  className?: string
  compact?: boolean
}) {
  const total = backed + missing
  const pct = total === 0 ? 0 : Math.round((backed / total) * 100)

  if (compact) {
    return (
      <div className={cn('flex items-center gap-2', className)}>
        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted/60">
          <div className="h-full rounded-full bg-verified" style={{ width: `${pct}%` }} />
        </div>
        <span className="font-mono text-xs tabular-nums text-muted-foreground">{pct}%</span>
      </div>
    )
  }

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      <div className="flex items-baseline justify-between">
        <span className="text-sm text-muted-foreground">Evidence coverage</span>
        <span className="font-mono text-lg font-semibold tabular-nums text-verified">{pct}%</span>
      </div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted/50">
        <div className="h-full bg-verified" style={{ width: `${pct}%` }} />
      </div>
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-1.5 text-verified">
          <ShieldCheck className="size-4" aria-hidden="true" />
          <span className="font-mono font-semibold tabular-nums">{backed}</span>
          <span className="text-muted-foreground">backed</span>
        </span>
        <span className="flex items-center gap-1.5 text-muted-foreground">
          <ShieldQuestion className="size-4" aria-hidden="true" />
          <span className="font-mono font-semibold tabular-nums">{missing}</span>
          <span>unverified</span>
        </span>
      </div>
    </div>
  )
}
