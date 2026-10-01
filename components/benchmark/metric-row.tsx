import { cn } from '@/lib/utils'

export interface Ratio {
  num: number
  den: number
}

/** Percentage of a ratio; 0 when the denominator is 0 (never NaN). */
export function ratioPct(r: Ratio): number {
  if (!r.den) return 0
  return (r.num / r.den) * 100
}

/** "n/d (x%)" — or "n/a" when there is no denominator. */
export function ratioText(r: Ratio): string {
  if (!r.den) return 'n/a'
  return `${r.num}/${r.den} (${ratioPct(r).toFixed(1)}%)`
}

/** Same as ratioText but only the percentage, for the big stat numbers. */
export function ratioPctText(r: Ratio): string {
  if (!r.den) return 'n/a'
  return `${ratioPct(r).toFixed(1)}%`
}

function Bar({
  variant,
  ratio,
}: {
  variant: 'grounded' | 'ungrounded'
  ratio: Ratio
}) {
  const pct = ratioPct(ratio)
  const tone = variant === 'grounded' ? 'bg-good' : 'bg-bad'
  const label = variant === 'grounded' ? 'Grounded' : 'Ungrounded'
  const ariaValue = ratio.den ? `${pct.toFixed(1)}%` : 'n/a'
  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          'w-[74px] shrink-0 text-[10px] font-medium tracking-wide uppercase',
          variant === 'grounded' ? 'text-good' : 'text-bad',
        )}
      >
        {variant}
      </span>
      <div
        role="img"
        aria-label={`${label}: ${ratio.num} of ${ratio.den} (${ariaValue})`}
        className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-muted"
      >
        <div
          className={cn('h-full rounded-full transition-[width]', tone)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-[96px] shrink-0 text-right font-mono text-[11px] text-muted-foreground tabular-nums">
        {ratioText(ratio)}
      </span>
    </div>
  )
}

/**
 * One metric rendered as a label plus two thin bars — grounded (green) and
 * ungrounded (red) — with the raw "n/d (x%)" value in monospace on the right.
 */
export function MetricRow({
  label,
  grounded,
  ungrounded,
}: {
  label: string
  grounded: Ratio
  ungrounded: Ratio
}) {
  return (
    <div className="flex flex-col gap-2 border-b border-border/60 py-3 first:pt-0 last:border-0 last:pb-0">
      <div className="text-xs font-medium text-foreground">{label}</div>
      <Bar variant="grounded" ratio={grounded} />
      <Bar variant="ungrounded" ratio={ungrounded} />
    </div>
  )
}
