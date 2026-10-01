import { cn } from '@/lib/utils'

type Tone = 'good' | 'bad' | 'brand'

const toneText: Record<Tone, string> = {
  good: 'text-good',
  bad: 'text-bad',
  brand: 'text-brand',
}

/**
 * Headline statistic: one big computed number, an uppercase label and a
 * muted line of raw counts. Values are always passed in — never hardcoded.
 */
export function StatCard({
  value,
  label,
  raw,
  tone,
}: {
  value: string
  label: string
  raw: string
  tone: Tone
}) {
  return (
    <div className="rounded-2xl border border-border bg-card p-[22px]">
      <div
        className={cn(
          'text-[40px] leading-none font-semibold tracking-tight tabular-nums',
          toneText[tone],
        )}
      >
        {value}
      </div>
      <div className="mt-3 text-[11px] font-medium tracking-[0.08em] text-muted-foreground uppercase">
        {label}
      </div>
      <div className="mt-1 font-mono text-xs break-words text-muted-foreground">{raw}</div>
    </div>
  )
}
