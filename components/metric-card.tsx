import { cn } from '@/lib/utils'
import { Card } from '@/components/ui/card'

export function MetricCard({
  label,
  value,
  icon: Icon,
  tone = 'default',
  hint,
}: {
  label: string
  value: string | number
  icon?: React.ComponentType<{ className?: string }>
  tone?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'verified' | 'primary'
  hint?: string
}) {
  const toneClass: Record<string, string> = {
    default: 'text-foreground',
    critical: 'text-critical',
    high: 'text-high',
    medium: 'text-medium',
    low: 'text-low',
    verified: 'text-verified',
    primary: 'text-primary',
  }
  const iconBg: Record<string, string> = {
    default: 'bg-muted/60 text-muted-foreground',
    critical: 'bg-critical/15 text-critical',
    high: 'bg-high/15 text-high',
    medium: 'bg-medium/15 text-medium',
    low: 'bg-low/15 text-low',
    verified: 'bg-verified/15 text-verified',
    primary: 'bg-primary/15 text-primary',
  }
  return (
    <Card className="flex flex-row items-center justify-between gap-3 p-4">
      <div className="min-w-0">
        <p className="truncate text-xs font-medium text-muted-foreground">{label}</p>
        <p className={cn('mt-1 font-mono text-2xl font-semibold tabular-nums', toneClass[tone])}>
          {value}
        </p>
        {hint && <p className="mt-0.5 truncate text-xs text-muted-foreground">{hint}</p>}
      </div>
      {Icon && (
        <div className={cn('flex size-9 shrink-0 items-center justify-center rounded-md', iconBg[tone])}>
          <Icon className="size-4.5" />
        </div>
      )}
    </Card>
  )
}
