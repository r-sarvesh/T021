import { BenchmarkView } from '@/components/benchmark/benchmark-view'
import { PageShell } from '@/components/shell/page-shell'

export default function BenchmarkPage() {
  return (
    <PageShell title="Benchmark — Hallucination Exhibit">
      <BenchmarkView />
    </PageShell>
  )
}
