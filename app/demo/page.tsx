import { DemoView } from '@/components/demo/demo-view'
import { PageShell } from '@/components/shell/page-shell'

export default function DemoPage() {
  return (
    <PageShell title="Demo — Grounded Findings">
      <DemoView />
    </PageShell>
  )
}
