import { PageShell } from '@/components/shell/page-shell'
import { DashboardView } from '@/components/dashboard/dashboard-view'

export default function DashboardPage() {
  return (
    <PageShell title="Dashboard">
      <DashboardView />
    </PageShell>
  )
}
