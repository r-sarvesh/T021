import { AppGuard } from '@/components/shell/app-guard'
import { SidebarNav } from '@/components/shell/sidebar-nav'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AppGuard>
      <div className="flex min-h-svh bg-background">
        {/* Persistent sidebar (desktop) */}
        <aside className="sticky top-0 hidden h-svh w-64 shrink-0 border-r border-sidebar-border md:block">
          <SidebarNav />
        </aside>
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </AppGuard>
  )
}
