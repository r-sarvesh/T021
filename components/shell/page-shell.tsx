import { Topbar, type Crumb } from '@/components/shell/topbar'

/**
 * Standard page frame used by every authenticated route: sticky top bar with
 * title/breadcrumb + a constrained, scrollable content column.
 */
export function PageShell({
  title,
  crumbs,
  children,
}: {
  title: string
  crumbs?: Crumb[]
  children: React.ReactNode
}) {
  return (
    <div className="flex min-h-svh flex-col">
      <Topbar title={title} crumbs={crumbs} />
      <main className="flex-1 px-4 py-6 md:px-6 md:py-8">
        <div className="mx-auto w-full max-w-[1400px]">{children}</div>
      </main>
    </div>
  )
}
