'use client'

import { useEffect } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { Radar } from 'lucide-react'
import { useAuth } from '@/lib/auth/auth-provider'
import { canAccess } from '@/lib/nav'
import { AccessDenied } from '@/components/shell/access-denied'

/**
 * Gates the authenticated app. Redirects unauthenticated users to /login and
 * renders an access-denied screen for routes the user's role cannot reach.
 * This mirrors backend authorization defensively — the backend is still the
 * source of truth and enforces access on every request.
 */
export function AppGuard({ children }: { children: React.ReactNode }) {
  const { user, status } = useAuth()
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    if (status === 'unauthenticated') router.replace('/login')
  }, [status, router])

  if (status !== 'authenticated' || !user) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <Radar className="size-6 animate-pulse text-primary" aria-hidden="true" />
          <p className="text-sm">Verifying session…</p>
        </div>
      </div>
    )
  }

  if (!canAccess(pathname, user.role)) {
    return <AccessDenied />
  }

  return <>{children}</>
}
