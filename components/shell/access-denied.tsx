'use client'

import Link from 'next/link'
import { ShieldX } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function AccessDenied() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 px-6 text-center">
      <div className="flex size-14 items-center justify-center rounded-full bg-critical/15 text-critical">
        <ShieldX className="size-7" aria-hidden="true" />
      </div>
      <div className="flex flex-col gap-1.5">
        <h1 className="text-xl font-semibold tracking-tight">Access denied</h1>
        <p className="max-w-md text-pretty text-sm text-muted-foreground">
          You do not have permission to access this area. This section is restricted to
          administrators. If you believe this is an error, contact a platform administrator.
        </p>
      </div>
      <Button render={<Link href="/dashboard" />} variant="outline">
        Return to dashboard
      </Button>
    </div>
  )
}
