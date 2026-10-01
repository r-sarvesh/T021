import {
  BarChart3,
  Beaker,
  FileText,
  LayoutDashboard,
  ScrollText,
  Settings,
  Upload,
  Radar,
} from 'lucide-react'
import type { Role } from '@/lib/api/types'

export interface NavItem {
  label: string
  href: string
  icon: typeof LayoutDashboard
  /** Roles allowed to see this item. Omit for all authenticated users. */
  roles?: Role[]
}

export const navItems: NavItem[] = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { label: 'Scans', href: '/scans', icon: Radar },
  { label: 'Import Scan', href: '/import', icon: Upload },
  { label: 'Reports', href: '/reports', icon: FileText },
  { label: 'Demo', href: '/demo', icon: Beaker },
  { label: 'Benchmark', href: '/benchmark', icon: BarChart3 },
  { label: 'Audit Log', href: '/audit-log', icon: ScrollText, roles: ['admin'] },
  { label: 'Settings', href: '/settings', icon: Settings },
]

export function navItemsForRole(role: Role): NavItem[] {
  return navItems.filter((item) => !item.roles || item.roles.includes(role))
}

export function canAccess(href: string, role: Role): boolean {
  const item = navItems.find((n) => href.startsWith(n.href))
  if (!item) return true
  return !item.roles || item.roles.includes(role)
}
