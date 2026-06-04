import type { ReactNode } from 'react';
import { Plus } from 'lucide-react';
import { Link, NavLink } from 'react-router-dom';
import type { TFunction } from '../../i18n';
import { navSections } from './navConfig';
import { cn } from './utils';

export function ShellNavigation({
  criticalBadge,
  findingsCount,
  runningRunCount,
  t,
}: {
  criticalBadge: boolean;
  findingsCount: number;
  runningRunCount: number;
  t: TFunction;
}) {
  return (
    <aside className="aegis-sidebar flex w-[180px] shrink-0 flex-col overflow-y-auto border-r border-border pt-4">
      <div className="px-3 mb-6">
        <Link
          className="flex w-full items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/5 py-2 text-[1rem] font-semibold text-cyan shadow-[0_0_1rem_rgba(94,207,255,0.08)] transition-all hover:border-cyan/50 hover:bg-cyan/10 hover:shadow-[0_0_1.25rem_rgba(94,207,255,0.18)]"
          to="/intake"
        >
          <Plus size={16} />
          {t('shell.newMission')}
        </Link>
      </div>

      <nav className="flex flex-col gap-6 px-3" aria-label={t('shell.primaryNavigation')}>
        {navSections.map((section) => (
          <div key={section.labelKey} className="flex flex-col gap-1">
            <span className="px-2 text-[0.77rem] font-bold uppercase tracking-wider text-muted mb-1">
              {t(section.labelKey)}
            </span>
            {section.items.map((item) => (
              <NavItem
                key={item.to}
                to={item.to}
                icon={<item.icon size={15} />}
                label={t(item.labelKey)}
                badge={item.badgeKey === 'findings' && findingsCount > 0 ? String(findingsCount) : undefined}
                criticalBadge={item.badgeKey === 'findings' && criticalBadge}
                showLivingPulse={Boolean(item.pulse && runningRunCount > 0)}
              />
            ))}
          </div>
        ))}
      </nav>
    </aside>
  );
}

function NavItem({
  icon,
  label,
  to,
  badge,
  criticalBadge,
  showLivingPulse,
}: {
  icon: ReactNode;
  label: string;
  to: string;
  badge?: string;
  criticalBadge?: boolean;
  showLivingPulse?: boolean;
}) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          'group relative flex w-full items-center justify-between rounded-md px-2 py-1.5 text-[1rem] font-medium transition-all duration-200',
          isActive
            ? 'bg-cyan/10 text-cyan shadow-[inset_0_0_0_1px_rgba(94,207,255,0.08),0_0_1rem_rgba(94,207,255,0.08)]'
            : 'text-muted hover:bg-surface hover:text-text hover:shadow-[0_0_1rem_rgba(94,207,255,0.07)]',
        )
      }
    >
      {({ isActive }) => (
        <>
          <div className="flex items-center gap-2">
            <span className={cn('transition-colors', isActive ? 'text-cyan' : 'text-muted group-hover:text-text')}>
              {icon}
            </span>
            {label}
          </div>
          <div className="flex items-center gap-2">
            {badge && (
              <span
                className={cn(
                  'living-badge-pop flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red/20 px-1 text-[0.77rem] font-bold text-red',
                  criticalBadge && 'living-critical-pulse',
                )}
              >
                {badge}
              </span>
            )}
            {showLivingPulse && isActive && (
              <div className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse shadow-[0_0_5px_rgba(94,207,255,0.8)]" />
            )}
          </div>
          {isActive && (
            <div className="absolute left-0 top-[10%] h-[80%] w-[3px] rounded-r bg-cyan shadow-[0_0_8px_rgba(94,207,255,0.8)]" />
          )}
        </>
      )}
    </NavLink>
  );
}
