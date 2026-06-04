import { useI18n } from '../../i18n';

export default function WorkspaceSkeleton() {
  const { t } = useI18n();
  return (
    <section className="flex h-full min-h-0 flex-col" aria-label={t('shell.loadingWorkspace')}>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-[18rem] flex-1">
          <div className="skeleton-glow mb-3 h-4 w-28 rounded-full" />
          <div className="skeleton-glow mb-3 h-8 w-64 max-w-full rounded-md" />
          <div className="skeleton-glow h-4 w-[30rem] max-w-full rounded-full" />
        </div>
        <div className="skeleton-glow h-10 w-28 rounded-md" />
      </div>

      <div className="mb-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }).map((_, index) => (
          <div key={`metric-skeleton-${index}`} className="neon-panel rounded-lg p-4">
            <div className="skeleton-glow mb-4 h-4 w-24 rounded-full" />
            <div className="skeleton-glow mb-3 h-8 w-16 rounded-md" />
            <div className="skeleton-glow h-3 w-32 rounded-full" />
          </div>
        ))}
      </div>

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-2">
        {Array.from({ length: 2 }).map((_, panelIndex) => (
          <div key={`panel-skeleton-${panelIndex}`} className="neon-panel rounded-lg p-5">
            <div className="skeleton-glow mb-5 h-5 w-40 rounded-md" />
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((__, rowIndex) => (
                <div key={`row-skeleton-${panelIndex}-${rowIndex}`} className="rounded-lg border border-border bg-bg/25 p-3">
                  <div className="skeleton-glow mb-3 h-4 w-3/4 rounded-full" />
                  <div className="skeleton-glow h-3 w-1/2 rounded-full" />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
