import { useMemo, useState } from 'react';
import { Activity, Play } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cancelRun } from '../../api/client';
import { useAegisStore } from '../../store';
import { useI18n } from '../../i18n';
import CinemaMode from '../CinemaMode';
import MissionControlV3 from './MissionControlV3';

const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled', 'canceled', 'completed_with_errors']);

export default function MissionControl() {
  const { t } = useI18n();
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const tasks = useAegisStore((state) => state.tasks);
  const findings = useAegisStore((state) => state.findings);
  const aiInsights = useAegisStore((state) => state.aiInsights);
  const loading = useAegisStore((state) => state.loading);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const setError = useAegisStore((state) => state.setError);
  const [busy, setBusy] = useState(false);
  const [cinemaOpen, setCinemaOpen] = useState(false);
  const proposals = useMemo(() => aiInsights?.proposals ?? [], [aiInsights?.proposals]);

  async function handleCancel() {
    if (!selectedRun) return;
    setBusy(true);
    setError(null);
    try {
      setSelectedRun(await cancelRun(selectedRun.id));
    } catch (error) {
      setError(error instanceof Error ? error.message : t('shell.apiFailed'));
    } finally {
      setBusy(false);
    }
  }

  if (!selectedRun) {
    return (
      <section className="max-w-4xl">
        <div className="glass-panel rounded-lg p-6">
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-cyan/30 bg-cyan/10 text-cyan">
              <Activity size={18} />
            </div>
            <div className="min-w-0">
              <h1 className="text-2xl font-semibold">{t('nav.missionControl')}</h1>
              <p className="mt-2 max-w-2xl text-[1rem] leading-6 text-muted">
                {loading.runs ? t('shell.loadingEngagements') : t('shell.noEngagement')}
              </p>
              <Link
                to="/intake"
                className="mt-5 inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
              >
                <Play size={15} />
                {t('intake.title')}
              </Link>
            </div>
          </div>
        </div>
      </section>
    );
  }

  const canKill = !busy && !TERMINAL_STATUSES.has((selectedRun.status || '').toLowerCase());

  return (
    <section className="flex h-full min-h-0 flex-col">
      <MissionControlV3
        run={selectedRun}
        tasks={tasks}
        findings={findings}
        proposals={proposals}
        onKill={() => void handleCancel()}
        onCinema={() => setCinemaOpen(true)}
        canKill={canKill}
        cinemaDisabled={busy}
      />
      {cinemaOpen && <CinemaMode onClose={() => setCinemaOpen(false)} />}
    </section>
  );
}
