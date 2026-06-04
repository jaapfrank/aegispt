import type { Engagement, Run, Task } from '../api/types';
import type { AegisSliceCreator, AegisStore } from './types';

type EngagementRunSlice = Pick<
  AegisStore,
  | 'engagements'
  | 'selectedEngagementId'
  | 'selectedEngagement'
  | 'runs'
  | 'selectedRunId'
  | 'selectedRun'
  | 'tasks'
  | 'setEngagements'
  | 'selectEngagement'
  | 'setRuns'
  | 'selectRun'
  | 'setSelectedRun'
  | 'setTasks'
  | 'resetRunScopedData'
>;

export const createEngagementRunSlice: AegisSliceCreator<EngagementRunSlice> = (set, get) => ({
  engagements: [],
  selectedEngagementId: null,
  selectedEngagement: null,
  runs: [],
  selectedRunId: null,
  selectedRun: null,
  tasks: [],
  setEngagements: (engagements: Engagement[]) => {
    const currentId = get().selectedEngagementId;
    const selectedEngagement =
      engagements.find((engagement) => engagement.id === currentId) ?? engagements[0] ?? null;
    set(
      {
        engagements,
        selectedEngagementId: selectedEngagement?.id ?? null,
        selectedEngagement,
      },
      false,
      'engagements/set',
    );
  },
  selectEngagement: (engagementId) => {
    const selectedEngagement =
      get().engagements.find((engagement) => engagement.id === engagementId) ?? null;
    set(
      {
        selectedEngagementId: selectedEngagement?.id ?? null,
        selectedEngagement,
        runs: [],
        selectedRunId: null,
        selectedRun: null,
        tasks: [],
        findings: [],
        selectedFindingId: null,
        inventory: null,
        aiInsights: null,
        proposals: [],
      },
      false,
      'engagements/select',
    );
  },
  setRuns: (runs: Run[]) => {
    const currentId = get().selectedRunId;
    const currentRun = get().selectedRun;
    const selectedRun =
      runs.find((run) => run.id === currentId) ??
      fallbackRunForMissingSelection(runs, currentRun) ??
      runs[0] ??
      null;
    set(
      {
        runs,
        selectedRunId: selectedRun?.id ?? null,
        selectedRun,
      },
      false,
      'runs/set',
    );
  },
  selectRun: (runId) => {
    const selectedRun = get().runs.find((run) => run.id === runId) ?? null;
    set(
      {
        selectedRunId: selectedRun?.id ?? null,
        selectedRun,
        tasks: selectedRun?.tasks ?? [],
        findings: [],
        selectedFindingId: null,
        inventory: null,
        aiInsights: null,
        proposals: [],
      },
      false,
      'runs/select',
    );
  },
  setSelectedRun: (run: Run | null) => {
    set(
      {
        selectedRun: run,
        selectedRunId: run?.id ?? null,
        tasks: run?.tasks ?? get().tasks,
      },
      false,
      'runs/set-selected',
    );
  },
  setTasks: (tasks: Task[]) => set({ tasks }, false, 'tasks/set'),
  resetRunScopedData: () =>
    set(
      {
        selectedRunId: null,
        selectedRun: null,
        tasks: [],
        findings: [],
        selectedFindingId: null,
        inventory: null,
        aiInsights: null,
        proposals: [],
      },
      false,
      'run-scoped/reset',
    ),
});

function assessmentChainId(run: Run | null): string | null {
  const chainId = run?.assessment_chain?.id;
  return typeof chainId === 'string' && chainId.trim() ? chainId : null;
}

function fallbackRunForMissingSelection(runs: Run[], currentRun: Run | null): Run | null {
  const chainId = assessmentChainId(currentRun);
  if (!chainId) return null;
  return (
    runs
      .filter((run) => assessmentChainId(run) === chainId)
      .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0] ?? null
  );
}
