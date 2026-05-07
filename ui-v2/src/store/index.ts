import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import type {
  AgentProposal,
  Engagement,
  Finding,
  InventorySnapshot,
  Run,
  RunAiInsights,
  SettingsEnvelope,
  Task,
  UUID,
} from '../api/types';

export interface ActorState {
  name: string;
  role: string;
}

export interface RunStreamState {
  status: 'connected' | 'disconnected';
  runId: UUID | null;
}

interface AegisStore {
  engagements: Engagement[];
  selectedEngagementId: UUID | null;
  selectedEngagement: Engagement | null;
  runs: Run[];
  selectedRunId: UUID | null;
  selectedRun: Run | null;
  tasks: Task[];
  findings: Finding[];
  selectedFindingId: UUID | null;
  inventory: InventorySnapshot | null;
  aiInsights: RunAiInsights | null;
  proposals: AgentProposal[];
  actor: ActorState;
  settings: SettingsEnvelope;
  runStream: RunStreamState;
  loading: Record<string, boolean>;
  error: string | null;
  setEngagements: (engagements: Engagement[]) => void;
  selectEngagement: (engagementId: UUID | null) => void;
  setRuns: (runs: Run[]) => void;
  selectRun: (runId: UUID | null) => void;
  setSelectedRun: (run: Run | null) => void;
  setTasks: (tasks: Task[]) => void;
  setFindings: (findings: Finding[]) => void;
  selectFinding: (findingId: UUID | null) => void;
  setInventory: (inventory: InventorySnapshot | null) => void;
  setAiInsights: (aiInsights: RunAiInsights | null) => void;
  setActor: (actor: Partial<ActorState>) => void;
  setSettings: (settings: SettingsEnvelope) => void;
  setRunStream: (runStream: Partial<RunStreamState>) => void;
  setLoading: (key: string, value: boolean) => void;
  setError: (error: string | null) => void;
  resetRunScopedData: () => void;
}

const emptySettings: SettingsEnvelope = {
  settings: null,
  readiness: null,
  chatgpt_connected: false,
  tool_readiness: {},
};

const useAegisStoreBase = create<AegisStore>()(
  devtools(
    (set, get) => ({
      engagements: [],
      selectedEngagementId: null,
      selectedEngagement: null,
      runs: [],
      selectedRunId: null,
      selectedRun: null,
      tasks: [],
      findings: [],
      selectedFindingId: null,
      inventory: null,
      aiInsights: null,
      proposals: [],
      actor: {
        name: 'operator-ui',
        role: 'admin',
      },
      settings: emptySettings,
      runStream: {
        status: 'disconnected',
        runId: null,
      },
      loading: {},
      error: null,
      setEngagements: (engagements) => {
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
      setRuns: (runs) => {
        const currentId = get().selectedRunId;
        const selectedRun = runs.find((run) => run.id === currentId) ?? runs[0] ?? null;
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
      setSelectedRun: (run) => {
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
      setTasks: (tasks) => set({ tasks }, false, 'tasks/set'),
      setFindings: (findings) => {
        const currentId = get().selectedFindingId;
        const selectedFindingId = findings.some((finding) => finding.id === currentId) ? currentId : findings[0]?.id ?? null;
        set({ findings, selectedFindingId }, false, 'findings/set');
      },
      selectFinding: (findingId) => set({ selectedFindingId: findingId }, false, 'findings/select'),
      setInventory: (inventory) => set({ inventory }, false, 'inventory/set'),
      setAiInsights: (aiInsights) =>
        set(
          {
            aiInsights,
            proposals: aiInsights?.proposals ?? [],
          },
          false,
          'ai-insights/set',
        ),
      setActor: (actor) =>
        set(
          {
            actor: {
              ...get().actor,
              ...actor,
            },
          },
          false,
          'actor/set',
        ),
      setSettings: (settings) => set({ settings }, false, 'settings/set'),
      setRunStream: (runStream) =>
        set(
          {
            runStream: {
              ...get().runStream,
              ...runStream,
            },
          },
          false,
          'run-stream/set',
        ),
      setLoading: (key, value) =>
        set(
          {
            loading: {
              ...get().loading,
              [key]: value,
            },
          },
          false,
          'loading/set',
        ),
      setError: (error) => set({ error }, false, 'error/set'),
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
    }),
    {
      enabled: import.meta.env.DEV,
      name: 'aegispt-v2-store',
    },
  ),
);

export const useAegisStore = useAegisStoreBase;
