import type { StateCreator } from 'zustand';
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

export interface AegisStore {
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

export type AegisSliceCreator<T> = StateCreator<AegisStore, [['zustand/devtools', never]], [], T>;
