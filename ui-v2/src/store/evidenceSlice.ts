import type { Finding, InventorySnapshot, RunAiInsights } from '../api/types';
import type { AegisSliceCreator, AegisStore } from './types';

type EvidenceSlice = Pick<
  AegisStore,
  | 'findings'
  | 'selectedFindingId'
  | 'inventory'
  | 'aiInsights'
  | 'proposals'
  | 'setFindings'
  | 'selectFinding'
  | 'setInventory'
  | 'setAiInsights'
>;

export const createEvidenceSlice: AegisSliceCreator<EvidenceSlice> = (set, get) => ({
  findings: [],
  selectedFindingId: null,
  inventory: null,
  aiInsights: null,
  proposals: [],
  setFindings: (findings: Finding[]) => {
    const currentId = get().selectedFindingId;
    const selectedFindingId = findings.some((finding) => finding.id === currentId) ? currentId : findings[0]?.id ?? null;
    set({ findings, selectedFindingId }, false, 'findings/set');
  },
  selectFinding: (findingId) => set({ selectedFindingId: findingId }, false, 'findings/select'),
  setInventory: (inventory: InventorySnapshot | null) => set({ inventory }, false, 'inventory/set'),
  setAiInsights: (aiInsights: RunAiInsights | null) =>
    set(
      {
        aiInsights,
        proposals: aiInsights?.proposals ?? [],
      },
      false,
      'ai-insights/set',
    ),
});
