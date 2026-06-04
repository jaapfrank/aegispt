import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import { ACTOR_STORAGE_KEY, V2_ACTOR_STORAGE_KEY } from './actorPersistence';
import { createEngagementRunSlice } from './engagementRunSlice';
import { createEvidenceSlice } from './evidenceSlice';
import { createOperatorSlice } from './operatorSlice';
import { createRuntimeSlice } from './runtimeSlice';
import type { AegisStore, ActorState, RunStreamState } from './types';

const useAegisStoreBase = create<AegisStore>()(
  devtools(
    (...storeApi) => ({
      ...createEngagementRunSlice(...storeApi),
      ...createEvidenceSlice(...storeApi),
      ...createOperatorSlice(...storeApi),
      ...createRuntimeSlice(...storeApi),
    }),
    {
      enabled: import.meta.env.DEV,
      name: 'aegispt-v2-store',
    },
  ),
);

export const useAegisStore = useAegisStoreBase;
export { ACTOR_STORAGE_KEY, V2_ACTOR_STORAGE_KEY };
export type { ActorState, RunStreamState };
