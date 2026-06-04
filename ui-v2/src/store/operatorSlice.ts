import type { SettingsEnvelope } from '../api/types';
import { persistActorName, readStoredActorName } from './actorPersistence';
import type { AegisSliceCreator, AegisStore } from './types';

type OperatorSlice = Pick<AegisStore, 'actor' | 'settings' | 'setActor' | 'setSettings'>;

const emptySettings: SettingsEnvelope = {
  settings: null,
  readiness: null,
  chatgpt_connected: false,
  tool_readiness: {},
};

export const createOperatorSlice: AegisSliceCreator<OperatorSlice> = (set, get) => ({
  actor: {
    name: readStoredActorName(),
    role: 'admin',
  },
  settings: emptySettings,
  setActor: (actor) => {
    const nextActor = {
      ...get().actor,
      ...actor,
    };
    if (actor.name !== undefined) {
      persistActorName(nextActor.name);
    }
    set({ actor: nextActor }, false, 'actor/set');
  },
  setSettings: (settings: SettingsEnvelope) => set({ settings }, false, 'settings/set'),
});
