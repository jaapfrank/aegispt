import type { AegisSliceCreator, AegisStore } from './types';

type RuntimeSlice = Pick<
  AegisStore,
  'runStream' | 'loading' | 'error' | 'setRunStream' | 'setLoading' | 'setError'
>;

export const createRuntimeSlice: AegisSliceCreator<RuntimeSlice> = (set, get) => ({
  runStream: {
    status: 'disconnected',
    runId: null,
  },
  loading: {},
  error: null,
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
});
