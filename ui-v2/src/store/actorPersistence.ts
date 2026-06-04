export const ACTOR_STORAGE_KEY = 'aegispt-actor';
export const V2_ACTOR_STORAGE_KEY = 'aegispt-v2-actor-name';

export function readStoredActorName(): string {
  if (typeof window === 'undefined') return 'operator-ui';
  const sharedActor = window.localStorage.getItem(ACTOR_STORAGE_KEY);
  const v2Actor = window.localStorage.getItem(V2_ACTOR_STORAGE_KEY);
  return (sharedActor || v2Actor || 'operator-ui').trim() || 'operator-ui';
}

export function persistActorName(actorName: string) {
  if (typeof window === 'undefined') return;
  const normalized = actorName.trim() || 'operator-ui';
  window.localStorage.setItem(ACTOR_STORAGE_KEY, normalized);
  window.localStorage.setItem(V2_ACTOR_STORAGE_KEY, normalized);
}
