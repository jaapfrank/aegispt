import { api } from './transport';
import type {
  DeceptionAlertList,
  DeceptionTrap,
  DeceptionTrapCreateInput,
  DeceptionTrapList,
} from './types';

export async function getDeceptionTraps(): Promise<DeceptionTrapList> {
  return api<DeceptionTrapList>('/api/v1/deception/traps');
}

export async function createDeceptionTrap(data: DeceptionTrapCreateInput): Promise<DeceptionTrap> {
  return api<DeceptionTrap>('/api/v1/deception/traps', {
    method: 'POST',
    json: data,
  });
}

export async function getDeceptionAlerts(): Promise<DeceptionAlertList> {
  return api<DeceptionAlertList>('/api/v1/deception/alerts');
}
