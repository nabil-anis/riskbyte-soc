import type { Role } from '../engine/types';
export { MAX_FAILED, MIN_PASSWORD } from '../engine/accounts';

export const USERNAMES_DEFAULT: Record<Role, string> = { analyst: 'soc.analyst', admin: 'soc.admin', ingest: 'ingest.agent' };
