import type { ClientId, Org } from '../engine/types';

const T0 = '2026-11-01T00:00:00.000Z';

export const DEFAULT_ORGS: Org[] = [
  { id: 'meezan', name: 'Meezan Bank', sector: 'Banking', description: 'Retail and corporate banking: mobile and internet banking, SMS gateway, ATMs, Raast settlement.', createdAt: T0, builtIn: true },
  { id: 'shu', name: 'Salim Habib University', sector: 'Higher Education', description: 'Admissions portal, student LMS, campus Active Directory, computer labs.', createdAt: T0, builtIn: true },
  { id: 'contour', name: 'Contour Software', sector: 'Software', description: 'Developer workstations, CI/CD, source repositories, corporate VPN.', createdAt: T0, builtIn: true },
];

/** Live organization registry. The engine keeps it in sync with stored data. */
let registry: Org[] = DEFAULT_ORGS;

export const getOrgs = () => registry;
export function setOrgs(orgs: Org[]) {
  registry = orgs.length ? orgs : DEFAULT_ORGS;
}

export function clientById(id: ClientId): Org {
  return registry.find((o) => o.id === id) ?? { id, name: id, sector: 'Unknown', createdAt: T0 };
}
export const clientName = (id: ClientId | 'system') => (id === 'system' ? 'Platform' : clientById(id).name);

export function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || 'org';
}
