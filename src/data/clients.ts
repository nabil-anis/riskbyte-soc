import type { ClientId } from '../engine/types';

export interface ClientProfile {
  id: ClientId;
  name: string;
  short: string;
  sector: string;
  label: string;
  what: string;
  platforms: string[];
  risks: string[];
}

export const CLIENTS: ClientProfile[] = [
  {
    id: 'meezan',
    name: 'Meezan Bank',
    short: 'Meezan',
    sector: 'Islamic Commercial Bank',
    label: 'Meezan Bank (Islamic Commercial Bank)',
    what: 'Islamic commercial bank in Pakistan (est. 2002) offering retail and corporate Shariah-compliant banking.',
    platforms: ['Mobile Banking App', 'Digital Account Opening', 'Internet Banking', 'WhatsApp Banking', 'SMS Gateway', 'ATMs', 'Raast Instant Settlement'],
    risks: ['Fake SMS / WhatsApp phishing', 'Customer account takeover', 'Raast payment fraud', 'Insider misuse', 'Web banking brute force'],
  },
  {
    id: 'shu',
    name: 'Salim Habib University',
    short: 'SHU',
    sector: 'Higher Education',
    label: 'Salim Habib University (Higher Education)',
    what: 'Higher education institution in Korangi Creek, Karachi, offering undergraduate and postgraduate education and research.',
    platforms: ['Online Admissions Portal (shu.edu.pk)', 'Student LMS', 'Campus Active Directory', 'Computer Labs', 'Faculty Research Systems'],
    risks: ['Phishing of student and faculty accounts', 'Admissions portal brute force', 'Ransomware on lab computers', 'Applicant document theft'],
  },
  {
    id: 'contour',
    name: 'Contour Software',
    short: 'Contour',
    sector: 'Constellation Software',
    label: 'Contour Software (Constellation Software)',
    what: 'Enterprise software company (Constellation Software subsidiary) with offices in Karachi, Lahore and Islamabad, building enterprise products and services.',
    platforms: ['Developer Workstations', 'CI/CD (Jenkins, GitLab Runners)', 'Source Code Repositories', 'Corporate VPN Gateways', 'Global Payroll Engines'],
    risks: ['Stolen developer credentials', 'Source code theft', 'Malware on laptops', 'Software supply-chain attacks', 'VPN abuse'],
  },
];

export const clientById = (id: ClientId) => CLIENTS.find((c) => c.id === id)!;
export const clientName = (id: ClientId | 'system') => (id === 'system' ? 'System' : clientById(id).name);
