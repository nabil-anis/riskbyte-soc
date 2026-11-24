import type { Indicator } from '../engine/types';

export const INDICATORS: Indicator[] = [
  { value: '1.2.3.4', type: 'ip', category: 'scanner / botnet', confidence: 0.9, note: 'Credential-guessing scanner (simulation). 1.2.3.4 is a widely used placeholder address, not a real attacker.' },
  { value: '198.51.100.99', type: 'ip', category: 'C2 / foreign infrastructure', confidence: 0.93, note: 'Command-and-control and foreign login source' },
  { value: '198.51.100.44', type: 'ip', category: 'exfiltration staging', confidence: 0.92, note: 'Untrusted external upload target' },
  { value: '203.0.113.88', type: 'ip', category: 'phishing proxy', confidence: 0.91, note: 'Proxy used to harvest credentials' },
  { value: 'meezan-fake-login.com', type: 'domain', category: 'phishing', confidence: 0.95, note: 'Spoof of a bank login' },
  { value: 'shu-admissions-phish.com', type: 'domain', category: 'phishing', confidence: 0.95, note: 'Spoof of a registrar message' },
  { value: 'ransomware-c2.net', type: 'domain', category: 'ransomware C2', confidence: 0.97, note: 'Ransomware control server' },
];

export const FLAGGED_PHISHING_DOMAINS = INDICATORS.filter((i) => i.type === 'domain' && i.category === 'phishing').map((i) => i.value);
