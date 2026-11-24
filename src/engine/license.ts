/** Simulated license. The signature is a demonstration value. */
const issued = new Date('2026-11-01T00:00:00Z');
const expires = new Date(issued.getTime() + 365 * 86400_000);

export const LICENSE = {
  licensee: 'Riskbyte Classroom Edition',
  tier: 'Enterprise (Development)',
  hostQuota: 25,
  issuedAt: issued.toISOString(),
  expiresAt: expires.toISOString(),
  signature: 'RSA-2048 signed (demonstration license)',
  simulated: true,
};

export function licenseStatus(now = new Date()) {
  const daysRemaining = Math.max(0, Math.ceil((expires.getTime() - now.getTime()) / 86400_000));
  return { valid: daysRemaining > 0 && LICENSE.signature.length > 0, daysRemaining };
}
