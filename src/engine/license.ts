import signed from '../data/license.json';

/**
 * License signed with ECDSA P-256 / SHA-256. Only the public key ships with the app;
 * the private key was discarded after signing, so the license cannot be altered without detection.
 */
export const LICENSE = signed.license;
export const LICENSE_SIGNATURE = signed.signature;
export const LICENSE_KEY = signed.publicKey;

export interface LicenseCheck {
  signature: 'valid' | 'invalid' | 'unavailable';
  valid: boolean;
  daysRemaining: number;
  expired: boolean;
}

const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function verifyLicense(license: unknown = LICENSE, signature = LICENSE_SIGNATURE, now = new Date()): Promise<LicenseCheck> {
  const daysRemaining = Math.max(0, Math.ceil((Date.parse(LICENSE.expiresAt) - now.getTime()) / 86400_000));
  const expired = daysRemaining <= 0;
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return { signature: 'unavailable', valid: !expired, daysRemaining, expired };
  try {
    const key = await subtle.importKey('jwk', { ...LICENSE_KEY, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64(signature), new TextEncoder().encode(JSON.stringify(license)));
    return { signature: ok ? 'valid' : 'invalid', valid: ok && !expired, daysRemaining, expired };
  } catch {
    return { signature: 'invalid', valid: false, daysRemaining, expired };
  }
}

/** Synchronous expiry check (signature is verified asynchronously by verifyLicense). */
export function licenseStatus(now = new Date()) {
  const daysRemaining = Math.max(0, Math.ceil((Date.parse(LICENSE.expiresAt) - now.getTime()) / 86400_000));
  return { valid: daysRemaining > 0, daysRemaining };
}
