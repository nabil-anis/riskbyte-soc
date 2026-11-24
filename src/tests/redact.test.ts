import { describe, it, expect } from 'vitest';
import { redact, unredact } from '../engine/redact';

describe('redaction', () => {
  it('tokenizes IPs, users, hosts, orgs and round-trips', () => {
    const src = 'Meezan Bank user customer.tariq on ibanking-web-02 logged in from 203.0.113.88 then again from 203.0.113.88; customer.tariq clicked meezan-fake-login.com';
    const r = redact(src, { users: ['customer.tariq'], hosts: ['ibanking-web-02'], orgs: ['Meezan Bank'] });
    expect(r.text).not.toContain('customer.tariq');
    expect(r.text).not.toContain('203.0.113.88');
    expect(r.text).not.toContain('ibanking-web-02');
    expect(r.text).not.toContain('Meezan Bank');
    expect(r.text).toContain('[REDACTED_IP_1]');
    expect(r.text).toContain('[REDACTED_USER_1]');
    expect(r.text).toContain('[REDACTED_HOST_1]');
    expect(r.text).toContain('meezan-fake-login.com'); // indicators are evidence, kept
    expect(r.counts).toEqual({ IP: 1, USER: 1, HOST: 1, ORG: 1 });
    expect(unredact(r.text, r.map)).toBe(src);
  });
  it('distinct values get distinct stable tokens', () => {
    const r = redact('a 1.1.1.1 b 2.2.2.2 c 1.1.1.1', {});
    expect(r.text).toBe('a [REDACTED_IP_1] b [REDACTED_IP_2] c [REDACTED_IP_1]');
  });
});
