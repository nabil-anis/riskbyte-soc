export type TokenKind = 'IP' | 'USER' | 'HOST' | 'ORG';

export interface Redaction {
  text: string;
  map: Record<string, string>; // token -> original
  counts: Record<TokenKind, number>;
}

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Replaces IPs, usernames, hostnames and organisation names with stable tokens
 * ([REDACTED_IP_1], [REDACTED_USER_1], ...). The same value always maps to the same token.
 */
export function redact(input: string, entities: { users?: string[]; hosts?: string[]; orgs?: string[] }): Redaction {
  const map: Record<string, string> = {};
  const reverse = new Map<string, string>();
  const counts: Record<TokenKind, number> = { IP: 0, USER: 0, HOST: 0, ORG: 0 };
  const tokenFor = (kind: TokenKind, value: string) => {
    const key = `${kind}:${value.toLowerCase()}`;
    let tok = reverse.get(key);
    if (!tok) {
      counts[kind] += 1;
      tok = `[REDACTED_${kind}_${counts[kind]}]`;
      reverse.set(key, tok);
      map[tok] = value;
    }
    return tok;
  };

  let text = input.replace(IPV4, (ip) => tokenFor('IP', ip));
  const lists: [TokenKind, string[]][] = [
    ['ORG', entities.orgs ?? []],
    ['HOST', entities.hosts ?? []],
    ['USER', entities.users ?? []],
  ];
  // Longest values first so "customer.tariq" is replaced before a shorter overlapping value.
  const all = lists.flatMap(([k, vs]) => [...new Set(vs.filter(Boolean))].map((v) => [k, v] as [TokenKind, string]));
  all.sort((a, b) => b[1].length - a[1].length);
  for (const [kind, value] of all) {
    const re = new RegExp(`(?<![\\w.-])${esc(value)}(?![\\w-])`, 'gi');
    if (re.test(text)) {
      const tok = tokenFor(kind, value);
      text = text.replace(new RegExp(`(?<![\\w.-])${esc(value)}(?![\\w-])`, 'gi'), tok);
    }
  }
  return { text, map, counts };
}

export function unredact(text: string, map: Record<string, string>): string {
  return text.replace(/\[REDACTED_(IP|USER|HOST|ORG)_\d+\]/g, (tok) => map[tok] ?? tok);
}
