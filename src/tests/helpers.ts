import { Engine } from '../engine/engineState';
import type { ApiContext } from '../engine/api';

export function makeEngine() {
  const logs: string[] = [];
  const engine = new Engine({
    log: (l, t) => logs.push(`${l} ${t}`),
    triageConfig: () => ({ apiKey: '', model: 'gemini-2.5-flash' }),
    onChange: () => {},
  });
  const ctx: ApiContext = {
    engine,
    isEngineOn: () => true,
    provider: () => ({ provider: 'heuristic', model: 'riskbyte-heuristic-v1' }),
    log: (l, t) => logs.push(`${l} ${t}`),
  };
  return { engine, ctx, logs };
}
