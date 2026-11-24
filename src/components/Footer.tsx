import { CREDIT, DISCLAIMER } from '../data/copy';

export function Footer() {
  return (
    <footer className="footer">
      <strong>{CREDIT}</strong>
      <p>{DISCLAIMER}</p>
    </footer>
  );
}
