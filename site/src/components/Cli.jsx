import Terminal from './Terminal';
import CopyButton from './CopyButton';

/*
 * Section 04 — COMMAND LINE
 * Split intro + live terminal, followed by the three core command rows.
 */

const COMMANDS = [
  {
    cmd: 'argus-header https://example.com',
    desc: 'BASIC SCAN',
  },
  {
    cmd: 'argus-header https://example.com --json report.json',
    desc: 'JSON REPORT',
  },
  {
    cmd: 'argus-header https://example.com --method HEAD',
    desc: 'HEAD REQUESTS',
  },
];

export default function Cli() {
  return (
    <section className="section" id="cli">
      <div className="section__inner">
        <div className="cliSplit">
          <div>
            <p className="tech-label section__label" data-reveal>
              04 / COMMAND LINE
            </p>
            <h2 data-reveal data-delay="1">
              Built for the terminal.
            </h2>
            <p className="section__lead" data-reveal data-delay="2">
              Argus fits directly into the security researcher's existing
              workflow — install once via pip, then point it at any target.
            </p>

            <ul className="hero__meta" data-reveal data-delay="3" style={{ marginTop: '48px' }}>
              <li>GET</li>
              <li>HEAD</li>
              <li>Retry</li>
              <li>Timeout</li>
            </ul>
          </div>

          <div>
            <Terminal />
          </div>
        </div>

        <div className="cmdList" data-reveal>
          <p className="cmdList__label" aria-hidden="true">
            COMMANDS
          </p>
          {COMMANDS.map((row) => (
            <div className="cmd-row" key={row.cmd}>
              <span className="cmd-row__prompt" aria-hidden="true">
                $
              </span>
              <code>{row.cmd}</code>
              <span className="cmd-row__desc">{row.desc}</span>
              <CopyButton text={row.cmd} label="COPY" />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}