/*
 * Section 03 — ANALYSIS
 * A browser-style dashboard that ties a raw response to its findings.
 */

const RAW_LINES = [
  { text: 'HTTP/1.1 200 OK', frame: 'b' },
  { text: 'Content-Type: application/json', frame: 'b' },
  { text: 'Server: nginx', frame: 'b', leak: true, ref: '#03' },
  { text: 'Access-Control-Allow-Origin: *', frame: 'b', wild: true, ref: '#02' },
  { text: 'Content-Security-Policy: <absent>', frame: 'm', ref: '#01' },
];

const FINDINGS = [
  { idx: '01', title: 'Missing CSP', meta: 'SECURITY HEADERS', sev: 'HIGH', cls: 'finding--high' },
  { idx: '02', title: 'Wildcard CORS', meta: 'CORS', sev: 'MEDIUM', cls: 'finding--med' },
  { idx: '03', title: 'Server information exposed', meta: 'INFO LEAKAGE', sev: 'LOW', cls: 'finding--low' },
];

export default function Analysis() {
  return (
    <section className="section section--relative" id="analysis">
      <div className="grid-backdrop" aria-hidden="true"></div>
      <div className="section__inner">
        <div className="section__head">
          <p className="tech-label section__label" data-reveal>
            03 / ANALYSIS
          </p>
          <h2 data-reveal data-delay="1">
            From raw response
            <br />
            to useful findings.
          </h2>
        </div>

        <div className="browser" data-reveal data-delay="2">
          <div className="browser__bar">
            <span className="browser__dots" aria-hidden="true">
              <i></i>
              <i></i>
              <i></i>
            </span>
            <span className="browser__url">https://example.com</span>
            <span className="panel__grow"></span>
          </div>

          <div className="browser__grid">
            <div className="browser__pane browser__raw">
              <div className="browser__pane-head">
                <span>HTTP RESPONSE</span>
                <span aria-hidden="true">—</span>
              </div>
              <div className="browser__raw-body">
                {RAW_LINES.map((line, i) => {
                  let cls = 'line';
                  if (line.leak) cls += ' hl-leak';
                  if (line.wild) cls += ' hl-wild';
                  if (line.frame === 'm') cls += ' hl-miss';
                  return (
                    <div className={cls} key={i}>
                      {line.frame === 'b' ? <b>{line.text}</b> : <span>{line.text}</span>}
                      {line.ref && <span aria-hidden="true">{line.ref}</span>}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="browser__pane browser__findings">
              <div className="browser__pane-head">
                <span>ARGUS FINDINGS</span>
                <span>03</span>
              </div>
              <div className="browser__findings-body">
                {FINDINGS.map((f) => (
                  <div className={'finding ' + f.cls} key={f.idx}>
                    <span className="finding__idx">{f.idx}</span>
                    <div className="finding__body">
                      <p className="finding__title">{f.title}</p>
                      <p className="finding__meta">
                        {f.meta} · <span className="sev">{f.sev}</span>
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}