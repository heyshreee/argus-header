/*
 * Section 06 — UNDER THE HOOD
 * Typographic engineering spec — no icons, just words and borders.
 */

const SPECS = [
  {
    term: 'REQUEST METHODS',
    vals: ['GET', 'HEAD'],
  },
  {
    term: 'NETWORK',
    vals: ['TIMEOUT', 'REDIRECTS', 'RETRY'],
  },
  {
    term: 'ANALYSIS',
    vals: ['SECURITY HEADERS', 'CORS', 'CACHE CONTROL', 'INFORMATION LEAKAGE'],
  },
  {
    term: 'OUTPUT',
    vals: ['RICH CLI', 'JSON REPORT'],
  },
];

export default function Engine() {
  return (
    <section className="section" id="engine">
      <div className="section__inner">
        <div className="section__head">
          <p className="tech-label section__label" data-reveal>
            06 / UNDER THE HOOD
          </p>
          <h2 data-reveal data-delay="1">
            Focused engineering.
            <br />
            Nothing unnecessary.
          </h2>
        </div>

        <div className="spec-list" data-reveal data-delay="2">
          {SPECS.map((spec) => (
            <div className="spec-row" key={spec.term}>
              <span className="spec-row__term">{spec.term}</span>
              <div className="spec-row__vals">
                {spec.vals.map((val) => (
                  <span key={val}>{val}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}