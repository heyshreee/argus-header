/*
 * Section 02 — SECURITY CHECKS
 * A full-width editorial list of the rule families Argus applies.
 */

const CHECKS = [
  {
    num: '01',
    title: 'Security Headers',
    desc: 'Detect missing or weak HTTP security headers.',
    tags: ['CSP', 'HSTS', 'X-Frame-Options', 'X-Content-Type-Options'],
  },
  {
    num: '02',
    title: 'CORS',
    desc: 'Identify potentially dangerous cross-origin configurations.',
    tags: ['Wildcard origin', 'Allow-Origin', 'Cross-origin behavior'],
  },
  {
    num: '03',
    title: 'Information Leakage',
    desc: 'Identify unnecessary infrastructure details exposed through HTTP responses.',
    tags: ['Server', 'Powered-By', 'Version information'],
  },
  {
    num: '04',
    title: 'Cache Control',
    desc: 'Inspect HTTP caching directives for potential security concerns.',
    tags: ['Cache-Control', 'Expires', 'Pragma'],
  },
];

export default function Checks() {
  return (
    <section className="section" id="checks">
      <div className="section__inner">
        <div className="section__head">
          <p className="tech-label section__label" data-reveal>
            02 / SECURITY CHECKS
          </p>
          <h2 data-reveal data-delay="1">
            One response.
            <br />
            Multiple security signals.
          </h2>
          <p className="section__lead" data-reveal data-delay="2">
            Every scan runs the same focused rule families against the headers
            your target sends back.
          </p>
        </div>

        <div className="checkWrap">
          {CHECKS.map((check) => (
            <article className="check-row" key={check.num}>
              <span className="check-row__num">{check.num}</span>
              <div>
                <h3 className="check-row__title">{check.title}</h3>
                <p className="check-row__desc">{check.desc}</p>
                <ul className="check-row__tags">
                  {check.tags.map((tag) => (
                    <li key={tag}>{tag}</li>
                  ))}
                </ul>
              </div>
              <span className="check-row__arrow" aria-hidden="true">
                →
              </span>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}