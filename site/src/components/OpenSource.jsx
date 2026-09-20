/*
 * Section 07 — OPEN SOURCE
 * Honest contribution area: no invented metrics. The activity grid is
 * decorative; links lead to the real repository and package index.
 */

const GRID = Array.from({ length: 112 }, (_, i) => {
  const row = Math.floor(i / 16);
  const col = i % 16;
  const accent = (row * 7 + col * 13 + row * col * 3) % 11 === 0;
  return accent;
});

export default function OpenSource() {
  return (
    <section className="section section--relative os-backdrop" id="opensource">
      <div className="grid-backdrop" aria-hidden="true"></div>
      <div className="section__inner">
        <div className="split">
          <div>
            <p className="tech-label section__label" data-reveal>
              07 / OPEN SOURCE
            </p>
            <h2 data-reveal data-delay="1">
              Built in the open.
            </h2>
            <p className="section__lead" data-reveal data-delay="2">
              Argus is an open-source HTTP security analyzer designed for
              developers and security researchers. Read the source, open an
              issue, or send a pull request.
            </p>

            <div className="os-actions" data-reveal data-delay="3">
              <a
                className="btn btn--primary"
                href="https://github.com/heyshreee/argus-header"
                target="_blank"
                rel="noopener"
              >
                VIEW SOURCE <span className="btn__arrow" aria-hidden="true">→</span>
              </a>
              <a
                className="btn btn--ghost"
                href="https://pypi.org/project/argus-header/"
                target="_blank"
                rel="noopener"
              >
                VIEW ON PYPI <span className="btn__arrow" aria-hidden="true">→</span>
              </a>
            </div>
          </div>

          <div className="os-activity" data-reveal data-delay="2" aria-hidden="true">
            <div className="os-activity__head">
              <span className="os-activity__title">CONTRIBUTION ACTIVITY</span>
              <span className="os-activity__legend">LESS ····· MORE</span>
            </div>
            <div className="os-grid">
              {GRID.map((accent, i) => (
                <i key={i} className={accent ? 'is-accent' : ''}></i>
              ))}
            </div>
            <div className="os-activity__foot">
              <span>COMMITS</span>
              <span>RELEASES</span>
              <span>DOCS</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}