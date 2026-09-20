/*
 * Section 09 — FINAL CTA
 * Minimal full-screen statement. No illustration, no decoration.
 */
export default function Cta() {
  return (
    <section className="cta" id="cta">
      <div className="cta__inner">
        <p className="tech-label" data-reveal>
          GET STARTED
        </p>
        <h2 className="cta__title" data-reveal data-delay="1">
          Start with
          <br />
          the response.
        </h2>
        <p className="cta__desc" data-reveal data-delay="2">
          Install Argus and inspect your next target.
        </p>
        <div className="cta__actions" data-reveal data-delay="3">
          <a className="btn btn--primary" href="#install">
            GET STARTED <span className="btn__arrow" aria-hidden="true">→</span>
          </a>
          <a
            className="btn btn--ghost"
            href="https://github.com/heyshreee/argus-header"
            target="_blank"
            rel="noopener"
          >
            VIEW GITHUB <span className="btn__arrow" aria-hidden="true">→</span>
          </a>
        </div>
      </div>
    </section>
  );
}