import Scanner from './Scanner';

/*
 * Hero — reduced to typography plus the live Argus scan console. No
 * illustration, no decorative network artwork.
 */
export default function Hero() {
  return (
    <section className="hero" id="top">
      <div className="hero__inner">
        <div className="grid-backdrop" aria-hidden="true"></div>

        <p className="tech-label hero__label-row" data-reveal>
          <span className="hero__dot" aria-hidden="true"></span>
          Open source HTTP security tool
        </p>

        <h1 className="hero__title" data-reveal data-delay="1">
          See what your
          <br />
          <span className="c-muted">HTTP headers</span>
          <br />
          reveal.
        </h1>

        <p className="hero__desc" data-reveal data-delay="2">
          Argus inspects HTTP responses for security&nbsp;headers, CORS
          misconfigurations, information leakage, and cache-related issues.
        </p>

        <div className="hero__actions" data-reveal data-delay="3">
          <a className="btn btn--primary" href="#install">
            GET STARTED <span className="btn__arrow" aria-hidden="true">→</span>
          </a>
          <a
            className="btn btn--ghost"
            href="https://github.com/heyshreee/argus-header"
            target="_blank"
            rel="noopener"
          >
            VIEW ON GITHUB <span className="btn__arrow" aria-hidden="true">→</span>
          </a>
        </div>

        <ul className="hero__meta" data-reveal data-delay="4">
          <li>Python</li>
          <li>CLI</li>
          <li>v0.8.0</li>
          <li>MIT</li>
        </ul>

        <div className="hero__visual" data-reveal data-delay="3">
          <Scanner />
        </div>
      </div>
    </section>
  );
}