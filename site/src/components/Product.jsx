import Scanner from './Scanner';

/*
 * Section 01 — THE TOOL
 * Split layout: typography left, the product console right (static final state).
 */
export default function Product() {
  return (
    <section className="section section--relative" id="product">
      <div className="grid-backdrop" aria-hidden="true"></div>
      <div className="section__inner">
        <div className="split">
          <div>
            <p className="tech-label section__label" data-reveal>
              01 / THE TOOL
            </p>
            <h2 data-reveal data-delay="1">
              HTTP security,
              <br />
              without the noise.
            </h2>
            <p className="section__lead" data-reveal data-delay="2">
              Argus focuses on the HTTP layer and surfaces the security signals
              that actually matter — no asset inventory, no agents, no noise.
            </p>
          </div>

          <div data-reveal data-delay="2">
            <Scanner staticMode />
          </div>
        </div>
      </div>
    </section>
  );
}