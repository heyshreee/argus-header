/*
 * Section 05 — WORKFLOW
 * Three-step flow. Arrows point across on wide screens, down when stacked.
 */

const STEPS = [
  {
    num: '01',
    title: 'Target',
    desc: 'Provide a URL.',
  },
  {
    num: '02',
    title: 'Analyze',
    desc: 'Argus inspects the HTTP response.',
  },
  {
    num: '03',
    title: 'Report',
    desc: 'Review findings directly in the terminal or export them as JSON.',
  },
];

export default function Workflow() {
  return (
    <section className="section" id="workflow">
      <div className="section__inner">
        <div className="section__head">
          <p className="tech-label section__label" data-reveal>
            05 / WORKFLOW
          </p>
          <h2 data-reveal data-delay="1">
            Simple enough
            <br />
            to run anywhere.
          </h2>
        </div>

        <div className="flow" data-reveal data-delay="2">
          {STEPS.map((step) => (
            <div className="flow__step" key={step.num}>
              <span className="flow__step-num">{step.num}</span>
              <h3 className="flow__step-title">{step.title}</h3>
              <p className="flow__step-desc">{step.desc}</p>
              <span className="flow__step-arrow flow__step-arrow--h" aria-hidden="true">
                →
              </span>
              <span className="flow__step-arrow flow__step-arrow--v" aria-hidden="true">
                ↓
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}