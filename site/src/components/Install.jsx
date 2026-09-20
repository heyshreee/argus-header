import CopyButton from './CopyButton';

/*
 * Section 08 — INSTALL
 * Full-width dark band with one very large monospace command.
 */

const INSTALL_CMD = 'pip install argus-header';

export default function Install() {
  return (
    <section className="section install" id="install">
      <div className="install-inner">
        <p className="tech-label" data-reveal>
          08 / INSTALL
        </p>
        <div className="install__cmd" data-reveal data-delay="1">
          <code className="install__cmd-code">{INSTALL_CMD}</code>
          <CopyButton text={INSTALL_CMD} label="COPY" copiedLabel="COPIED" />
        </div>
        <div className="install__meta-row" data-reveal data-delay="2">
          <ul className="install__meta">
            <li>Python</li>
            <li>CLI</li>
            <li>Open Source</li>
            <li>MIT</li>
          </ul>
        </div>
      </div>
    </section>
  );
}