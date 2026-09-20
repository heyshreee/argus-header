import { useEffect, useState } from 'react';
import { reduceMotion } from '../lib/config';

/*
 * Scanner — the Argus analysis console. In interactive mode it walks a
 * staged scan (CONNECTING → ANALYZING → CHECKING → GENERATING → COMPLETE).
 * In staticMode it renders the finished report immediately (used by the
 * Product section), which keeps one source of truth for the product UI.
 */

const PHASES = [
  { text: 'CONNECTING...', busy: true },
  { text: 'ANALYZING TARGET...', busy: true },
  { text: 'CHECKING HEADERS...', busy: true },
  { text: 'CHECKING CORS...', busy: true },
  { text: 'GENERATING REPORT...', busy: true },
  { text: 'ANALYSIS COMPLETE', busy: false },
];

const STEP_MS = 620;

const HEADER_ROWS = [
  { key: 'hsts', name: 'Strict-Transport-Security', tag: 'PASS', cls: 'is-pass', mark: '✓' },
  { key: 'xcto', name: 'X-Content-Type-Options', tag: 'PASS', cls: 'is-pass', mark: '✓' },
  { key: 'xfo', name: 'X-Frame-Options', tag: 'PASS', cls: 'is-pass', mark: '✓' },
  { key: 'csp', name: 'Content-Security-Policy', tag: 'WARN', cls: 'is-warn', mark: '!' },
];

const CORS_ROWS = [
  { key: 'acao', name: 'Access-Control-Allow-Origin', tag: 'WARN', cls: 'is-warn', mark: '!' },
];

const LEAK_ROWS = [
  { key: 'server', name: 'Server: nginx', tag: 'FOUND', cls: 'is-found', mark: '●' },
];

const GROUPS = [
  { label: 'SECURITY HEADERS', rows: HEADER_ROWS, at: 2 },
  { label: 'CORS', rows: CORS_ROWS, at: 3 },
  { label: 'INFORMATION LEAKAGE', rows: LEAK_ROWS, at: 4 },
];

const MAX = PHASES.length - 1;

export default function Scanner({ staticMode = false }) {
  const [started, setStarted] = useState(false);
  const [stage, setStage] = useState(staticMode ? MAX : 0);

  useEffect(() => {
    if (staticMode) {
      setStage(MAX);
      return undefined;
    }
    if (reduceMotion) {
      setStage(MAX);
      return undefined;
    }
    const t = window.setTimeout(() => setStarted(true), 400);
    return () => window.clearTimeout(t);
  }, [staticMode]);

  useEffect(() => {
    if (staticMode || !started || reduceMotion) {
      return undefined;
    }
    if (stage >= MAX) {
      return undefined;
    }
    const t = window.setTimeout(
      () => setStage((s) => Math.min(s + 1, MAX)),
      STEP_MS
    );
    return () => window.clearTimeout(t);
  }, [staticMode, started, stage]);

  function rescan() {
    setStage(0);
    setStarted(true);
  }

  const isFinal = stage >= MAX;
  const phase = PHASES[stage];

  return (
    <div
      className={'scan panel' + (isFinal ? ' is-final' : '')}
      role="img"
      aria-label="Argus scan console showing analysis of https://example.com"
    >
      <div className="scan__bar">
        <span className="scan__brand">ARGUS</span>
        <span
          className={'scan__status' + (phase.busy ? ' is-busy' : ' is-ready')}
          aria-live="polite"
        >
          <i className="scan__dot" aria-hidden="true"></i>
          {phase.text}
        </span>
        {isFinal && !staticMode && (
          <button className="scan__rescan" type="button" onClick={rescan}>
            RESCAN
          </button>
        )}
      </div>

      <div className="scan__body">
        {stage >= 1 && (
          <>
            <div className="scan__row" style={{ '--d': '0ms' }}>
              <span className="scan__label">TARGET</span>
              <span className="scan__value scan__value--url">
                https://example.com
              </span>
            </div>
            <div className="scan__row" style={{ '--d': '80ms' }}>
              <span className="scan__label">RESPONSE</span>
              <span className="scan__value">200 OK</span>
              <span className="scan__right">
                <span className="scan__sel">184ms</span>
              </span>
            </div>
          </>
        )}

        {GROUPS.map((group) =>
          stage >= group.at ? (
            <div className="scan__group" key={group.label} style={{ '--d': '0ms' }}>
              <p className="scan__group-label">{group.label}</p>
              {group.rows.map((row, i) => (
                <div className="scan__check" key={row.key} style={{ '--d': `${i * 80}ms` }}>
                  <span className="scan__check-name">{row.name}</span>
                  {isFinal ? (
                    <span className={'scan__status-tag ' + row.cls} style={{ '--d': `${i * 70}ms` }}>
                      <span className="tick" aria-hidden="true">
                        {row.mark}
                      </span>
                      {row.tag}
                    </span>
                  ) : (
                    <span className="scan__status-tag" aria-hidden="true">
                      …
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : null
        )}

        {stage >= 4 && (
          <div className="scan__foot">
            <span className="scan__foot-mark">02 FINDINGS</span>
            <span className="scan__foot-note" style={{ '--d': '100ms' }}>
              {isFinal ? '● REPORT READY' : 'SCANNING…'}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}