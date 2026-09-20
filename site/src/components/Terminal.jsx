import { useEffect, useRef } from 'react';
import { reduceMotion } from '../lib/config';
import CopyButton from './CopyButton';

/*
 * Terminal — types the demo session into the body once the terminal scrolls
 * into view, with a hard failsafe so it is never left empty. Reduced motion
 * (or a JS failure) renders the full transcript instantly.
 */

const SCRIPT = [
  { t: 'cmd', d: 'pip install argus-header' },
  { t: 'gap' },
  { t: 'cmd', d: 'argus-header https://example.com' },
  { t: 'gap' },
  { t: 'sec', d: 'ARGUS HTTP SECURITY ANALYZER' },
  { t: 'div', d: '──────────────────────────────────────────────' },
  { t: 'kv', d: 'Target: ', v: 'https://example.com' },
  { t: 'kv', d: 'Status: ', v: '200 OK' },
  { t: 'gap' },
  { t: 'sec', d: 'Security Headers' },
  { t: 'ok', d: '✓  Strict-Transport-Security' },
  { t: 'ok', d: '✓  X-Content-Type-Options' },
  { t: 'warn', d: '!  Content-Security-Policy' },
  { t: 'gap' },
  { t: 'sec', d: 'CORS' },
  { t: 'warn', d: '!  Wildcard origin detected' },
  { t: 'gap' },
  { t: 'sec', d: 'Information Leakage' },
  { t: 'warn', d: '!  Server information exposed' },
];

const COPY_TEXT = SCRIPT.map((line) =>
  line.t === 'cmd' ? `$ ${line.d}` : line.t === 'gap' ? '' : line.d
)
  .filter((s, i, arr) => !(s === '' && (i === 0 || arr[i - 1] === '')))
  .join('\n');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function makeLine(className, text) {
  const div = document.createElement('div');
  div.className = 't-line' + (className ? ' ' + className : '');
  div.textContent = text;
  return div;
}

function makeCaret() {
  const caret = document.createElement('span');
  caret.className = 't-caret';
  caret.setAttribute('aria-hidden', 'true');
  return caret;
}

export default function Terminal() {
  const bodyRef = useRef(null);

  useEffect(() => {
    const body = bodyRef.current;
    if (!body) {
      return undefined;
    }

    let cancelled = false;
    let onScroll = null;
    const timers = [];
    const later = (fn, ms) => {
      timers.push(window.setTimeout(fn, ms));
    };

    function printInstant() {
      SCRIPT.forEach((line) => {
        if (line.t === 'gap') {
          body.appendChild(makeLine('', ''));
        } else if (line.t === 'kv') {
          const div = document.createElement('div');
          div.className = 't-line t-kv';
          div.innerHTML = '';
          const label = document.createElement('span');
          label.textContent = line.d;
          const val = document.createElement('strong');
          val.textContent = line.v;
          div.appendChild(label);
          div.appendChild(val);
          body.appendChild(div);
        } else {
          body.appendChild(makeLine(line.t, line.d));
        }
      });
      body.appendChild(makeCaret());
    }

    async function printTyped() {
      for (let i = 0; i < SCRIPT.length; i++) {
        const line = SCRIPT[i];
        if (cancelled) {
          return;
        }
        if (line.t === 'cmd') {
          const row = makeLine('t-cmd', '');
          const prompt = document.createElement('span');
          prompt.className = 't-prompt';
          prompt.textContent = '$ ';
          const text = document.createElement('span');
          const caret = makeCaret();
          row.appendChild(prompt);
          row.appendChild(text);
          row.appendChild(caret);
          body.appendChild(row);
          for (let ci = 0; ci < line.d.length; ci++) {
            text.textContent += line.d.charAt(ci);
            await delay(14);
          }
          row.removeChild(caret);
        } else if (line.t === 'gap') {
          body.appendChild(makeLine('', ''));
        } else if (line.t === 'kv') {
          const div = document.createElement('div');
          div.className = 't-line t-kv';
          const label = document.createElement('span');
          label.textContent = line.d;
          const val = document.createElement('strong');
          val.textContent = line.v;
          div.appendChild(label);
          div.appendChild(val);
          body.appendChild(div);
          await delay(24);
        } else {
          body.appendChild(makeLine(line.t, line.d));
          await delay(24);
        }
      }
      if (!cancelled) {
        body.appendChild(makeCaret());
      }
    }

    async function play() {
      if (reduceMotion) {
        printInstant();
      } else {
        await printTyped();
      }
    }

    let started = false;
    function start() {
      if (started) {
        return;
      }
      started = true;
      play();
    }

    const prefersReduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduce || typeof IntersectionObserver === 'undefined') {
      start();
    } else {
      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              start();
              observer.disconnect();
            }
          });
        },
        { threshold: 0.15 }
      );
      observer.observe(body);
      later(start, 5000);
      onScroll = () => {
        const r = body.getBoundingClientRect();
        if (r.top < window.innerHeight && r.bottom > 0) {
          start();
        }
      };
      window.addEventListener('scroll', onScroll, { passive: true });
    }

    return () => {
      cancelled = true;
      timers.forEach((t) => t && window.clearTimeout(t));
      if (onScroll) {
        window.removeEventListener('scroll', onScroll);
      }
    };
  }, []);

  return (
    <div className="term" data-reveal>
      <div className="term__bar">
        <span className="panel__bar-btns" aria-hidden="true">
          <i></i>
          <i></i>
          <i></i>
        </span>
        <span className="term__title">ARGUS HEADER — TERMINAL</span>
        <span className="term__copy">
          <CopyButton
            text={COPY_TEXT}
            label="COPY COMMAND"
            copiedLabel="COPIED"
          />
        </span>
      </div>
      <div className="term__body" ref={bodyRef} aria-label="Demo terminal output"></div>
    </div>
  );
}