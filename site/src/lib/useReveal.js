/*
 * useReveal — scroll-reveal system for [data-reveal] elements.
 *
 * Fail-safe design: there is no resting hidden state. Entrance effects are
 * one-shot keyframe animations (css/animations.css) that only play once the
 * reveal system has armed itself (html.js[data-reveal-ready]) AND tagged an
 * element with .is-in. If JS is off, errors, or the observer never fires,
 * every element stays fully visible by default.
 */
import { useEffect } from 'react';
import { reduceMotion } from './config';

let run = false;

export function useReveal() {
  useEffect(() => {
    if (run) {
      return undefined;
    }
    run = true;

    const doc = document.documentElement;
    doc.classList.add('js');

    const revealEls = Array.prototype.slice.call(
      document.querySelectorAll('[data-reveal]')
    );

    function inViewport(el) {
      if (!el || !el.getBoundingClientRect) {
        return false;
      }
      const r = el.getBoundingClientRect();
      return r.top < window.innerHeight - 40 && r.bottom > 0;
    }

    function revealAll() {
      revealEls.forEach((el) => el.classList.add('is-in'));
    }

    let revealObserver = null;

    function revealEntry(entry) {
      if (!entry.isIntersecting) {
        return;
      }
      entry.target.classList.add('is-in');
      if (revealObserver) {
        revealObserver.unobserve(entry.target);
      }
    }

    if (!reduceMotion && typeof IntersectionObserver !== 'undefined') {
      try {
        revealObserver = new IntersectionObserver(revealEntry, {
          threshold: 0.12,
          rootMargin: '0px 0px -6% 0px',
        });
      } catch (err) {
        revealObserver = null;
      }
    }

    if (revealObserver) {
      doc.setAttribute('data-reveal-ready', '');
      revealEls.forEach((el) => {
        try {
          revealObserver.observe(el);
        } catch (err) {
          el.classList.add('is-in');
        }
      });

      /* Failsafes: tag in-viewport elements if the observer is slow, and
         tag everything after a hard timeout so nothing is ever blank. */
      const soft = window.setTimeout(() => {
        revealEls.forEach((el) => {
          if (!el.classList.contains('is-in') && inViewport(el)) {
            el.classList.add('is-in');
          }
        });
      }, 1200);

      const hard = window.setTimeout(revealAll, 6000);

      return () => {
        window.clearTimeout(soft);
        window.clearTimeout(hard);
        revealObserver.disconnect();
      };
    }

    revealAll();
    return undefined;
  }, []);
}