import { useEffect } from 'react';

/*
 * useScrollSpy — highlights the primary-nav link for the section currently
 * in view (port of the sectionObserver logic in js/navigation.js).
 */
export function useScrollSpy() {
  useEffect(() => {
    const links = Array.prototype.slice.call(
      document.querySelectorAll('.nav__links a[href^="#"]')
    );

    if (typeof IntersectionObserver === 'undefined' || !links.length) {
      return undefined;
    }

    const map = {};
    links.forEach((link) => {
      const id = link.getAttribute('href').slice(1);
      const target = document.getElementById(id);
      if (target) {
        map[id] = link;
      }
    });

    const sections = Object.keys(map)
      .map((id) => document.getElementById(id))
      .filter(Boolean);

    const spy = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) {
            return;
          }
          const active = map[entry.target.id];
          if (!active) {
            return;
          }
          links.forEach((link) => link.classList.remove('is-active'));
          active.classList.add('is-active');
        });
      },
      { rootMargin: '-45% 0px -50% 0px', threshold: 0 }
    );

    sections.forEach((section) => spy.observe(section));
    return () => spy.disconnect();
  }, []);
}