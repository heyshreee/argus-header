import { useEffect, useState } from 'react';

/*
 * useScrolledNav — adds `.is-scrolled` to the fixed nav past 8px.
 */
export function useScrolledNav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return scrolled;
}