/*
 * Shared runtime flags.
 */
const hasWindow = typeof window !== 'undefined';

export const reduceMotion = hasWindow
  ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
  : true;

export const coarsePointer = hasWindow
  ? window.matchMedia('(hover: none)').matches ||
    window.matchMedia('(pointer: coarse)').matches
  : false;