/*
 * ArgusMark — minimal scanner-target glyph: a rounded frame, a hairline
 * crosshair, and a single accent pupil. Renders in currentColor except the
 * pupil, which uses the brand accent.
 */
export default function ArgusMark({ className }) {
  return (
    <svg
      className={className}
      viewBox="0 0 32 32"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="29" height="29" rx="3.5" />
      <path d="M16 7v18M7 16h18" strokeOpacity="0.5" />
      <circle cx="16" cy="16" r="2.4" fill="#b7ff3c" stroke="none" />
    </svg>
  );
}