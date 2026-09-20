import { useEffect, useRef, useState } from 'react';

/*
 * CopyButton — copies `text` to the clipboard with a temporary COPIED state.
 * Uses the async clipboard API when available, otherwise a hidden-textarea
 * fallback.
 */
function legacyCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (err) {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}

export default function CopyButton({
  text,
  label = 'COPY',
  copiedLabel = 'COPIED',
  className = '',
  ...rest
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef(null);

  useEffect(
    () => () => {
      if (timer.current) {
        window.clearTimeout(timer.current);
      }
    },
    []
  );

  async function handleClick() {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (err) {
      ok = false;
    }
    if (!ok) {
      ok = legacyCopy(text);
    }
    if (ok) {
      setCopied(true);
      if (timer.current) {
        window.clearTimeout(timer.current);
      }
      timer.current = window.setTimeout(() => setCopied(false), 1800);
    }
  }

  const cls = ['copy-btn', copied ? 'is-copied' : '', className]
    .filter(Boolean)
    .join(' ');

  return (
    <button
      type="button"
      className={cls}
      onClick={handleClick}
      aria-label={copied ? copiedLabel : label}
      {...rest}
    >
      {copied ? copiedLabel : label}
    </button>
  );
}