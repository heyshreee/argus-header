import { useEffect, useState } from 'react';
import { useScrolledNav } from '../lib/useScrolledNav';
import { useScrollSpy } from '../lib/useScrollSpy';
import ArgusMark from './ArgusMark';

const GITHUB_URL = 'https://github.com/heyshreee/argus-header';
const GITHUB_STARS = 16;

const GITHUB_ICON =
  'M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12';

function GitHubStars({ className = '' }) {
  return (
    <a
      className={`nav__gh ${className}`.trim()}
      href={GITHUB_URL}
      target="_blank"
      rel="noopener"
      aria-label={`${GITHUB_STARS} stars on GitHub`}
    >
      <svg className="nav__gh-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path fill="currentColor" d={GITHUB_ICON} />
      </svg>
      <span>{GITHUB_STARS}</span>
    </a>
  );
}

const LINKS = [
  { href: '#checks', label: 'FEATURES' },
  { href: '#cli', label: 'CLI' },
  {
    href: 'https://github.com/heyshreee/argus-header/blob/main/docs/DOCUMENTATION.md',
    label: 'DOCUMENTATION',
    external: true,
  },
];

const MOBILE_LINKS = [
  { href: '#checks', label: 'Features', num: '01' },
  { href: '#cli', label: 'CLI', num: '02' },
  { href: '#analysis', label: 'Analysis', num: '03' },
  {
    href: 'https://github.com/heyshreee/argus-header/blob/main/docs/DOCUMENTATION.md',
    label: 'Documentation',
    num: '04',
    external: true,
  },
];

export default function Nav() {
  const [open, setOpen] = useState(false);
  const scrolled = useScrolledNav();
  useScrollSpy();

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e) => {
      if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = prev;
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <header className={'nav' + (scrolled || open ? ' is-scrolled' : '')} id="nav">
      <nav className="nav__inner" aria-label="Primary">
        <a className="nav__brand" href="#top" aria-label="Argus Header — home">
          <ArgusMark className="nav__mark" />
          <span className="nav__word">
            <strong>ARGUS</strong>
            <small>HTTP SECURITY ANALYZER</small>
          </span>
        </a>

        <ul className="nav__links">
          {LINKS.map((l) =>
            l.external ? (
              <li key={l.label}>
                <a href={l.href} target="_blank" rel="noopener">
                  {l.label}
                </a>
              </li>
            ) : (
              <li key={l.label}>
                <a href={l.href}>{l.label}</a>
              </li>
            )
          )}
        </ul>

        <div className="nav__actions">
          <GitHubStars />
          <a className="btn btn--sm btn--primary nav__get" href="#install">
            GET STARTED <span className="btn__arrow" aria-hidden="true">→</span>
          </a>
          <button
            className="nav__toggle"
            id="navToggle"
            type="button"
            aria-label={open ? 'Close menu' : 'Open menu'}
            aria-expanded={open}
            aria-controls="mobileNav"
            onClick={() => setOpen(!open)}
          >
            <span></span>
            <span></span>
            <span></span>
          </button>
        </div>
      </nav>

      {open && (
        <div className="mobile-nav" id="mobileNav">
          <nav aria-label="Mobile">
            <ul>
              {MOBILE_LINKS.map((l) => (
                <li key={l.label}>
                  <a
                    href={l.href}
                    target={l.external ? '_blank' : undefined}
                    rel={l.external ? 'noopener' : undefined}
                    onClick={() => setOpen(false)}
                  >
                    {l.label}
                    <small>{l.num}</small>
                  </a>
                </li>
              ))}
            </ul>
            <div className="mobile-nav__foot">
              <GitHubStars className="nav__gh--mobile" />
              <a className="btn btn--primary" href="#install" onClick={() => setOpen(false)}>
                GET STARTED <span className="btn__arrow" aria-hidden="true">→</span>
              </a>
              <div className="mobile-nav__links">
                <a href="https://pypi.org/project/argus-header/" target="_blank" rel="noopener">
                  PYPI
                </a>
              </div>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}