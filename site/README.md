# Argus Header — Landing Page

Landing page for **Argus Header**, an open-source HTTP security analyzer
and CLI tool. Built with React + Vite (plain JavaScript, no TypeScript).

## Requirements

- **Node.js 18+** (required by Vite 5)
- npm (bundled with Node)

## Run locally

```
npm install
npm run dev
```

Then open the URL Vite prints (default `http://localhost:5173`).

## Build for production

```
npm run build
npm run preview
```

`npm run build` outputs the static site to `dist/`.

## Structure

```
site/
├── index.html              # Vite entry (fonts, meta, #root)
├── vite.config.js          # Vite + React plugin config
├── package.json
├── public/                 # copied as-is into dist/
│   ├── favicon.svg         # brand mark (green-pupil scanner glyph)
│   └── og-image.png        # 1200×630 social card
├── css/
│   ├── style.css           # reset, tokens, typography, layout, responsive
│   ├── components.css      # navbar, buttons, scanner, panels, flow, footer
│   └── animations.css      # keyframes, reveal, scanner mount, reduced-motion
└── src/
    ├── main.jsx            # React entry — imports the css files
    ├── App.jsx             # composes the page sections
    ├── lib/
    │   ├── config.js           # motion / pointer runtime flags
    │   ├── useReveal.js        # IntersectionObserver reveals (no-op safe)
    │   ├── useScrolledNav.js   # scrolled-nav state
    │   └── useScrollSpy.js     # active section highlighting
    └── components/
        ├── Nav.jsx             # fixed nav + fullscreen mobile menu
        ├── Hero.jsx            # headline, meta, scrolling terminal + scanner
        ├── Scanner.jsx         # interactive live-analysis panel (hero + product)
        ├── Product.jsx         # product preview / why-argus split
        ├── Checks.jsx          # security checks ledger
        ├── Analysis.jsx        # sample header analysis report
        ├── Terminal.jsx        # typing terminal (failsafe protected)
        ├── Cli.jsx             # CLI commands + marker examples
        ├── Workflow.jsx        # three-step workflow with arrows
        ├── Engine.jsx          # rule engine spec rows
        ├── OpenSource.jsx      # open-source section + activity grid
        ├── Install.jsx         # pip install command + copy button
        ├── Cta.jsx             # closing call to action
        ├── Footer.jsx
        ├── CopyButton.jsx      # reusable clipboard button
        └── ArgusMark.jsx       # shared logo glyph
```

## Behavior notes

- **No resting hidden states.** Entrance animations are one-shot keyframes
  gated on `html.js[data-reveal-ready]` + `.is-in`. If JS errors or the
  observer never fires, every element stays visible by default. The terminal
  also has a 5s failsafe timer.
- `prefers-reduced-motion` is respected in both CSS and JS.
- `StrictMode` is intentionally **not** enabled so the terminal typing
  animation does not double-run in development.
- `base: './'` is set in `vite.config.js`, so the build works from a
  sub-path or file-based hosting.
- Version shown is **v0.8.0**, matching the released CLI banner
  (`ARGUS-HEADER v0.8.0`).
- All external links point at the real product:
  GitHub `github.com/heyshreee/argus-header`, PyPI
  `pypi.org/project/argus-header`.

## Deploy

The build output (`dist/`, created by `npm run build`) is fully static and
deploys as-is to GitHub Pages, Netlify, or Vercel.