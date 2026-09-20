export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer__inner">
        <div className="footer__grid">
          <div className="footer__brand">
            <strong>ARGUS</strong>
            <span>HTTP SECURITY ANALYZER</span>
          </div>

          <div className="footer__col">
            <p className="footer__col-title">Product</p>
            <ul>
              <li>
                <a href="#checks">Features</a>
              </li>
              <li>
                <a href="#cli">CLI</a>
              </li>
              <li>
                <a
                  href="https://github.com/heyshreee/argus-header/blob/main/docs/DOCUMENTATION.md"
                  target="_blank"
                  rel="noopener"
                >
                  Documentation
                </a>
              </li>
            </ul>
          </div>

          <div className="footer__col">
            <p className="footer__col-title">Community</p>
            <ul>
              <li>
                <a
                  href="https://github.com/heyshreee/argus-header"
                  target="_blank"
                  rel="noopener"
                >
                  GitHub
                </a>
              </li>
              <li>
                <a href="https://pypi.org/project/argus-header/" target="_blank" rel="noopener">
                  PyPI
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="footer__meta">
          <span>v0.8.0 · MIT License</span>
          <span>© 2026 Argus</span>
        </div>
      </div>
    </footer>
  );
}