"""Deep header analyzers for Argus Header v0.8.

Each analyzer inspects a specific family of security headers and emits
structured findings (id, severity, category, title, description,
evidence, impact, recommendation, references).
"""

from .cache import analyze_cache
from .cookies import analyze_cookies
from .cors import analyze_cors
from .cross_origin import analyze_cross_origin
from .csp import analyze_csp
from .hsts import analyze_hsts
from .permissions import analyze_permissions
from .referrer import analyze_referrer

__all__ = [
    "analyze_cache",
    "analyze_cookies",
    "analyze_cors",
    "analyze_cross_origin",
    "analyze_csp",
    "analyze_hsts",
    "analyze_permissions",
    "analyze_referrer",
]
