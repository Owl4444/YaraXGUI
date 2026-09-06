"""Locations shared by source checkouts and PyInstaller bundles.

Keep resources anchored to the application, independent of the working
directory. User settings and database locations must survive source moves.
"""

import sys
from pathlib import Path


def resource_root() -> Path:
    """Return the checkout root or the frozen bundle's resource directory."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
