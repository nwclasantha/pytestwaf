"""Version tracking for GoTestWAF."""

VERSION: str = "unknown"

try:
    from importlib.metadata import version as _meta_version
    VERSION = _meta_version("gotestwaf")
except Exception:
    pass


def get_version() -> str:
    """Return the current version string."""
    return VERSION if VERSION else "unknown"
