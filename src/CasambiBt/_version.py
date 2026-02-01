"""Package version (kept in-sync with setup.cfg).

Home Assistant integrations sometimes run with strict event-loop blocking checks.
Avoid using importlib.metadata in hot paths by providing a static version string.
"""

__all__ = ["__version__"]

# NOTE: Must match `casambi-bt/setup.cfg` [metadata] version.
__version__ = "0.3.12.dev7"
