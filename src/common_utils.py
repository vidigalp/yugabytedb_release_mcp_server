# yugabytedb_release_mcp_server/src/common_utils.py
"""
Common utility functions for the YugabyteDB Release MCP server.
"""
from typing import Optional

def _normalize_version_string(version_str: Optional[str]) -> str:
    """Normalizes a version or series string for consistent comparison.

    Removes a leading 'v' (case-insensitive) and strips leading/trailing
    whitespace.

    Args:
        version_str: The version or series string to normalize.
                     Can be None.

    Returns:
        The normalized string, or an empty string if the input is None.
    """
    if not version_str:
        return ""
    s = str(version_str).strip()
    if s.lower().startswith('v'):
        s = s[1:]
    return s