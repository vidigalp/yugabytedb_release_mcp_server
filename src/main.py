from mcp.server.fastmcp import FastMCP, Context
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
# Removed: from dataclasses import dataclass
from dotenv import load_dotenv
# Removed: from mem0 import Memory
import asyncio
import json
import os

# Removed: from utils import get_db_client

load_dotenv()

# Removed: DEFAULT_USER_ID

# Removed: LincolnContext dataclass

@asynccontextmanager
async def release_info_lifespan(server: FastMCP) -> AsyncIterator[None]:
    """
    Manages the lifecycle for the YugabyteDB Release MCP server.
    Currently, no specific context is injected.

    Args:
        server: The FastMCP server instance

    Yields:
        None
    """
    try:
        yield None
    finally:
        pass

# Initialize FastMCP server
mcp = FastMCP(
    "mcp-yugabytedb-release",
    description="MCP server for YugabyteDB Release Information retrieval",
    lifespan=release_info_lifespan, # Using the new simple lifespan
    host=os.getenv("HOST", "0.0.0.0"),
    port=int(os.getenv("PORT", "8050")) # Ensure port is an integer
)

@mcp.tool()
async def get_release_version_info(ctx: Context, version_number: str) -> str:
    """Provides detailed information for a specific YugabyteDB release version.

    Args:
        ctx: The MCP server provided context.
        version_number: The YugabyteDB version number (e.g., "2.25.1.0", "2.14.2.0-b381").

    Returns:
        A JSON string containing:
        - version: The full version number.
        - series: The release series (e.g., "v2.14").
        - type: Release type (PREVIEW, LTS, STS, NONE).
        - released: Release date.
        - end_of_maintenance: End of Maintenance date.
        - end_of_life: End of Life (EOL) date.
        - status: Current status (ACTIVE, EOL).
    """
    # Placeholder implementation
    # In a real implementation, this would query a database or a data source.
    response_data = {
        "version": version_number,
        "series": "vX.Y", # Placeholder
        "type": "STS", # Placeholder
        "released": "YYYY-MM-DD", # Placeholder
        "end_of_maintenance": "YYYY-MM-DD", # Placeholder
        "end_of_life": "YYYY-MM-DD", # Placeholder
        "status": "ACTIVE" # Placeholder
    }
    return json.dumps(response_data)

@mcp.tool()
async def get_cve_list(ctx: Context, version_number: str = None) -> str:
    """Retrieves a list of CVEs, optionally filtered by YugabyteDB version.

    Args:
        ctx: The MCP server provided context.
        version_number: Optional YugabyteDB version number to filter CVEs.

    Returns:
        A JSON string representing a list of CVEs.
    """
    # Placeholder implementation
    cves = [
        {"id": "CVE-YYYY-NNNN1", "description": "Example vulnerability 1", "versions_affected": ["2.x.x"]},
        {"id": "CVE-YYYY-NNNN2", "description": "Example vulnerability 2", "versions_affected": ["all"]},
    ]
    if version_number:
        # Dummy filter logic
        cves = [cve for cve in cves if version_number in cve.get("versions_affected", []) or "all" in cve.get("versions_affected", [])]
    return json.dumps(cves)

@mcp.tool()
async def get_technical_advisories(ctx: Context, version_number: str) -> str:
    """Fetches technical advisories for a specific YugabyteDB version.

    Args:
        ctx: The MCP server provided context.
        version_number: The YugabyteDB version number.

    Returns:
        A JSON string containing a list of technical advisories (e.g., titles and links).
    """
    # Placeholder implementation
    advisories = [
        {"title": f"Advisory 1 for {version_number}", "link": "https://docs.yugabyte.com/preview/releases/techadvisories/example1"},
        {"title": f"Advisory 2 for {version_number}", "link": "https://docs.yugabyte.com/preview/releases/techadvisories/example2"},
    ]
    return json.dumps(advisories)

@mcp.tool()
async def get_release_notes(ctx: Context, version_number: str) -> str:
    """Provides a link to or content of the release notes for a specific YugabyteDB version.

    Args:
        ctx: The MCP server provided context.
        version_number: The YugabyteDB version number.

    Returns:
        A string, which could be a URL to the release notes or the notes content itself.
    """
    # Placeholder implementation
    # Example: "v2.20.1.0" -> "v2.20" for URL construction
    series_part = ".".join(version_number.split(".")[:2]) # e.g., "2.20"
    if series_part.startswith("v"):
         url_series_part = series_part
    else:
        url_series_part = "v" + series_part # e.g., "v2.20"

    release_notes_url = f"https://docs.yugabyte.com/preview/releases/ybdb-releases/{url_series_part}/#change-log"
    return f"Release notes for {version_number} can be found at: {release_notes_url}"

async def main():
    transport = os.getenv("TRANSPORT", "sse")
    if transport == 'sse':
        # Run the MCP server with sse transport
        await mcp.run_sse_async()
    else:
        # Run the MCP server with stdio transport
        await mcp.run_stdio_async()

if __name__ == "__main__":
    asyncio.run(main())