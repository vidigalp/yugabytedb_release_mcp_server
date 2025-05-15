import sys
import asyncio
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict # Import asdict

from dotenv import load_dotenv
from loguru import logger # Import logger
from fastmcp import Context, FastMCP

# Import functions and classes from other modules
from yugabytedb_cve_fetcher import (
    fetch_yugabytedb_cves,
    YugabyteDbCveInfo,
)
from yugabytedb_release_info_scraper import (
    scrape_yugabytedb_release_info,
    YugabyteReleaseInfo,
)
from yugabytedb_release_notes_fetcher import fetch_yugabytedb_version_notes

from yugabytedb_tech_advisories_fetcher import (
    fetch_yugabytedb_tech_advisories,
    YugabyteTechAdvisory,
)

load_dotenv()

# Fetch NVD API Key from environment if available
NVD_API_KEY: str | None = os.getenv("NVD_API_KEY")


@asynccontextmanager
async def release_info_lifespan(server: FastMCP) -> AsyncIterator[None]:
    """
    Manages the lifecycle for the YugabyteDB Release MCP server.
    Logs API key usage status.

    Args:
        server: The FastMCP server instance

    Yields:
        None
    """
    if NVD_API_KEY:
        logger.info("NVD API Key found and will be used for CVE fetching.")
    else:
        logger.warning(
            "NVD_API_KEY environment variable not set. "
            "CVE fetching will use lower rate limits."
        )
    try:
        yield None
    finally:
        pass


# Initialize FastMCP server
mcp = FastMCP(
    "mcp-yugabytedb-release",
    description="MCP server for YugabyteDB Release Information retrieval",
    lifespan=release_info_lifespan,
    host=os.getenv("HOST", "0.0.0.0"),
    port=int(os.getenv("PORT", "8050")),
)


@mcp.tool()
async def get_release_version_info(
    ctx: Context, version_or_series: str
) -> str:
    """Provides detailed release lifecycle information for a specific YugabyteDB version or series.

       This tool scrapes the official YugabyteDB documentation release page
       (typically https://docs.yugabyte.com/preview/releases/ybdb-releases/)
       to find information about a given release version or series (e.g., "2.20", "v2024.1", "2.18.3.0").
       It extracts details about the release's support status and timeline.

       Args:
           ctx: The MCP server provided context.
           version_or_series: The YugabyteDB version or series string to look up.
                              Examples: "2.20", "v2024.1", "2.18.3.0".

       Returns:
           A JSON string containing the release lifecycle details if found.
           The JSON object includes the following keys:
           - `series` (str): The release series identifier (e.g., "2.20").
           - `type` (str): The release type (e.g., "LTS", "STS", "Preview"). Note: Can be None if not determinable.
           - `released` (str): The date the first version in the series was released (e.g., "2024-03-15").
           - `end_of_maintenance` (str): The date maintenance support ends (e.g., "2025-09-30", "No support").
           - `end_of_life` (str): The date the release reaches end of life (e.g., "2026-03-31", "n/a").
           - `status` (Literal["Active", "EOL", "Unknown"]): The current status of the release series.

           Example Success:
           '{ "series": "2.20", "type": "LTS", "released": "2024-03-15", "end_of_maintenance": "2025-09-30", "end_of_life": "2026-03-31", "status": "Active" }'

           Example Not Found / Error:
           '{ "error": "Release information not found for version/series: 2.99" }'
           '{ "error": "Failed to retrieve release information due to: <reason>" }'
       """
    logger.info(f"Fetching release info for: {version_or_series}")
    try:
        # The scraper function expects the target version or series
        releases_data: list[
            YugabyteReleaseInfo
        ] = scrape_yugabytedb_release_info(
            target_version_or_series=version_or_series
        )

        if releases_data:
            # Should return only one item when a target is specified
            release_info = releases_data[0]
            # Convert dataclass to dict for JSON serialization
            response_data = asdict(release_info)
            logger.success(f"Found release info for {version_or_series}.")
            return json.dumps(response_data)
        else:
            logger.warning(
                f"Release information not found for: {version_or_series}"
            )
            return json.dumps(
                {
                    "error": f"Release information not found for version/series: {version_or_series}"
                }
            )
    except Exception as e:
        logger.error(
            f"Error scraping release info for {version_or_series}: {e}",
            exc_info=True,
        )
        return json.dumps(
            {"error": f"Failed to retrieve release information due to: {e}"}
        )


@mcp.tool()
async def get_cve_list(
    ctx: Context, version_or_series: str | None = None
) -> str:
    """Retrieves a list of Common Vulnerabilities and Exposures (CVEs) related to YugabyteDB.

        This tool queries the National Vulnerability Database (NVD) API v2.0
        (https://nvd.nist.gov/developers/vulnerabilities) to find CVEs associated
        with YugabyteDB. It uses keyword searching ("YugabyteDB") and attempts to
        filter results based on versioning information provided in the NVD data
        if a specific `version_or_series` is supplied.

        Filtering Logic:
        - If `version_or_series` is a specific version (e.g., "2.18.1.0", "v2024.1.2.0"):
          It attempts to match CVEs where NVD data explicitly lists this version or a range
          including this version as affected.
        - If `version_or_series` is a series (e.g., "2.18", "v2024.1"):
          It attempts to match CVEs where NVD data mentions versions within that series
          as affected (this is heuristic-based).
        - If `version_or_series` is None:
          It returns all CVEs found that mention "YugabyteDB" in the NVD database,
          without version filtering.

        Note: The accuracy of version-based filtering depends on the quality and
        format of the configuration data provided by NVD for each CVE. An NVD API
        key (set via the NVD_API_KEY environment variable) is recommended for higher
        request rates.

        Args:
            ctx: The MCP server provided context.
            version_or_series: Optional. The YugabyteDB version or series string to filter by.
                               Examples: "2.18", "v2024.1", "2.18.1.0". If None, fetches all.

        Returns:
            A JSON string representing a list of CVE objects matching the criteria.
            Each CVE object in the list contains:
            - `cve_id` (str): The unique CVE identifier (e.g., "CVE-2023-1234").
            - `description` (str): The English description of the vulnerability from NVD.
            - `cvss_v3_score` (Optional[float]): The CVSS v3 base score, if available.
            - `cvss_v3_severity` (Optional[str]): The CVSS v3 severity level (e.g., "HIGH"), if available.
            - `affected_info` (str): A summary string derived from NVD's configuration data indicating
                                     potentially affected versions/ranges (e.g., "version 2.18.0",
                                     "in range [>= 2.16.0, < 2.16.5]"). Can be "N/A".
            - `published_date` (str): The date the CVE was published by NVD (ISO 8601 format).
            - `last_modified_date` (str): The date the CVE was last modified by NVD (ISO 8601 format).
            - `url` (str): A direct link to the NVD page for the CVE.

            Example Success:
            '[ { "cve_id": "CVE-2023-...", "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH", "affected_info": "version 2.18.1.0", ... }, ... ]'

            Example Error:
            '{ "error": "Failed to retrieve CVE information due to: <reason>" }'
        """
    target_display = f"'{version_or_series}'" if version_or_series else "'All'"
    logger.info(f"Fetching CVE list for target: {target_display}")
    try:
        cves: list[YugabyteDbCveInfo] = fetch_yugabytedb_cves(
            target_version_or_series=version_or_series,
            api_key=NVD_API_KEY
        )

        # Convert list of dataclasses to list of dicts
        cve_list_dict = [asdict(cve) for cve in cves]
        logger.success(
            f"Found {len(cve_list_dict)} CVE(s) for target {target_display}."
        )
        return json.dumps(cve_list_dict)
    except Exception as e:
        logger.error(
            f"Error fetching CVEs for target {target_display}: {e}",
            exc_info=True,
        )
        return json.dumps(
            {"error": f"Failed to retrieve CVE information due to: {e}"}
        )


@mcp.tool()
async def get_technical_advisories(
    ctx: Context, version_or_series: str | None = None
) -> str:
    """Fetches YugabyteDB Technical Advisories (TAs), optionally filtered by version or series.

        This tool scrapes the official YugabyteDB Technical Advisories page
        (https://docs.yugabyte.com/preview/releases/techadvisories/) to gather
        information about known issues or important notices.

        Filtering Logic:
        - If `version_or_series` is provided (e.g., "2.18", "v2024.1", "2.20.3.0"),
          the tool identifies the corresponding series (e.g., "2.18", "2024.1", "2.20")
          and returns only the advisories listed as affecting that series based on
          parsing the 'Affected Versions' column on the documentation page.
        - If `version_or_series` is None, the tool retrieves all available advisories.

        After identifying relevant advisories, it fetches the detailed content from each
        advisory's specific page.

        Args:
            ctx: The MCP server provided context.
            version_or_series: Optional. The YugabyteDB version or series string to filter by.
                               Examples: "2.18", "v2024.1", "2.18.1.0". If None, fetches all.

        Returns:
            A JSON string representing a list of technical advisory objects matching the criteria.
            Each object in the list contains:
            - `id` (str): The advisory identifier (e.g., "TA-12345").
            - `title` (str): The title of the advisory.
            - `url` (str): The direct URL to the advisory's page.
            - `affected_versions_raw` (str): The raw text from the 'Affected Versions' column.
            - `affected_series_parsed` (List[str]): A list of series identifiers parsed from the raw text (e.g., ["2.18", "2.20"]).
            - `content` (Optional[str]): The fetched text content of the advisory page.
                                        Will be "Error: Content could not be retrieved." if fetching failed.

            Example Success (filtered for "2.18"):
            '[ { "id": "TA-123", "title": "Issue under load", "url": "...", "affected_versions_raw": "2.18.x", "affected_series_parsed": ["2.18"], "content": "Detailed description..." }, ... ]'

            Example Success (all):
            '[ { "id": "TA-123", ... }, { "id": "TA-456", ... }, ... ]'

            Example Error:
            '{ "error": "Failed to retrieve technical advisories due to: <reason>" }'
    """
    target_display = f"{version_or_series}" if version_or_series else "All"
    logger.info(f"Fetching technical advisories for target: {target_display}")
    try:
        # Call the imported fetcher function
        advisories_data: list[
            dict
        ] = fetch_yugabytedb_tech_advisories(
            target_version_or_series=version_or_series
            # base_url could be passed here if needed, but defaults are usually fine
        )

        logger.success(
            f"Found {len(advisories_data)} technical advisory/advisories for target {target_display}."
        )
        # The fetcher function already returns a list of dicts, ready for JSON
        return json.dumps(advisories_data)

    except Exception as e:
        logger.error(
            f"Error fetching technical advisories for target {target_display}: {e}",
            exc_info=True,
        )
        return json.dumps(
            {"error": f"Failed to retrieve technical advisories due to: {e}"}
        )


@mcp.tool()
async def get_release_notes(
    ctx: Context, version_or_series: str
) -> str:
    """Retrieves the release notes content for a specific YugabyteDB version or series.

        This tool fetches the HTML content from the official YugabyteDB documentation
        release notes page corresponding to the provided `version_or_series`.
        For example, if "2.18.3.0" or "v2.18" is provided, it targets the release notes
        page for the "v2.18" series (e.g., https://docs.yugabyte.com/preview/releases/ybdb-releases/v2.18/).

        Args:
            ctx: The MCP server provided context.
            version_or_series: The YugabyteDB version or series number.
                               Examples: "2.20", "v2024.1", "2.18.3.0", "v2.16.5.0".

        Returns:
            A string containing the release notes in Markdown format if found and processed
            successfully. If processing fails or the version/series is invalid, it returns
            an error message string.

            Example Success (Markdown content):
            "### New Features\\n\\n*   Feature A...\\n\\n### Improvements\\n\\n*   Improvement B..."

            Example Error:
            "Error: Release notes could not be found or generated for '2.99'. The version might be invalid, too old, or the documentation structure may have changed."
            "Error: Failed to retrieve release notes for '2.18.3.0' due to: <reason>"
        """
    logger.info(f"Fetching release notes for: {version_or_series}")
    try:
        notes: str | None = fetch_yugabytedb_version_notes(version_or_series)

        if notes:
            logger.success(
                f"Successfully fetched release notes for {version_or_series}."
            )
            # Limit output length slightly for logs if notes are very long
            logger.debug(f"Notes snippet: {notes[:200]}...")
            return notes
        else:
            logger.warning(
                f"Could not find or generate release notes for: {version_or_series}"
            )
            return (
                f"Error: Release notes could not be found or generated for "
                f"'{version_or_series}'. The version might be invalid, too old, "
                f"or the documentation structure may have changed."
            )
    except Exception as e:
        logger.error(
            f"Error fetching release notes for {version_or_series}: {e}",
            exc_info=True,
        )
        return f"Error: Failed to retrieve release notes for '{version_or_series}' due to: {e}"


async def main():
    # Configure logging level (e.g., INFO for summary, DEBUG for details)
    # Set log level via environment variable or directly
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.remove() # Remove default handler
    logger.add(sys.stderr, level=log_level) # Add back with configured level
    logger.info(f"Log level set to: {log_level}")

    transport = os.getenv("TRANSPORT", "sse")
    logger.info(f"Using transport: {transport}")
    if transport == 'sse':
        # Run the MCP server with sse transport
        await mcp.run_http_async()
    else:
        # Run the MCP server with stdio transport
        await mcp.run_stdio_async()


if __name__ == "__main__":

    asyncio.run(main())
