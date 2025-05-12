# yugabytedb_release_mcp_server/src/yugabytedb_tech_advisories_fetcher.py
"""
Fetches and processes YugabyteDB Technical Advisories (TAs).

Scrapes the main TA listing page, filters advisories based on version/series,
fetches the content of relevant advisories, and returns the data as a list.
"""

import dataclasses
import json
import re
import sys
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag
from loguru import logger

# Assuming common_utils.py exists in src or parent and contains _normalize_version_string
# If not, uncomment and use the local version below
# from src.common_utils import _normalize_version_string

# --- Local _normalize_version_string if common_utils is not available ---
def _normalize_version_string(version_str: Optional[str]) -> str:
    """Helper to normalize version strings, e.g., 'v2.20.1' -> '2.20.1'."""
    if not version_str:
        return ""
    return version_str.strip().lstrip('vV ')
# --- End Local Helper ---


@dataclasses.dataclass
class YugabyteTechAdvisory:
    """Holds information about a YugabyteDB Technical Advisory."""
    id: str
    title: str
    url: str
    affected_versions_raw: str  # Raw string from the table
    affected_series_parsed: List[str] # Parsed list like ["2.18", "2.20"]
    content: Optional[str] = None # Fetched content from the detail page


def _parse_affected_series(version_str: str) -> List[str]:
    """
    Parses the 'Affected Versions' string from the TA table into a list of
    base series identifiers (e.g., "2.18", "2.20", "2024.1").

    Handles simple formats like "2.18.x", "2.20.x", "2024.1.x", lists
    separated by commas/and, and attempts to extract major.minor patterns.
    It's a best-effort parsing based on observed formats.
    """
    parsed_series: List[str] = []
    # Normalize whitespace and separators
    normalized_str = re.sub(r'\s+(?:and|,)\s+', ',', version_str.strip())
    normalized_str = re.sub(r'\s+', ' ', normalized_str) # Consolidate spaces

    # Find all patterns like X.Y or XXXX.Y (allowing optional .z etc. suffix)
    # This regex looks for digits.digits (potentially more digits.digits)
    potential_matches = re.findall(r'(\d+\.\d+(?:\.\d+)*)', normalized_str)

    for match in potential_matches:
        parts = match.split('.')
        if len(parts) >= 2:
            series_id = f"{parts[0]}.{parts[1]}"
            if series_id not in parsed_series:
                parsed_series.append(series_id)
        elif len(parts) == 1 and parts[0].isdigit(): # Handle case maybe like "2" if it ever appears
             if match not in parsed_series: # Less likely, but capture just in case
                 parsed_series.append(match)


    # If regex fails, try simple splitting as a fallback for unexpected formats
    if not parsed_series and normalized_str:
        logger.trace(f"Regex failed for '{version_str}', trying simple split.")
        components = normalized_str.split(',')
        for comp in components:
            comp_strip = comp.strip().rstrip('.x').rstrip('x').strip()
            # Check if it looks like a version number fragment
            if re.match(r'^\d+\.\d+', comp_strip):
                 parts = comp_strip.split('.')
                 series_id = f"{parts[0]}.{parts[1]}"
                 if series_id not in parsed_series:
                     parsed_series.append(series_id)
            elif comp_strip and comp_strip not in ["later", "earlier", "only", "and"]: # Avoid adding noise
                 # Fallback: Add the stripped component if it seems meaningful
                 logger.debug(f"Adding non-standard component '{comp_strip}' from '{version_str}' to parsed series.")
                 if comp_strip not in parsed_series:
                    parsed_series.append(comp_strip) # Add potentially non-standard entries


    logger.trace(f"Parsed '{version_str}' -> {parsed_series}")
    return parsed_series


def _fetch_advisory_content(advisory_url: str) -> Optional[str]:
    """Fetches and extracts the main content of a single TA page."""
    try:
        response = requests.get(advisory_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Common content containers in YB docs themes
        content_area: Optional[Tag] = None
        selectors = ['div.td-content', 'article', 'div.main-content', 'main'] # Add more selectors if needed

        for selector in selectors:
             content_area = soup.select_one(selector)
             if content_area:
                  logger.trace(f"Found content area using selector: '{selector}'")
                  break

        if not content_area:
            logger.warning(f"Could not find main content area in {advisory_url}")
            return None

        # Basic cleanup: remove script, style tags, nav elements if any slipped through
        for tag in content_area.find_all(['script', 'style', 'nav', 'aside']):
            tag.decompose()

        # Extract text, trying to preserve some structure with newlines
        text_content = content_area.get_text(separator='\n', strip=True)
        # Reduce multiple blank lines to a maximum of two
        text_content = re.sub(r'\n{3,}', '\n\n', text_content)

        return text_content.strip()

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching TA content from {advisory_url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing TA content from {advisory_url}: {e}")
        return None


def _scrape_advisories_list(base_url: str) -> List[YugabyteTechAdvisory]:
    """Scrapes the main TA listing page to get basic info for all advisories."""
    advisories: List[YugabyteTechAdvisory] = []
    try:
        logger.debug(f"Fetching TA list from: {base_url}")
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find the table - adjust selector if the structure changes
        table = soup.find('table') # Simple assumption, might need refinement
        if not table:
             # Look for tables inside common wrappers if direct find fails
             table_wrapper = soup.select_one('div.table-responsive table') or \
                             soup.select_one('article table')
             table = table_wrapper if table_wrapper else None


        if not isinstance(table, Tag):
            logger.error(f"Could not find the advisories table on {base_url}")
            return advisories

        tbody = table.find('tbody')
        if not isinstance(tbody, Tag):
            logger.warning(f"Advisories table found, but has no tbody. Skipping. URL: {base_url}")
            return advisories

        rows = tbody.find_all('tr', recursive=False)
        logger.debug(f"Found {len(rows)} rows in the TA table.")

        for row in rows:
            if not isinstance(row, Tag):
                continue
            cells = row.find_all('td', recursive=False)
            if len(cells) < 3: # Expecting ID, Title, Affected Versions
                logger.debug(f"Skipping row with insufficient cells: {row.get_text(strip=True)}")
                continue

            id_cell, title_cell, affected_cell = cells[0], cells[1], cells[2]

            # Extract ID and URL from the link in the first cell
            id_tag = id_cell.find('a')
            advisory_id = "Unknown"
            advisory_url = None
            if isinstance(id_tag, Tag) and id_tag.get('href'):
                advisory_id = id_tag.get_text(strip=True)
                relative_url = id_tag['href']
                # Ensure the URL is absolute
                advisory_url = urljoin(base_url, relative_url) # Handles relative paths correctly

            if not advisory_url:
                 logger.warning(f"Could not extract URL for row: {row.get_text(strip=True)}. Skipping.")
                 continue # Cannot fetch content without URL

            # Extract Title
            title = title_cell.get_text(strip=True)

            # Extract Raw Affected Versions string
            affected_versions_raw = affected_cell.get_text(strip=True)
            if not affected_versions_raw:
                 affected_versions_raw = "N/A" # Handle empty cells


            # Parse the affected versions string into series
            affected_series = _parse_affected_series(affected_versions_raw)

            advisories.append(YugabyteTechAdvisory(
                id=advisory_id,
                title=title,
                url=advisory_url,
                affected_versions_raw=affected_versions_raw,
                affected_series_parsed=affected_series
            ))

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching TA list from {base_url}: {e}")
    except Exception as e:
        logger.error(f"Error parsing TA list from {base_url}: {e}")

    logger.info(f"Scraped basic info for {len(advisories)} technical advisories.")
    return advisories


def fetch_yugabytedb_tech_advisories(
    target_version_or_series: Optional[str] = None,
    base_url: str = "https://docs.yugabyte.com/preview/releases/techadvisories/"
) -> List[Dict[str, Any]]:
    """
    Fetches YugabyteDB Technical Advisories, filters them, and retrieves content.

    Args:
        target_version_or_series: If provided, filters advisories to those
            affecting this specific version (e.g., "2.18.1.0") or series
            (e.g., "2.18", "v2024.1"). If None, retrieves all advisories.
        base_url: The URL of the main Technical Advisories listing page.

    Returns:
        A list of dictionaries, where each dictionary represents a relevant
        technical advisory including its content. Returns an empty list on failure.
    """
    all_advisories_base_info = _scrape_advisories_list(base_url)
    if not all_advisories_base_info:
        return []

    filtered_advisories: List[YugabyteTechAdvisory] = []
    target_series: Optional[str] = None

    if target_version_or_series:
        normalized_target = _normalize_version_string(target_version_or_series)
        target_parts = normalized_target.split('.')
        if len(target_parts) >= 2:
            target_series = f"{target_parts[0]}.{target_parts[1]}"
            logger.info(f"Filtering advisories for target '{target_version_or_series}', matching against series '{target_series}'.")
        else:
             logger.warning(f"Could not determine series from target '{target_version_or_series}'. No filtering applied.")
             # Proceed as if no target was given, or return empty? Let's proceed for now.
             target_series = None # Fallback to getting all
    else:
        logger.info("No target version/series specified. Fetching all advisories.")


    for advisory in all_advisories_base_info:
        # Apply filter
        is_relevant = False
        if not target_series: # No filter applied or fallback
             is_relevant = True
        elif target_series in advisory.affected_series_parsed:
            logger.debug(f"Advisory '{advisory.id}' matches target series '{target_series}'.")
            is_relevant = True
        else:
             # Check for potential "X.Y.z and later" type matches if applicable
             # Basic check: Does any affected series partially match and imply range?
             # This part is complex and depends heavily on consistent notation in 'affected_versions_raw'
             # Keeping it simple for now: direct series match.
             pass


        if is_relevant:
            logger.info(f"Fetching content for relevant advisory: {advisory.id} ({advisory.url})")
            advisory.content = _fetch_advisory_content(advisory.url)
            if advisory.content is None:
                 logger.warning(f"Failed to fetch or process content for {advisory.id}. It will be included without content.")
                 advisory.content = "Error: Content could not be retrieved." # Add placeholder
            filtered_advisories.append(advisory)


    logger.info(f"Returning {len(filtered_advisories)} filtered advisories.")

    # Convert list of dataclasses to list of dictionaries for JSON serialization
    return [dataclasses.asdict(adv) for adv in filtered_advisories]


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, level="INFO") # Change to DEBUG or TRACE for more detail

    test_targets = [
        "2.18",           # Series
        "v2.20.3.0",      # Specific version -> should match 2.20 series
        "2024.1",         # Series
        "2024.2.1.0",     # Specific version -> should match 2024.2 series
        "2.16",           # Series
        "NonExistentSeries", # Should return empty or log warning
        None,  # Get all
    ]

    results: Dict[str, Any] = {}

    for target in test_targets:
        target_key = str(target) if target else "All"
        print(f"\n--- Fetching Technical Advisories for: {target_key} ---")
        advisories_data = fetch_yugabytedb_tech_advisories(target_version_or_series=target)

        if advisories_data:
            print(f"Found {len(advisories_data)} advisories for '{target_key}'.")
            # Storing for potential JSON output later
            results[target_key] = advisories_data
            # Print summary for verification
            for i, adv in enumerate(advisories_data[:2]): # Print first 2 summaries
                 print(f"  [{i+1}] ID: {adv['id']}, Title: {adv['title'][:50]}..., Affected Raw: {adv['affected_versions_raw']}, Content Length: {len(adv.get('content', '')) if adv.get('content') else 0}")
            if len(advisories_data) > 2:
                 print(f"  ... and {len(advisories_data) - 2} more.")
        else:
            print(f"No advisories found or returned for '{target_key}'.")
            results[target_key] = []

    # Example of saving the results for 'All' to a JSON file
    # try:
    #     output_filename = "all_tech_advisories.json"
    #     with open(output_filename, 'w', encoding='utf-8') as f:
    #         json.dump(results.get("All", []), f, indent=2, ensure_ascii=False)
    #     print(f"\nSaved results for 'All' to {output_filename}")
    # except Exception as e:
    #     print(f"\nError saving results to JSON: {e}")

    print("\n--- Fetching Complete ---")
