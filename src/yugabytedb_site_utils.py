# yugabytedb_release_mcp_server/src/yugabytedb_site_utils.py
"""
Utilities for scraping information from the YugabyteDB documentation site.

This module requires the 'requests', 'beautifulsoup4', and 'loguru' libraries.
Install them using: pip install requests beautifulsoup4 loguru
"""

import dataclasses
import sys
from typing import List, Literal, Optional, Union

import requests
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString
from loguru import logger


@dataclasses.dataclass
class YugabyteReleaseInfo:
    """Holds information about a YugabyteDB release series."""
    series: str
    type: Literal["PREVIEW", "LTS", "STS"]
    released: str
    end_of_maintenance: str
    end_of_life: str
    status: Literal["Active", "EOL", "Unknown"]


def _normalize_version_string(version_str: Optional[str]) -> str:
    """Helper to normalize version/series strings for comparison."""
    if not version_str:
        return ""
    s = str(version_str).strip()
    if s.lower().startswith('v'):
        s = s[1:]
    return s


def _parse_table(
    table_element: Tag,
    current_status: Literal["Active", "EOL", "Unknown"]
) -> List[YugabyteReleaseInfo]:
    """
    Parses a single HTML table element to extract release information.

    Args:
        table_element: The BeautifulSoup Tag object representing the table.
        current_status: The status to assign to releases found in this table
                        (e.g., "Active" or "EOL").

    Returns:
        A list of YugabyteReleaseInfo objects.
    """
    releases: List[YugabyteReleaseInfo] = []
    tbody = table_element.find('tbody')
    if not isinstance(tbody, Tag): # Check if tbody is a Tag, not None
        logger.warning("Table has no tbody. Skipping table.")
        return releases

    rows: List[Tag] = tbody.find_all('tr', recursive=False) # Get only direct children tr
    for row in rows:
        if not isinstance(row, Tag): # Should be Tag, but defensive
            continue
        cells: List[Tag] = row.find_all('td', recursive=False)
        if len(cells) < 4:
            logger.debug(f"Skipping row with insufficient cells: {row.get_text(strip=True)}")
            continue

        # Cell 0: Release Series & Type
        series_cell: Tag = cells[0]
        series_cell_text: str = series_cell.get_text(separator=" ", strip=True)

        series_name: str = ""
        series_link_tag: Optional[Tag] = series_cell.find('a')

        if isinstance(series_link_tag, Tag):
            link_text_content: Union[NavigableString, Tag, None] = series_link_tag.string
            if link_text_content is not None:
                series_name = str(link_text_content).strip()

        if not series_name: # Fallback if <a> tag missing, empty, or .string is None
            name_parts = series_cell_text.split(' ')
            if name_parts:
                series_name = name_parts[0]

        if not series_name: # If still no series name, skip
            logger.warning(f"Could not determine series name from cell: {series_cell_text}. Skipping row.")
            continue

        release_type: Optional[Literal["PREVIEW", "LTS", "STS"]] = None

        # Prioritize "Preview" text in series name or cell text
        if "Preview" in series_name or "Preview" in series_cell_text:
            release_type = "PREVIEW"
            series_name = series_name.replace("Preview", "").strip() # Clean up series name
        else:
            # Check for specific class spans
            lts_span: Optional[Tag] = series_cell.find('span', class_='lts')
            sts_span: Optional[Tag] = series_cell.find('span', class_='sts')

            if not (lts_span or sts_span): # Try more specific classes if simple ones not found
                lts_span = series_cell.find('span', class_='tag release lts')
                sts_span = series_cell.find('span', class_='tag release sts')
                # Check for preview span explicitly if other types not found by specific class
                if not (lts_span or sts_span) and series_cell.find('span', class_='tag release preview'):
                    release_type = "PREVIEW" # This would be hit if "Preview" text wasn't in name/cell

            if lts_span and not release_type: # Assign if not already PREVIEW
                release_type = "LTS"
            elif sts_span and not release_type: # Assign if not already PREVIEW or LTS
                release_type = "STS"

        if not release_type:
            logger.warning(f"Could not determine release type for series '{series_name}'. Skipping row.")
            continue

        # Cell 1: Released Date
        released_date: str = cells[1].get_text(strip=True)

        # Cell 2: End of Maintenance Support
        eom_date: str = cells[2].get_text(strip=True)
        if eom_date.lower() == "no support": # Normalize
            eom_date = "No support"

        # Cell 3: End of Life (EOL)
        eol_date: str = cells[3].get_text(strip=True)
        if eol_date.lower() == "n/a": # Normalize
            eol_date = "n/a"

        releases.append(YugabyteReleaseInfo(
            series=series_name,
            type=release_type,
            released=released_date,
            end_of_maintenance=eom_date,
            end_of_life=eol_date,
            status=current_status
        ))
    return releases


def scrape_yugabytedb_release_info(
    url: str = "https://docs.yugabyte.com/preview/releases/ybdb-releases/",
    target_version_or_series: Optional[str] = None
) -> List[YugabyteReleaseInfo]:
    """
    Scrapes YugabyteDB release information from the specified URL.

    The function looks for two tables: one for active releases and one for
    End of Life (EOL) releases. If target_version_or_series is provided,
    it filters the results to include only the matching release series.

    Args:
        url: The URL of the YugabyteDB releases page.
        target_version_or_series: An optional string representing the target
            YugabyteDB version (e.g., "2.20.1.0", "v2.18") or series
            (e.g., "v2.20", "2024.1"). If provided, the results will be
            filtered to match this target.

    Returns:
        A list of YugabyteReleaseInfo objects containing the scraped data.
        Returns an empty list if fetching or parsing fails, or if a
        target_version_or_series is specified but no match is found.
    """
    all_releases: List[YugabyteReleaseInfo] = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL {url}: {e}")
        return all_releases

    soup = BeautifulSoup(response.content, 'html.parser')

    active_table: Optional[Tag] = None
    active_releases_header: Optional[Tag] = soup.find('h2', id='releases')
    if isinstance(active_releases_header, Tag):
        table_wrapper: Optional[Tag] = active_releases_header.find_next_sibling('div', class_='table-responsive')
        if isinstance(table_wrapper, Tag):
            active_table = table_wrapper.find('table')
        else:
            # Fallback: try direct table sibling or table in next generic div
            direct_table_sibling = active_releases_header.find_next_sibling('table')
            if isinstance(direct_table_sibling, Tag):
                active_table = direct_table_sibling
            else:
                next_generic_div_sibling = active_releases_header.find_next_sibling('div')
                if isinstance(next_generic_div_sibling, Tag):
                    active_table = next_generic_div_sibling.find('table')

        if isinstance(active_table, Tag):
            all_releases.extend(_parse_table(active_table, "Active"))
            logger.debug("Successfully parsed active releases table.")
        else:
            logger.warning("Active releases table not found after 'Releases' header (id='releases').")
    else:
        logger.warning("'Releases' header (id='releases') not found.")

    eol_table: Optional[Tag] = None
    eol_releases_header: Optional[Tag] = soup.find('h2', id='eol-releases')
    if isinstance(eol_releases_header, Tag):
        table_wrapper = eol_releases_header.find_next_sibling('div', class_='table-responsive')
        if isinstance(table_wrapper, Tag):
            eol_table = table_wrapper.find('table')
        else:
            direct_table_sibling = eol_releases_header.find_next_sibling('table')
            if isinstance(direct_table_sibling, Tag):
                eol_table = direct_table_sibling
            else:
                next_generic_div_sibling = eol_releases_header.find_next_sibling('div')
                if isinstance(next_generic_div_sibling, Tag):
                    eol_table = next_generic_div_sibling.find('table')

        if isinstance(eol_table, Tag):
            all_releases.extend(_parse_table(eol_table, "EOL"))
            logger.debug("Successfully parsed EOL releases table.")
        else:
            logger.warning("EOL releases table not found after 'Releases at end of life (EOL)' header (id='eol-releases').")
    else:
        logger.warning("'Releases at end of life (EOL)' header (id='eol-releases') not found.")

    if not target_version_or_series:
        logger.debug(f"No target version specified, returning all {len(all_releases)} scraped releases.")
        return all_releases

    filtered_releases: List[YugabyteReleaseInfo] = []
    norm_target_input = _normalize_version_string(target_version_or_series)

    target_input_parts = norm_target_input.split('.')
    target_series_component_to_match = norm_target_input

    if len(target_input_parts) >= 2:
        target_series_component_to_match = f"{target_input_parts[0]}.{target_input_parts[1]}"

    logger.debug(f"Filtering for target: '{target_version_or_series}', normalized input: '{norm_target_input}', series component to match: '{target_series_component_to_match}'")

    for release in all_releases:
        norm_scraped_series = _normalize_version_string(release.series)
        if norm_scraped_series == target_series_component_to_match:
            logger.debug(f"Found match: Scraped series '{norm_scraped_series}' matches target series component '{target_series_component_to_match}'")
            filtered_releases.append(release)
            break

    if not filtered_releases:
         logger.info(f"No release information found for target '{target_version_or_series}' (derived series component: '{target_series_component_to_match}').")

    return filtered_releases


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, level="DEBUG")

    test_versions = [
        None,
        "v2.20",
        "2.18",
        "v2024.1",
        "2.14.2.0",
        "2.16.1.0-b123",
        "vNonExistent",
        "1.0.0.0",
        "v2.25",
        "v2.12",
    ]

    for version_filter in test_versions:
        if version_filter:
            logger.info(f"\n--- Scraping YugabyteDB release information for: {version_filter} ---")
        else:
            logger.info("\n--- Scraping all YugabyteDB release information ---")

        releases_data = scrape_yugabytedb_release_info(target_version_or_series=version_filter)

        if releases_data:
            logger.info(f"Successfully scraped {len(releases_data)} release entries for '{version_filter if version_filter else 'all'}'.")
            for release in releases_data:
                logger.info(
                    f"  Series: {release.series}, Type: {release.type}, Status: {release.status}\n"
                    f"    Released: {release.released}\n"
                    f"    End of Maintenance: {release.end_of_maintenance}\n"
                    f"    End of Life: {release.end_of_life}"
                )
        else:
            if not version_filter:
                 logger.info(f"No release information was returned for 'all'.")
            # For specific filters, the "No release information found..." log is now inside scrape_yugabytedb_release_info
