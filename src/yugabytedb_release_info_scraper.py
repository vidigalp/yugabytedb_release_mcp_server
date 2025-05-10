# yugabytedb_release_mcp_server/src/yugabytedb_release_info_scraper.py
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

from src.common_utils import _normalize_version_string


@dataclasses.dataclass
class YugabyteReleaseInfo:
    """Holds information about a YugabyteDB release series."""
    series: str
    type: str  # Stores the raw type string like "LTS", "STS", "Preview"
    released: str
    end_of_maintenance: str
    end_of_life: str
    status: Literal["Active", "EOL", "Unknown"] # Status can remain Literal


def _parse_table(
    table_element: Tag,
    current_status: Literal["Active", "EOL", "Unknown"]
) -> List[YugabyteReleaseInfo]:
    """Parses a single HTML table element to extract YugabyteDB release information.

    It iterates through table rows, extracting details such as release series,
    type (LTS, STS, Preview), release date, end of maintenance, and end of life.

    Args:
        table_element: The BeautifulSoup `Tag` object representing the HTML table
                       containing release data.
        current_status: The status (e.g., "Active", "EOL") to assign to all
                        releases found within this specific table.

    Returns:
        A list of `YugabyteReleaseInfo` objects, each representing a parsed
        release series from the table. Returns an empty list if the table
        body (`<tbody>`) is not found or if no valid rows are parsed.
    """
    releases: List[YugabyteReleaseInfo] = []
    tbody = table_element.find('tbody')
    if not isinstance(tbody, Tag):
        logger.warning("Table has no tbody. Skipping table.")
        return releases

    rows: List[Tag] = tbody.find_all('tr', recursive=False)
    for row in rows:
        if not isinstance(row, Tag):
            continue
        cells: List[Tag] = row.find_all('td', recursive=False)
        if len(cells) < 4:
            logger.debug(f"Skipping row with insufficient cells: {row.get_text(strip=True)}")
            continue

        series_cell: Tag = cells[0]
        series_cell_text: str = series_cell.get_text(separator=" ", strip=True)

        series_name: str = ""
        series_link_tag: Optional[Tag] = series_cell.find('a')

        if isinstance(series_link_tag, Tag):
            link_text_content: Union[NavigableString, Tag, None] = series_link_tag.string
            if link_text_content is not None:
                series_name = str(link_text_content).strip()

        if not series_name:
            name_parts = series_cell_text.split(' ')
            if name_parts:
                series_name = name_parts[0]

        if not series_name:
            logger.warning(f"Could not determine series name from cell: {series_cell_text}. Skipping row.")
            continue

        release_type_str: Optional[str] = None

        span_class_candidates = [
            'tag release preview',
            'tag release lts',
            'tag release sts',
            'preview',
            'lts',
            'sts'
        ]

        for css_class in span_class_candidates:
            type_span: Optional[Tag] = series_cell.find('span', class_=css_class)
            if isinstance(type_span, Tag):
                span_text_content_str: str = type_span.get_text(strip=True)
                if span_text_content_str:
                    release_type_str = span_text_content_str
                    break

        if not release_type_str and "Preview" in series_cell_text:
            release_type_str = "Preview"

        if release_type_str == "Preview":
            if series_name.endswith(" Preview"):
                series_name = series_name.removesuffix(" Preview").strip()
            elif series_name.endswith("Preview"):
                 series_name = series_name.removesuffix("Preview").strip()
        
        #if not release_type_str: # Check added from previous steps, ensuring it's still here
        #    logger.warning(f"Could not determine release type string for series '{series_name}' from cell '{series_cell_text}'. Skipping row.")
        #    continue


        released_date: str = cells[1].get_text(strip=True)
        eom_date: str = cells[2].get_text(strip=True)
        if eom_date.lower() == "no support":
            eom_date = "No support"

        eol_date: str = cells[3].get_text(strip=True)
        if eol_date.lower() == "n/a":
            eol_date = "n/a"

        releases.append(YugabyteReleaseInfo(
            series=series_name,
            type=release_type_str,
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
    """Scrapes YugabyteDB release information from the official documentation page.

    Fetches and parses the HTML content from the given URL. It specifically looks
    for tables associated with active releases (under an `<h2>` with `id="releases"`)
    and end-of-life (EOL) releases (under an `<h2>` with `id="eol-releases"`).

    If a `target_version_or_series` is provided, the function filters the scraped
    results to return only the release series information that matches the target.
    The match can be against a series identifier (e.g., "v2.20", "2024.1") or
    a more specific version string (e.g., "2.20.1.0", "2024.1.0.0-b123"), where
    the function will attempt to match the base series (e.g., "2.20", "2024.1").

    Args:
        url: The URL of the YugabyteDB releases page to scrape. Defaults to the
             YugabyteDB preview releases page.
        target_version_or_series: An optional string representing the specific
            YugabyteDB version or series to retrieve. If None, all found release
            series information is returned. Examples: "v2.20", "2.18",
            "2024.1", "2.14.2.0".

    Returns:
        A list of `YugabyteReleaseInfo` objects. Each object contains details
        for a release series. If `target_version_or_series` is specified,
        the list will contain at most one entry (or be empty if not found).
        Returns an empty list if the URL cannot be fetched, parsing fails to
        find relevant tables, or if a specified target is not found.
    """
    all_releases: List[YugabyteReleaseInfo] = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
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
