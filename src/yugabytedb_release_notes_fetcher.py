# yugabytedb_release_mcp_server/src/yugabytedb_release_notes_fetcher.py
"""
Fetches and processes YugabyteDB release notes for LLM consumption.
Uses requests for fetching, BeautifulSoup for HTML processing,
and crawl4ai for Markdown conversion.
"""
import re
from typing import Optional, Tuple

import requests
from bs4 import BeautifulSoup, Tag
from crawl4ai.markdown_generation_strategy import DefaultMarkdownGenerator
from crawl4ai.content_filter_strategy import PruningContentFilter, BM25ContentFilter
from crawl4ai.async_configs import CrawlerRunConfig
from loguru import logger

#from common_utils import _normalize_version_string


def _parse_input_to_url_parts(version_or_series: str) -> Tuple[str, Optional[str]]:
    """
    Parses the input string to determine the series for URL construction and
    the specific version tag for HTML ID lookup or Markdown section extraction.

    Args:
        version_or_series: The YugabyteDB version or series string
                           (e.g., "2.20", "v2024.1", "2.20.1.0", "v2024.1.2.0").

    Returns:
        A tuple containing:
        - series_url_part (str): The part of the version used for the URL (e.g., "v2.20", "v2024.1").
                                 Always starts with 'v'.
        - specific_version_tag (Optional[str]): The full version tag if a specific
                                                 version was provided (e.g., "v2.20.1.0", "v2024.1.2.0"),
                                                 always starts with 'v'. Otherwise None.
    Raises:
        ValueError: If the input string format is unrecognized.
    """
    if not version_or_series:
        raise ValueError("Input version_or_series cannot be empty.")

    normalized_input = version_or_series.lstrip('vV ')
    parts = normalized_input.split('.')

    if len(parts) < 2:
        raise ValueError(
            f"Invalid version or series format: '{version_or_series}'. "
            "Expected at least major.minor (e.g., '2.20', '2024.1')."
        )

    series_url_part = f"v{parts[0]}.{parts[1]}"
    specific_version_tag: Optional[str] = None

    if len(parts) > 2:
        # Ensure specific_version_tag always starts with 'v' for consistency with HTML IDs
        specific_version_tag = f"v{normalized_input}"

    return series_url_part, specific_version_tag


def _extract_specific_version_html_content(
    full_soup: BeautifulSoup,
    version_id_tag: str
) -> Optional[BeautifulSoup]:
    """
    Extracts the HTML content for a specific version ID from the full page soup.
    Content is extracted from the version's heading tag until the next heading
    of the same or higher level, or end of document.
    The version_id_tag is expected to be the 'id' attribute of the heading (e.g., "v2.20.1.0").
    """
    start_node = full_soup.find(id=version_id_tag)

    # Try finding by string if ID match fails (some older versions might not have perfect ID tags)
    if not start_node:
        normalized_text_to_find = version_id_tag.lstrip('v') # e.g., "2.20.1.0"
        # Look for h2 or h3 that contains this version string
        for header_tag_name in ['h2', 'h3', 'h4']:
            headers = full_soup.find_all(header_tag_name)
            for header in headers:
                if normalized_text_to_find in header.get_text(strip=True):
                    start_node = header
                    logger.debug(f"Found start node by text match for {version_id_tag}: <{start_node.name}> {header.get_text(strip=True)[:30]}")
                    break
            if start_node:
                break

    if not start_node or not isinstance(start_node, Tag):
        logger.warning(f"Could not find start node for version ID tag: {version_id_tag}")
        return None

    logger.debug(f"Found start node for {version_id_tag}: <{start_node.name}> id='{start_node.get('id', '')}'")

    content_elements = [start_node]

    try:
        start_node_level = int(start_node.name[1:]) if start_node.name.startswith('h') and len(start_node.name) > 1 and start_node.name[1:].isdigit() else 99
    except ValueError:
        start_node_level = 99

    for sibling in start_node.find_next_siblings():
        if isinstance(sibling, Tag) and sibling.name.startswith('h') and len(sibling.name) > 1 and sibling.name[1:].isdigit():
            try:
                sibling_level = int(sibling.name[1:])
                if sibling_level <= start_node_level:
                    logger.debug(f"Stopping at next header of same/higher level: <{sibling.name}>")
                    break
            except ValueError:
                pass # Sibling is not a standard h-tag name like h1, h2 etc.
        content_elements.append(sibling)

    if not content_elements:
        return None

    html_string_of_section = "".join(str(el) for el in content_elements)
    if not html_string_of_section.strip():
        logger.warning(f"Extracted HTML section for {version_id_tag} is empty string.")
        return None

    section_soup = BeautifulSoup(f"<div>{html_string_of_section}</div>", 'html.parser').div
    if not section_soup or not section_soup.contents: # Check if div is empty or parsing failed
        logger.warning(f"Failed to create valid soup from extracted HTML for {version_id_tag}.")
        return None

    logger.info(f"Successfully extracted HTML section for version ID '{version_id_tag}'.")
    return section_soup


def _filter_html_content(soup_to_filter: BeautifulSoup):
    """
    Modifies the BeautifulSoup object in-place to remove unwanted sections.
    """
    if not soup_to_filter:
        logger.warning("Attempted to filter None soup object.")
        return

    logger.debug("Applying HTML exclusion filters...")

    # 1. Remove "Third-party licenses" paragraphs
    for p_tag in soup_to_filter.find_all('p'):
        strong_tag = p_tag.find('strong')
        if strong_tag and 'Third-party licenses:' in strong_tag.get_text(strip=True, separator=" "):
            logger.trace(f"Decomposing third-party license paragraph: {p_tag.get_text(strip=True)[:100]}")
            p_tag.decompose()

    # 2. Remove "Downloads" H3 sections and their associated content (ULs, Docker P+DIV)
    for h3_download_tag in soup_to_filter.find_all(['h3', 'h4'], string=re.compile(r'Downloads', re.I)): # Could be H3 or H4
        logger.trace(f"Found 'Downloads' header: <{h3_download_tag.name}> {h3_download_tag.get_text(strip=True)}")

        elements_to_remove = [h3_download_tag]
        current_element = h3_download_tag

        while (current_element := current_element.find_next_sibling()):
            if not isinstance(current_element, Tag):
                continue

            # Stop if we hit another H2, H3 or H4 (likely next section or higher level)
            if current_element.name in ['h2', 'h3', 'h4']:
                break

            # Check for <ul class="nav yb-pills"> or any UL directly under Downloads
            if current_element.name == 'ul':
                if ('nav' in current_element.get('class', []) and \
                    'yb-pills' in current_element.get('class', [])) or \
                    (h3_download_tag.find_next_sibling() == current_element): # a generic ul right after
                    logger.trace(f"Adding downloads UL ({current_element.get('class', '')}) to removal list.")
                    elements_to_remove.append(current_element)
                    continue

            # Check for <p><strong>Docker:</strong></p>
            if current_element.name == 'p':
                strong_tag = current_element.find('strong')
                if strong_tag and 'Docker:' in strong_tag.get_text(strip=True, separator=" "):
                    logger.trace("Adding Docker P to removal list.")
                    elements_to_remove.append(current_element)
                    # Check for the subsequent <div class="highlight"> for Docker command
                    docker_code_div = current_element.find_next_sibling('div', class_='highlight')
                    if docker_code_div and docker_code_div.find_previous_sibling() == current_element:
                         logger.trace("Adding Docker code DIV to removal list.")
                         elements_to_remove.append(docker_code_div)
                    continue

            # Break if it's not one of the known subsequent elements for downloads.
            # This means we only grab ULs and Docker P/DIVs immediately following the H3.
            if not (current_element.name == 'ul' or current_element.name == 'p' or current_element.name == 'div'):
                 break

        for el in reversed(elements_to_remove):
            el.decompose()

    # Independent pass for any remaining <p><strong>Docker:</strong></p> that weren't under a Downloads H3/H4
    for p_tag in soup_to_filter.find_all('p'):
        strong_tag = p_tag.find('strong')
        if strong_tag and 'Docker:' in strong_tag.get_text(strip=True, separator=" "):
            # Check if it was already decomposed by being part of a downloads section
            if not p_tag.parent: continue

            logger.trace(f"Found standalone Docker P: {p_tag.get_text(strip=True)[:50]}")
            docker_code_div = p_tag.find_next_sibling('div', class_='highlight')
            if docker_code_div and docker_code_div.find_previous_sibling() == p_tag:
                logger.trace("Decomposing standalone Docker code div.")
                docker_code_div.decompose()
            p_tag.decompose()

    logger.debug("Finished applying HTML exclusion filters.")


def fetch_yugabytedb_version_notes(version_or_series: str) -> Optional[str]:
    """
    Fetches YugabyteDB release notes using requests, processes HTML with BeautifulSoup,
    and converts to LLM-friendly Markdown using crawl4ai's DefaultMarkdownGenerator.

    Args:
        version_or_series: The YugabyteDB version or series string
                           (e.g., "2.20", "v2024.1", "2.20.1.0").

    Returns:
        An LLM-optimized Markdown string of the release notes, or None if fetching/processing fails.
    """
    try:
        series_url_part, specific_version_tag = _parse_input_to_url_parts(version_or_series)
    except ValueError as e:
        logger.error(f"Error parsing input '{version_or_series}': {e}")
        return None

    target_url = f"https://docs.yugabyte.com/preview/releases/ybdb-releases/{series_url_part}/"
    logger.info(f"Fetching release notes from URL: {target_url}")
    logger.info(f"Targeting series: {series_url_part}, specific version HTML ID: {specific_version_tag or 'N/A'}")

    try:
        response = requests.get(target_url, timeout=15) # Increased timeout slightly
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL {target_url}: {e}")
        return None

    full_page_soup = BeautifulSoup(response.content, 'html.parser')

    # This will be the soup object that gets filtered and converted
    soup_to_process = full_page_soup

    if specific_version_tag:
        logger.info(f"Attempting to extract HTML section for version ID: '{specific_version_tag}'.")
        # specific_version_tag from _parse_input_to_url_parts already starts with 'v'
        extracted_section_soup = _extract_specific_version_html_content(full_page_soup, specific_version_tag)
        if extracted_section_soup:
            soup_to_process = extracted_section_soup # Process only the extracted section
            logger.info(f"Successfully created soup for specific version section '{specific_version_tag}'.")
        else:
            logger.warning(
                f"Could not extract specific HTML section for version ID '{specific_version_tag}'. "
                f"Proceeding with filtering on the full page content for series '{series_url_part}'. "
                f"This may not be the desired output for a specific version query."
            )
            # soup_to_process remains full_page_soup

    _filter_html_content(soup_to_process) # Modifies soup_to_process in-place

    processed_html_string = str(soup_to_process)

    # Check if the soup became effectively empty (e.g. only "<div></div>" or similar)
    # A simple check for significant content:
    if len(re.sub(r'<[^>]+>', '', processed_html_string).strip()) < 50 : # Less than 50 chars of text content
        logger.warning(f"HTML content for '{version_or_series}' became sparse after processing. URL: {target_url}")
        # Potentially return None if this is considered an error.
        # For now, we'll let it convert, might result in empty/minimal markdown.
        if not re.sub(r'<[^>]+>', '', processed_html_string).strip(): # Truly empty
             logger.error(f"HTML content for '{version_or_series}' is effectively empty. Returning None.")
             return None


    # Pruning - removing unwanted contents
    #prune_filter = PruningContentFilter(
    #    threshold=0.5,
    #    threshold_type="fixed",
    #    min_word_threshold=10
    #)
    #md_generator = DefaultMarkdownGenerator(content_filter=prune_filter)
    #config = CrawlerRunConfig(markdown_generator=md_generator)

    # BM25 - Selection of relevant chunks from the whole data
    bm25_filter = BM25ContentFilter(
        user_query="health benefits fruit",
        bm25_threshold=1.2
    )
    md_generator = DefaultMarkdownGenerator(content_filter=bm25_filter)
    markdown = md_generator.generate_markdown(processed_html_string)

    #markdown = re.sub(r"\n{3,}", "\n\n", markdown).strip()

    if not markdown:
        logger.warning(f"Markdown conversion resulted in empty content for '{version_or_series}'. URL: {target_url}")
        return None

    logger.info(f"Finished processing release notes for '{version_or_series}'.")
    return {"release_notes": markdown.markdown_with_citations}

if __name__ == "__main__":
    import sys
    logger.remove()
    # Use "TRACE" for most detailed BeautifulSoup/filter logs
    # Use "DEBUG" for general flow and extraction info
    # Use "INFO" for high-level results
    logger.add(sys.stderr, level="DEBUG")

    versions_to_test = [
        "v2.20.3.0",       # Specific patch, YB docs ID: v2.20.3.0
        "2024.2.1.0",      # Specific patch, YB docs ID: v2024.2.1.0
        "v2.18",           # Series only
        "2024.1",          # Series only
        "2.16.3.0",        # Specific patch that might have "Downloads" section
        # "v2.14.2.0",     # Older specific version for structure check
        # "v2.12.11.0",
        "unsupported.version",
        "v2.999.0.0"       # Non-existent version
    ]

    for ver_str in versions_to_test:
        print(f"\n--- Testing: {ver_str} ---")
        notes = fetch_yugabytedb_version_notes(ver_str)
        if notes:
            print(f"Markdown for {ver_str} (first 700 chars):\n{notes}")
            #print(f"Markdown for {ver_str} (first 700 chars):\n{notes[:700]}...")
            # print(f"\nFull Markdown for {ver_str}:\n{notes}")
        else:
            print(f"No notes returned or notes were empty for {ver_str}.")
        print("--- End Test ---")
