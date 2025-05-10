# yugabytedb_release_mcp_server/src/yugabytedb_release_notes_fetcher.py
"""Fetches and parses YugabyteDB release notes from documentation.

This module provides utilities to retrieve release notes as LLM-optimized Markdown
for specific YugabyteDB versions or entire release series. It primarily uses the
official YugabyteDB releases RSS feed and the corresponding release series pages
on the documentation website, processed by the crawl4ai library.

This module requires 'requests', 'feedparser', 'loguru', and 'crawl4ai'.
Install them using:
`pip install requests feedparser loguru crawl4ai`
"""

import asyncio
import re
import sys
from typing import Optional

import feedparser
import requests
from crawl4ai import AsyncWebCrawler # type: ignore
from loguru import logger

from src.common_utils import _normalize_version_string


def _filter_llm_markdown(markdown_content: str) -> str:
    """
    Filters out unwanted sections from the LLM-optimized Markdown.

    Args:
        markdown_content: The raw Markdown string.

    Returns:
        The filtered Markdown string.
    """
    logger.debug("Starting Markdown filtering.")
    filtered_content = markdown_content

    # Regex patterns for sections to remove:
    patterns_to_remove = [
        # Docker section: Matches "### Docker", optional link, and optional code block
        re.compile(r"^### Docker\s*(?:\[.*?\]\(.*?\))?\s*\n(?:^```[\s\S]*?^```\s*)?", re.MULTILINE),
        # Third-party licenses: Matches the bolded text and everything until the next significant break
        re.compile(r"^\*\*Third-party licenses:\*\*[\s\S]*?(?=\n##|\n\n---|\n\n\n\n|$)", re.MULTILINE),
        # Downloads section: Matches "### Downloads", optional link, and potentially content until next heading or significant break
        re.compile(r"^### Downloads\s*(?:\[.*?\]\(.*?\))?[\s\S]*?(?=\n##|\n\n---|\n\n\n\n|$)", re.MULTILINE),
        # "On this page" navigation element
        re.compile(r"^!\[On this page\]\(https://docs\.yugabyte\.com/icons/list-icon\.svg\) On this page\s*\n?", re.MULTILINE),
        # Remove "Edit this page" links often found at the bottom
        re.compile(r"\[Edit this page\]\(.*?\)\s*\n?", re.MULTILINE),
        # Remove "Found an issue" or "Suggest an edit" links
        re.compile(r"\[Found an issue\? Suggest an edit\.\]\(.*?\)\s*\n?", re.MULTILINE),
        # Generic pattern for "Learn more" or "Read more" sections that might be just links or short paragraphs
        re.compile(r"^(?:##?#?#?\s*)?(?:Learn more|Read more|Further reading|Next steps)[\s\S]*?(?=\n##|\n\n---|\n\n\n\n|$)", re.MULTILINE | re.IGNORECASE),
        # Remove multiple blank lines to make it more compact
        re.compile(r"\n{3,}", re.MULTILINE),
    ]

    for i, pattern in enumerate(patterns_to_remove):
        prev_len = len(filtered_content)
        filtered_content = pattern.sub("", filtered_content)
        if len(filtered_content) < prev_len:
            logger.debug(f"Applied filter pattern {i+1}, removed {prev_len - len(filtered_content)} characters.")
        else:
            logger.debug(f"Filter pattern {i+1} did not match.")

    # Replace multiple newlines (more than 2) with just two to clean up.
    filtered_content = re.sub(r'\n{3,}', '\n\n', filtered_content)
    logger.debug("Markdown filtering completed.")
    return filtered_content.strip()


def _get_series_page_url_from_rss(
    rss_feed_url: str, target_series: str
) -> Optional[str]:
    """Finds the URL for a specific release series page from the RSS feed.

    Args:
        rss_feed_url: URL of the main YugabyteDB releases RSS feed.
        target_series: The target series (e.g., "2.20", "2024.1", "v2.18").
                       Normalization (like adding 'v') is handled internally.

    Returns:
        The URL of the series page if found, otherwise None.
    """
    logger.debug(f"Fetching RSS feed from: {rss_feed_url} for series: {target_series}")
    try:
        feed = feedparser.parse(rss_feed_url)
    except Exception as e:
        logger.error(f"Exception fetching or parsing RSS feed {rss_feed_url}: {e}")
        return None

    if feed.bozo:
        logger.warning(
            f"Error parsing RSS feed {rss_feed_url} (bozo set): {feed.bozo_exception}"
        )
        if not feed.entries:
            return None

    normalized_target_series_input = _normalize_version_string(target_series)

    for entry in feed.entries:
        link = entry.get("link", "")
        title = entry.get("title", "")

        link_last_segment = link.strip("/").split("/")[-1]
        normalized_title_series = _normalize_version_string(title.replace("YugabyteDB", "").strip())

        if _normalize_version_string(link_last_segment) == normalized_target_series_input or \
           normalized_title_series == normalized_target_series_input:
            logger.info(f"Found series page URL for '{target_series}' via RSS: {link}")
            return link

    logger.warning(
        f"Series page URL for '{target_series}' not found directly in RSS feed {rss_feed_url}."
    )
    return None


async def fetch_yugabytedb_version_notes(
    target_version_or_series: str,
    rss_feed_url: str = "https://docs.yugabyte.com/preview/releases/ybdb-releases/index.xml",
) -> Optional[str]:
    """Fetches release notes as LLM-optimized Markdown for a YugabyteDB version or series.

    This function is asynchronous and uses AsyncWebCrawler.

    Args:
        target_version_or_series: YugabyteDB version (e.g., "2.20.1.0", "v2.25.0.0-b123")
                                  or series (e.g., "v2.20", "2024.1") to fetch notes for.
        rss_feed_url: URL of the main YugabyteDB releases RSS feed.

    Returns:
        A string containing the LLM-optimized and filtered Markdown of the release notes,
        or None if the notes cannot be fetched or processed.
    """
    normalized_target = _normalize_version_string(target_version_or_series)
    target_parts = normalized_target.split(".")

    target_series_normalized: str
    # target_minor_spec: Optional[str] = None # Keep for potential future use with selector

    if len(target_parts) >= 2:
        target_series_normalized = f"{target_parts[0]}.{target_parts[1]}"
        # if len(target_parts) > 2 or "-b" in normalized_target: # If specific minor version
        #     target_minor_spec = normalized_target
    else:
        logger.error(f"Invalid target_version_or_series: '{target_version_or_series}'. Must be at least X.Y or vX.Y format.")
        return None

    series_for_rss = target_series_normalized
    if target_series_normalized[0].isdigit():
        series_for_rss = f"v{target_series_normalized}"

    series_page_url = _get_series_page_url_from_rss(rss_feed_url, series_for_rss)

    if not series_page_url:
        logger.warning(f"Series '{series_for_rss}' not found in RSS. Attempting direct URL construction.")
        constructed_series_segment = series_for_rss
        if target_series_normalized[0].isdigit() and not constructed_series_segment.startswith('v'):
            constructed_series_segment = f"v{target_series_normalized}"

        series_page_url = f"https://docs.yugabyte.com/preview/releases/ybdb-releases/{constructed_series_segment}/"
        logger.info(f"Trying fallback URL: {series_page_url}")
        try:
            response = requests.head(series_page_url, timeout=5, allow_redirects=True)
            if response.status_code != 200:
                logger.error(f"Fallback URL {series_page_url} invalid (status: {response.status_code}). Cannot fetch notes.")
                return None
            logger.info(f"Fallback URL {series_page_url} seems valid.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking fallback URL {series_page_url}: {e}")
            return None

    url_to_crawl = series_page_url
    # css_selector_for_minor_version_if_any: Optional[str] = None
    # if target_minor_spec:
    #     anchor_version_part = target_minor_spec.replace(".", "-").replace("-b", "b") # Handle build numbers in anchors
    #     css_selector_for_minor_version_if_any = f"#version-{anchor_version_part}"
    #     logger.info(f"Targeting specific minor version. URL: {url_to_crawl}, Selector for context: {css_selector_for_minor_version_if_any}")
    # else:
    #     logger.info(f"Targeting entire series page: {url_to_crawl}")

    try:
        async with AsyncWebCrawler(
            engine_config={"engine": "readability"},
            parser_config={"parser": "markdown", "llm_optimize": True}
        ) as crawler:
            logger.info(f"Crawling page {url_to_crawl} for target '{target_version_or_series}'.")
            # For now, crawl the entire page. Specific minor version content needs to be identified by the LLM.
            result = await crawler.arun(url=url_to_crawl)

            if result and result.markdown:
                logger.info(f"Successfully crawled. Length before filtering: {len(result.markdown)}")
                filtered_markdown = _filter_llm_markdown(result.markdown)
                logger.info(f"Markdown filtered. Length after filtering: {len(filtered_markdown)}")
                return filtered_markdown
            else:
                logger.warning(f"crawl4ai (AsyncWebCrawler) did not return Markdown content for {url_to_crawl}")
                return None
    except ImportError:
        logger.error("crawl4ai library is not installed. Please install it with `pip install crawl4ai`.")
        return None
    except Exception as e:
        logger.error(f"Error during crawl4ai (AsyncWebCrawler) processing for {url_to_crawl}: {e}")
        return None


async def main_async():
    """Async main function to test the fetcher."""
    logger.remove()
    logger.add(sys.stderr, level="DEBUG") # Changed to DEBUG for more verbose test output

    versions_to_test = [
        "v2.20.1.0",
        "v2.20",
        "v2024.1.0.0",
        "v2024.1",
        "v2.25", # Preview series - often has Docker and Downloads
    ]

    for version_input in versions_to_test:
        logger.info(f"\n--- Fetching release notes Markdown for: {version_input} ---")
        markdown_output = await fetch_yugabytedb_version_notes(version_input)
        if markdown_output:
            logger.info(f"Successfully fetched Markdown for '{version_input}'. Length: {len(markdown_output)}")
            print("\n" + "="*80)
            print(f"FILTERED MARKDOWN for {version_input}:")
            # For testing, you might want to print more or all of it
            # print(markdown_output[:2000] + ("..." if len(markdown_output) > 2000 else ""))
            print(markdown_output) # Print all for verification during testing
            print("="*80 + "\n")
        else:
            logger.info(f"No Markdown release notes found for '{version_input}'.")

if __name__ == "__main__":
    asyncio.run(main_async())
