# yugabytedb_release_mcp_server/src/yugabytedb_cve_fetcher.py
"""
Fetches Common Vulnerabilities and Exposures (CVEs) for YugabyteDB
from the National Vulnerability Database (NVD) API v2.0.

This module requires the 'requests', 'packaging', and 'loguru' libraries.
Install them using: pip install requests packaging loguru
"""

import dataclasses
import sys
import time
from typing import Dict, List, Optional, Tuple, Any

import requests
from loguru import logger
from packaging import version as pkg_version

from common_utils import _normalize_version_string


@dataclasses.dataclass
class YugabyteDbCveInfo:
    """Holds structured information about a specific CVE affecting YugabyteDB."""
    cve_id: str
    description: str
    cvss_v3_score: Optional[float]
    cvss_v3_severity: Optional[str]
    affected_info: str # Summary of affected YugabyteDB versions/ranges from NVD data
    published_date: str
    last_modified_date: str
    url: str

# --- NVD API Constants ---
NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD recommends max 2000 results per page for API v2.0
RESULTS_PER_PAGE: int = 2000
# NVD Rate Limits (as of early 2024):
# - Without API key: ~10 requests per rolling 60-second window (6s delay)
# - With API key: ~100 requests per rolling 60-second window (0.6s delay)
REQUEST_DELAY_SECONDS_NO_KEY: float = 6.0
REQUEST_DELAY_SECONDS_WITH_KEY: float = 0.6
# Target CPE prefix for YugabyteDB application
YUGABYTEDB_CPE_PREFIX: str = "cpe:2.3:a:yugabyte:yugabytedb:"
# Keyword for searching if CPE is not reliable enough
YUGABYTEDB_KEYWORD: str = "YugabyteDB"


def _parse_version(v_str: Optional[str]) -> Optional[pkg_version.Version]:
    """
    Safely parse a version string using packaging.version.
    Handles potential build metadata or other suffixes found in NVD data.
    Returns None if parsing fails.
    """
    if not v_str:
        return None
    try:
        # Clean common suffixes before parsing
        cleaned_str = v_str.split('+')[0].split('-')[0]
        return pkg_version.parse(cleaned_str)
    except pkg_version.InvalidVersion:
        logger.trace(f"Could not parse version string: {v_str}")
        return None

def _check_version_affected_by_cpe_match(
    target_version: Optional[pkg_version.Version],
    target_series_prefix: Optional[str],
    cpe_match: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Checks a single NVD cpeMatch object against the target version/series.

    Args:
        target_version: The parsed specific target version.
        target_series_prefix: The target series prefix (e.g., "2.20.").
        cpe_match: A dictionary representing the cpeMatch object from NVD.

    Returns:
        A tuple: (is_affected_by_this_rule, summary_string_for_this_rule)
    """
    if not cpe_match.get('vulnerable', False):
        return False, "Rule indicates non-vulnerable"

    criteria = cpe_match.get('criteria', '')
    if not criteria.startswith(YUGABYTEDB_CPE_PREFIX):
        return False, "Rule not for YugabyteDB application CPE"

    # Extract version from CPE criteria string itself, if specific
    parts = criteria.split(':')
    cpe_version_str: Optional[str] = None
    if len(parts) > 5 and parts[5] != '*' and parts[5]:
        cpe_version_str = parts[5]
    cpe_version = _parse_version(cpe_version_str)

    # Extract version range specifiers
    v_start_inc = cpe_match.get('versionStartIncluding')
    v_start_exc = cpe_match.get('versionStartExcluding')
    v_end_inc = cpe_match.get('versionEndIncluding')
    v_end_exc = cpe_match.get('versionEndExcluding')

    parsed_start_inc = _parse_version(v_start_inc)
    parsed_start_exc = _parse_version(v_start_exc)
    parsed_end_inc = _parse_version(v_end_inc)
    parsed_end_exc = _parse_version(v_end_exc)

    # --- Build summary string for this rule ---
    summary_parts = []
    if cpe_version_str:
        summary_parts.append(f"version {cpe_version_str}")
    range_parts = []
    if v_start_inc: range_parts.append(f">= {v_start_inc}")
    if v_start_exc: range_parts.append(f"> {v_start_exc}")
    if v_end_inc: range_parts.append(f"<= {v_end_inc}")
    if v_end_exc: range_parts.append(f"< {v_end_exc}")
    if range_parts:
        summary_parts.append(f"in range [{', '.join(range_parts)}]")

    rule_summary = " ".join(summary_parts) if summary_parts else "Unspecified version/range"

    # --- Check if target matches this rule ---
    if target_version is None and target_series_prefix is None:
        # If no target specified, any vulnerable YB rule means the CVE is relevant
        return True, rule_summary

    match_found = False
    # 1. Specific Version Check
    if target_version:
        # Case 1.1: Exact match in CPE criteria (and no ranges specified)
        if cpe_version and not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
            if target_version == cpe_version:
                match_found = True
        # Case 1.2: Check if target version falls within specified ranges
        elif any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
            in_range = True
            # Apply range checks (careful with None checks)
            if parsed_start_inc and not (target_version >= parsed_start_inc): in_range = False
            if parsed_start_exc and not (target_version > parsed_start_exc): in_range = False
            if parsed_end_inc and not (target_version <= parsed_end_inc): in_range = False
            if parsed_end_exc and not (target_version < parsed_end_exc): in_range = False
            if in_range:
                match_found = True

    # 2. Series Check (less precise, heuristic)
    elif target_series_prefix:
        # Check if the series *could* be involved based on rule boundaries or exact CPE version
        # Heuristic: Check if any version mentioned starts with the target series prefix.
        versions_in_rule = [
            _normalize_version_string(v) for v in
            [cpe_version_str, v_start_inc, v_start_exc, v_end_inc, v_end_exc] if v
        ]
        if any(norm_v and norm_v.startswith(target_series_prefix) for norm_v in versions_in_rule):
             match_found = True
        # Additional check: If it's a simple exact version rule, does its series match?
        elif cpe_version_str and not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
             norm_cpe_v = _normalize_version_string(cpe_version_str)
             if norm_cpe_v and norm_cpe_v.startswith(target_series_prefix):
                 match_found = True
        # Note: More complex range checks for series (e.g., series fully within range) are possible but omitted for simplicity.

    return match_found, rule_summary


def _process_nvd_configurations(
    target_version: Optional[pkg_version.Version],
    target_series_prefix: Optional[str],
    configurations: List[Dict[str, Any]]
) -> Tuple[bool, str]:
    """
    Processes the 'configurations' list from an NVD CVE item to determine
    if the target version/series is affected and provide a summary.

    Args:
        target_version: Parsed specific target version.
        target_series_prefix: Target series prefix (e.g., "2.20.").
        configurations: The 'configurations' list from NVD.

    Returns:
        A tuple: (is_potentially_affected, consolidated_affected_info_summary)
    """
    if not configurations:
        # NVD guidance is often unclear here. Could mean all versions, or version irrelevant.
        # We'll assume it's potentially relevant if no target, but doesn't match a specific target.
        is_relevant = target_version is None and target_series_prefix is None
        return is_relevant, "N/A (No configuration data provided by NVD)"

    affected_summaries: List[str] = []
    potentially_affected = False # Is the target version/series affected?
    found_yugabyte_rule = False # Did we find any YB-specific rule?

    try:
        # NVD configurations can have complex logical structures (AND/OR nodes).
        # We simplify by checking all cpeMatch entries across all nodes.
        # This usually approximates an OR condition for matching.
        nodes_to_process = []
        for cfg in configurations:
             nodes_to_process.extend(cfg.get('nodes', []))

        processed_nodes = 0
        while processed_nodes < len(nodes_to_process):
             node = nodes_to_process[processed_nodes]
             processed_nodes += 1

             # Process cpeMatch in the current node
             for cpe_match in node.get('cpeMatch', []):
                 match_found, rule_summary = _check_version_affected_by_cpe_match(
                     target_version, target_series_prefix, cpe_match
                 )
                 # Only add summary if it's a relevant YB rule
                 if rule_summary != "Rule not for YugabyteDB application CPE":
                     found_yugabyte_rule = True
                     if rule_summary != "Rule indicates non-vulnerable":
                         affected_summaries.append(rule_summary)
                         if match_found:
                              potentially_affected = True

             # Add children nodes for processing (recursive-like iteration)
             nodes_to_process.extend(node.get('children', []))

    except Exception as e:
        logger.warning(f"Error processing NVD configurations: {e}. Filtering may be incomplete.")
        # Fallback based on target presence
        summary = f"Error processing NVD config: {e}"
        if target_version is not None or target_series_prefix is not None:
            return False, summary # Error means we can't confirm affect on target
        else:
            return True, summary # Error means we can't rule it out for general search

    unique_summaries = sorted(list(set(s for s in affected_summaries if s)))
    final_summary = "; ".join(unique_summaries) if unique_summaries else "N/A"

    if not found_yugabyte_rule:
         final_summary = "N/A (No specific YugabyteDB configuration found)"
         potentially_affected = False # Cannot affect if no rule found

    # If no target specified, return True if *any* relevant YB rule was found.
    # If target specified, return the potentially_affected flag derived from matching rules.
    if target_version is None and target_series_prefix is None:
         return found_yugabyte_rule, final_summary
    else:
         return potentially_affected, final_summary


def fetch_yugabytedb_cves(
    target_version_or_series: Optional[str] = None,
    api_key: Optional[str] = None
) -> List[YugabyteDbCveInfo]:
    """
    Fetches YugabyteDB CVE information from the NVD API, optionally filtering
    by a specific version or series.

    Recommends using an NVD API key for better rate limits.

    Args:
        target_version_or_series: An optional string representing the specific
            YugabyteDB version or series to filter CVEs for.
            Examples: "v2.20", "2.18", "2024.1", "2.14.2.0".
            If None, retrieves all CVEs potentially related to YugabyteDB.
        api_key: An optional NVD API key. See: https://nvd.nist.gov/developers/request-an-api-key

    Returns:
        A list of `YugabyteDbCveInfo` objects matching the criteria. Returns
        an empty list if no relevant CVEs are found or if a critical error occurs.
    """
    found_cves: List[YugabyteDbCveInfo] = []
    start_index = 0
    total_results_available = -1 # Use -1 to indicate we don't know yet
    processed_results_count = 0
    request_delay = REQUEST_DELAY_SECONDS_WITH_KEY if api_key else REQUEST_DELAY_SECONDS_NO_KEY

    # Normalize target and determine if it's a specific version or just a series
    norm_target = _normalize_version_string(target_version_or_series)
    target_version: Optional[pkg_version.Version] = None
    target_series_prefix: Optional[str] = None
    if norm_target:
        parts = norm_target.split('.')
        if len(parts) > 2: # Assume specific version if patch/build present
            target_version = _parse_version(norm_target)
            if target_version:
                # Store prefix for series matching as well
                target_series_prefix = f"{target_version.major}.{target_version.minor}."
                logger.info(f"Targeting specific version: {norm_target} (Parsed: {target_version})")
            else:
                 logger.warning(f"Could not parse '{norm_target}' as a specific version. Treating as series.")
                 target_series_prefix = f"{parts[0]}.{parts[1]}." # Attempt series
                 logger.info(f"Targeting series: {parts[0]}.{parts[1]}")

        elif len(parts) == 2: # Assume series if only major.minor
            target_series_prefix = f"{norm_target}."
            logger.info(f"Targeting series: {norm_target}")
        else:
            logger.warning(f"Input '{target_version_or_series}' format unclear. Treating as keyword only.")
            # No version/series info extracted for filtering

    while True:
        params = {
                    # Using keyword search is broader; CPE might miss some if NVD data is inconsistent
                    "keywordSearch": YUGABYTEDB_KEYWORD,
                    # Removed "keywordExactMatch": False, as the parameter's presence implies True,
                    # and its absence implies False (the desired default).
                    # Consider adding "cpeName": YUGABYTEDB_CPE_PREFIX without version for more focus?
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index
                }
        headers = {"apiKey": api_key} if api_key else {}

        target_display = f"'{target_version_or_series}'" if target_version_or_series else "'All'"
        logger.debug(f"Fetching NVD data page: startIndex={start_index}, target={target_display}")

        try:
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=30) # Increased timeout
            response.raise_for_status() # Raises HTTPError for 4xx/5xx responses

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            current_results_count = len(vulnerabilities)
            if total_results_available == -1: # First request
                 total_results_available = data.get('totalResults', 0)
            processed_results_count += current_results_count

            if not vulnerabilities:
                logger.debug("No more vulnerabilities returned in this batch or total.")
                break

            logger.debug(f"Received {current_results_count} CVEs. Total available: {total_results_available}. Processed so far: {processed_results_count}")

            for item in vulnerabilities:
                cve_data = item.get('cve')
                if not cve_data:
                    logger.trace("Skipping item with missing 'cve' data.")
                    continue

                cve_id = cve_data.get('id', 'Unknown ID')

                # Extract primary English description
                description = "No description available."
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', description)
                        break

                # Extract CVSS v3.1 or v3.0 score/severity (prefer v3.1)
                cvss_v3_score: Optional[float] = None
                cvss_v3_severity: Optional[str] = None
                metrics = cve_data.get('metrics', {})
                cvss_metrics = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
                if cvss_metrics:
                    cvss_data = cvss_metrics[0].get('cvssData', {}) # Use first available
                    cvss_v3_score = cvss_data.get('baseScore')
                    cvss_v3_severity = cvss_data.get('baseSeverity')

                published_date = cve_data.get('published', 'N/A')
                last_modified_date = cve_data.get('lastModified', 'N/A')
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # Check if this CVE affects the target based on configurations
                configurations = cve_data.get('configurations', [])
                is_affected, affected_info_summary = _process_nvd_configurations(
                    target_version, target_series_prefix, configurations
                )

                # Add CVE if it's potentially affected based on the check
                if is_affected:
                    logger.debug(f"Adding CVE {cve_id} matching target {target_display}. Affected info: {affected_info_summary}")
                    found_cves.append(YugabyteDbCveInfo(
                        cve_id=cve_id,
                        description=description,
                        cvss_v3_score=cvss_v3_score,
                        cvss_v3_severity=cvss_v3_severity,
                        affected_info=affected_info_summary,
                        published_date=published_date,
                        last_modified_date=last_modified_date,
                        url=cve_url
                    ))
                else:
                    logger.trace(f"Skipping CVE {cve_id} (does not match target {target_display} or no relevant YB config). Reason: {affected_info_summary}")

            # Prepare for the next page
            start_index += RESULTS_PER_PAGE
            if start_index >= total_results_available:
                logger.debug(f"Processed {processed_results_count} results, reaching total available {total_results_available}.")
                break

            # Respect NVD rate limits before next request
            logger.trace(f"Waiting {request_delay:.1f} seconds before next NVD request...")
            time.sleep(request_delay)

        except requests.exceptions.Timeout:
             logger.error(f"Timeout occurred while fetching NVD data (startIndex={start_index}).")
             break # Stop fetching on timeout
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching NVD data (startIndex={start_index}): {e}")
            # Decide if retry logic is needed; for now, stop on error.
            break
        except Exception as e: # Catch other potential errors (e.g., JSON decoding)
            logger.error(f"An unexpected error occurred during NVD processing (startIndex={start_index}): {e}", exc_info=True)
            break

    logger.info(f"Finished NVD query for target {target_display}. Found {len(found_cves)} relevant CVEs.")
    # Sort CVEs by ID for consistent output
    found_cves.sort(key=lambda cve: cve.cve_id)
    return found_cves


if __name__ == "__main__":
    # Configure logging level (e.g., INFO for summary, DEBUG for details)
    logger.remove()
    logger.add(sys.stderr, level="INFO")

    # --- NVD API Key (Optional but Recommended) ---
    # Request a key from: https://nvd.nist.gov/developers/request-an-api-key
    # Set the key here or via an environment variable for better practice.
    NVD_API_KEY: Optional[str] = None  # Replace with your key string, or keep as None
    # Example using environment variable (recommended):
    # import os
    # NVD_API_KEY = os.environ.get("NVD_API_KEY")

    if NVD_API_KEY:
        logger.info("Using NVD API Key (higher rate limit).")
    else:
        logger.warning("No NVD API Key provided. Using lower rate limits (~10 req/min). Fetching may be slow.")

    # --- Test Cases ---
    test_targets: List[Optional[str]] = [
        "2.18",             # Series
        "v2.20",            # Series with 'v' prefix
        "2.18.1.0",         # Specific version
        "v2.16.3.0",        # Specific version with 'v'
        "2024.1",           # Series (new format)
        "2024.1.0.0",       # Specific version (new format)
        "2.18.5.0",         # Test a specific patch that might exist
        "99.99",            # Non-existent series
        "1.0.0.0",           # Unlikely version
        None,  # All CVEs mentioning YugabyteDB
    ]

    for target in test_targets:
        target_display = f"'{target}'" if target else "'All'"
        logger.info(f"\n--- Fetching CVEs for YugabyteDB target: {target_display} ---")

        cves: List[YugabyteDbCveInfo] = fetch_yugabytedb_cves(
            target_version_or_series=target,
            api_key=NVD_API_KEY
        )

        if cves:
            logger.info(f"Found {len(cves)} CVE(s) potentially affecting target {target_display}:")
            for cve in cves:
                score_sev = f"{cve.cvss_v3_score} ({cve.cvss_v3_severity})" if cve.cvss_v3_score else "N/A"
                logger.info(
                    f"  - ID: {cve.cve_id}\n"
                    f"    Score/Severity (CVSSv3): {score_sev}\n"
                    f"    Published: {cve.published_date}\n"
                    f"    Affected Info (from NVD): {cve.affected_info}\n"
                    # f"    Description: {cve.description[:150]}...\n" # Optionally show description
                    f"    URL: {cve.url}"
                )
        else:
            logger.info(f"No relevant CVEs found matching target {target_display} based on NVD data.")
        logger.info(f"--- Finished test for {target_display} ---")
