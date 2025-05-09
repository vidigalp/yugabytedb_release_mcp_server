# yugabytedb_release_mcp_server/tests/test_yugabytedb_site_utils.py
"""
Tests for yugabytedb_site_utils.py
"""

import pytest
import requests
from bs4 import BeautifulSoup, Tag
from loguru import logger

from yugabytedb_release_mcp_server.src.yugabytedb_site_utils import (
    YugabyteReleaseInfo,
    _parse_table,
    scrape_yugabytedb_release_info,
)


@pytest.fixture
def mock_requests_get(mocker):
    """Fixture to mock requests.get."""
    return mocker.patch("yugabytedb_release_mcp_server.src.yugabytedb_site_utils.requests.get")

# --- Helper Functions ---
def create_html_table(rows_html_list, include_tbody=True):
    """Helper to create a BeautifulSoup table Tag from list of row HTML strings."""
    table_content = "".join(rows_html_list)
    if include_tbody:
        full_html = f"<table><tbody>{table_content}</tbody></table>"
    else:
        full_html = f"<table>{table_content}</table>"
    soup = BeautifulSoup(full_html, "html.parser")
    return soup.find("table")

def mock_response_content(html_content, status_code=200):
    """Helper to create a mock response object."""
    mock_resp = requests.Response()
    mock_resp.status_code = status_code
    mock_resp._content = html_content.encode('utf-8')
    if status_code >= 400:
        mock_resp.reason = "Client Error" if 400 <= status_code < 500 else "Server Error"
        mock_resp.request = requests.Request('GET', 'http://mockurl.com').prepare() # for raise_for_status
    return mock_resp

# --- HTML Templates for Mocking ---
MOCK_URL = "https://fake-docs.yugabyte.com/releases/"

HTML_CONTENT_ACTIVE_RELEASES_MULTIPLE = """
<h2>Releases</h2>
<div class="wy-table-responsive">
    <table>
        <thead><tr><th>Series</th><th>Released</th><th>EOM</th><th>EOL</th></tr></thead>
        <tbody>
            <tr>
                <td><a href="v2024.2/">v2024.2</a> <span class="tag release lts">LTS</span></td>
                <td>Dec 9, 2024</td><td>Dec 9, 2026</td><td>Jun 9, 2027</td>
            </tr>
            <tr>
                <td><a href="v2024.1/">v2024.1</a> <span class="tag release sts">STS</span></td>
                <td>Jun 4, 2024</td><td>Sep 4, 2025</td><td>Mar 7, 2026</td>
            </tr>
            <tr>
                <td><a href="v2.20/">v2.20</a> <span class="tag release lts">LTS</span></td>
                <td>Nov 13, 2023</td><td>Nov 13, 2025</td><td>May 13, 2026</td>
            </tr>
            <tr>
                <td><a href="v2.25/">v2.25</a> Preview</td>
                <td>Jan 17, 2025</td><td>No support</td><td>n/a</td>
            </tr>
        </tbody>
    </table>
</div>
"""

HTML_CONTENT_EOL_RELEASES_MULTIPLE_FOR_TESTING = """
<h2>Releases at end of life (EOL)</h2>
<div class="wy-table-responsive">
    <table>
        <thead><tr><th>Series</th><th>Released</th><th>EOM</th><th>EOL</th></tr></thead>
        <tbody>
            <tr>
                <td><a href="v2.18/">v2.18</a> <span class="tag release sts">STS</span></td>
                <td>May 16, 2023</td><td>Aug 16, 2024</td><td>Feb 16, 2025</td>
            </tr>
            <tr>
                <td><a href="v2.16/">v2.16</a> <span class="tag release sts">STS</span></td>
                <td>Dec 14, 2022</td><td>Dec 14, 2023</td><td>Jun 14, 2024</td>
            </tr>
            <tr>
                <td><a href="v2.14/">v2.14</a> <span class="tag release lts">LTS</span></td>
                <td>Jul 14, 2022</td><td>Jul 14, 2024</td><td>Jan 14, 2025</td>
            </tr>
            <tr>
                <td><a href="v2.12/">v2.12</a> <span class="tag release sts">STS</span></td> <!-- Added STS for testability -->
                <td>Feb 22, 2022</td><td>Feb 22, 2023</td><td>Aug 22, 2023</td>
            </tr>
        </tbody>
    </table>
</div>
"""
FULL_HTML_CONTENT_MULTIPLE = f"<html><body>{HTML_CONTENT_ACTIVE_RELEASES_MULTIPLE}{HTML_CONTENT_EOL_RELEASES_MULTIPLE_FOR_TESTING}</body></html>"


# --- Tests for _parse_table (largely unchanged) ---

def test_parse_table_empty_tbody(caplog):
    table_html = "<table><tr><td>No tbody here</td></tr></table>"
    soup = BeautifulSoup(table_html, "html.parser")
    table_tag = soup.find("table")
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    results = _parse_table(table_tag, "Active")
    assert len(results) == 0
    assert "Table has no tbody. Skipping table." in caplog.text

def test_parse_table_row_with_insufficient_cells(caplog):
    rows_html = ["<tr><td>v2.20 LTS</td><td>Nov 13, 2023</td><td>Nov 13, 2025</td></tr>"]
    table = create_html_table(rows_html)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    results = _parse_table(table, "Active")
    assert len(results) == 0
    assert "Skipping row with insufficient cells" in caplog.text

def test_parse_table_valid_rows():
    rows_html = [
        "<tr><td><a href='vLTS/'>vLTS</a> <span class='tag release lts'>LTS</span></td><td>D1</td><td>D2</td><td>D3</td></tr>",
        "<tr><td><a href='vSTS/'>vSTS</a> <span class='tag release sts'>STS</span></td><td>D4</td><td>D5</td><td>D6</td></tr>",
        "<tr><td><a href='vPRE/'>vPRE</a> Preview</td><td>D7</td><td>No support</td><td>n/a</td></tr>",
    ]
    table = create_html_table(rows_html)
    results = _parse_table(table, "Active")
    assert len(results) == 3
    assert results[0] == YugabyteReleaseInfo("vLTS", "LTS", "D1", "D2", "D3", "Active")
    assert results[1] == YugabyteReleaseInfo("vSTS", "STS", "D4", "D5", "D6", "Active")
    assert results[2] == YugabyteReleaseInfo("vPRE", "PREVIEW", "D7", "No support", "n/a", "Active")

def test_parse_table_unknown_type_skipped(caplog):
    rows_html = ["<tr><td><a href='vX.Y/'>vX.Y</a> <span>OTHER</span></td><td>D1</td><td>D2</td><td>D3</td></tr>"]
    table = create_html_table(rows_html)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    results = _parse_table(table, "EOL")
    assert len(results) == 0
    assert "Could not determine release type for series 'vX.Y'. Skipping row." in caplog.text

def test_parse_table_series_name_extraction_no_link():
    rows_html = ["<tr><td>v2.23 Preview</td><td>Sep 13, 2024</td><td>n/a</td><td>n/a</td></tr>"]
    table = create_html_table(rows_html)
    results = _parse_table(table, "EOL")
    assert len(results) == 1
    assert results[0].series == "v2.23"
    assert results[0].type == "PREVIEW"


# --- Tests for scrape_yugabytedb_release_info ---

def test_scrape_all_releases_successful(mock_requests_get):
    """Test scraping all releases when no target_version_or_series is specified."""
    mock_requests_get.return_value = mock_response_content(FULL_HTML_CONTENT_MULTIPLE)
    results = scrape_yugabytedb_release_info(MOCK_URL, target_version_or_series=None)

    # 4 active releases from HTML_CONTENT_ACTIVE_RELEASES_MULTIPLE
    # 4 EOL releases from HTML_CONTENT_EOL_RELEASES_MULTIPLE_FOR_TESTING
    assert len(results) == 8
    mock_requests_get.assert_called_once_with(MOCK_URL, timeout=10)

    # Check a few samples
    assert any(r.series == "v2024.2" and r.status == "Active" for r in results)
    assert any(r.series == "v2.20" and r.status == "Active" for r in results)
    assert any(r.series == "v2.18" and r.status == "EOL" for r in results)
    assert any(r.series == "v2.12" and r.status == "EOL" and r.type == "STS" for r in results)


@pytest.mark.parametrize(
    "target_input, expected_series, expected_type, expected_status, expected_count",
    [
        ("v2.20", "v2.20", "LTS", "Active", 1),
        ("2.20", "v2.20", "LTS", "Active", 1), # Without 'v'
        ("v2024.1", "v2024.1", "STS", "Active", 1),
        ("2024.1.0.0", "v2024.1", "STS", "Active", 1), # Full version
        ("v2.18", "v2.18", "STS", "EOL", 1),
        ("2.18.1.0", "v2.18", "STS", "EOL", 1), # Full version EOL
        ("v2.16", "v2.16", "STS", "EOL", 1),
        ("2.16.3.0-b123", "v2.16", "STS", "EOL", 1), # Full version with build
        ("v2.25", "v2.25", "PREVIEW", "Active", 1), # Preview
        ("v2.12", "v2.12", "STS", "EOL", 1), # EOL with type added for testability
        ("vNonExistent", None, None, None, 0), # Non-existent series
        ("3.0", None, None, None, 0), # Non-existent series format
        ("  v2.20  ", "v2.20", "LTS", "Active", 1), # With whitespace
    ]
)
def test_scrape_with_filtering(mock_requests_get, caplog, target_input, expected_series, expected_type, expected_status, expected_count):
    mock_requests_get.return_value = mock_response_content(FULL_HTML_CONTENT_MULTIPLE)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")

    results = scrape_yugabytedb_release_info(MOCK_URL, target_version_or_series=target_input)

    assert len(results) == expected_count
    if expected_count > 0:
        assert results[0].series == expected_series
        assert results[0].type == expected_type
        assert results[0].status == expected_status
        assert f"Found match: Scraped series '{expected_series.lstrip('v')}' matches target series component" in caplog.text
    else:
        assert f"No release information found for target '{target_input}'" in caplog.text

def test_scrape_only_active_table_present(mock_requests_get, caplog):
    html_content = f"<html><body>{HTML_CONTENT_ACTIVE_RELEASES_MULTIPLE}</body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")

    results = scrape_yugabytedb_release_info(MOCK_URL) # No filter
    assert len(results) == 4 # Only active releases
    assert "'Releases at end of life (EOL)' header not found." in caplog.text

    # Test with filter for an active release
    results_filtered = scrape_yugabytedb_release_info(MOCK_URL, target_version_or_series="v2.20")
    assert len(results_filtered) == 1
    assert results_filtered[0].series == "v2.20"

def test_scrape_only_eol_table_present(mock_requests_get, caplog):
    html_content = f"<html><body>{HTML_CONTENT_EOL_RELEASES_MULTIPLE_FOR_TESTING}</body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")

    results = scrape_yugabytedb_release_info(MOCK_URL) # No filter
    assert len(results) == 4 # Only EOL releases
    assert "'Releases' header not found." in caplog.text

    # Test with filter for an EOL release
    results_filtered = scrape_yugabytedb_release_info(MOCK_URL, target_version_or_series="v2.14")
    assert len(results_filtered) == 1
    assert results_filtered[0].series == "v2.14"

def test_scrape_missing_active_header(mock_requests_get, caplog):
    html_content = f"<html><body>{HTML_CONTENT_EOL_RELEASES_MULTIPLE_FOR_TESTING}</body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    scrape_yugabytedb_release_info(MOCK_URL)
    assert "'Releases' header not found." in caplog.text

def test_scrape_missing_eol_header(mock_requests_get, caplog):
    html_content = f"<html><body>{HTML_CONTENT_ACTIVE_RELEASES_MULTIPLE}</body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    scrape_yugabytedb_release_info(MOCK_URL)
    assert "'Releases at end of life (EOL)' header not found." in caplog.text

def test_scrape_missing_active_table_after_header(mock_requests_get, caplog):
    html_content = f"<html><body><h2>Releases</h2><p>No table here</p>{HTML_CONTENT_EOL_RELEASES_MULTIPLE_FOR_TESTING}</body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    scrape_yugabytedb_release_info(MOCK_URL)
    assert "Active releases table not found after 'Releases' header." in caplog.text

def test_scrape_missing_eol_table_after_header(mock_requests_get, caplog):
    html_content = f"<html><body>{HTML_CONTENT_ACTIVE_RELEASES_MULTIPLE}<h2>Releases at end of life (EOL)</h2><p>No table here</p></body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    scrape_yugabytedb_release_info(MOCK_URL)
    assert "EOL releases table not found after 'Releases at end of life (EOL)' header." in caplog.text

def test_scrape_request_exception(mock_requests_get, caplog):
    mock_requests_get.side_effect = requests.exceptions.RequestException("Network error")
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    results = scrape_yugabytedb_release_info(MOCK_URL)
    assert len(results) == 0
    assert f"Error fetching URL {MOCK_URL}: Network error" in caplog.text

def test_scrape_http_error(mock_requests_get, caplog):
    mock_requests_get.return_value = mock_response_content("Error page", status_code=404)
    logger.enable("yugabytedb_release_mcp_server.src.yugabytedb_site_utils")
    results = scrape_yugabytedb_release_info(MOCK_URL)
    assert len(results) == 0
    assert f"Error fetching URL {MOCK_URL}: 404 Client Error" in caplog.text


def test_scrape_table_without_div_wrapper(mock_requests_get):
    active_table_no_div = """
    <h2>Releases</h2>
    <table><tbody><tr>
        <td><a href="vA.2/">vA.2</a> <span class="tag release sts">STS</span></td>
        <td>Feb 1, 2023</td><td>Feb 1, 2025</td><td>Feb 1, 2026</td>
    </tr></tbody></table>
    """
    eol_table_no_div = """
    <h2>Releases at end of life (EOL)</h2>
    <table><tbody><tr>
        <td><a href="vE.2/">vE.2</a> <span class="tag release lts">LTS</span></td>
        <td>Aug 1, 2020</td><td>Aug 1, 2021</td><td>Aug 1, 2022</td>
    </tr></tbody></table>
    """
    html_content = f"<html><body>{active_table_no_div}{eol_table_no_div}</body></html>"
    mock_requests_get.return_value = mock_response_content(html_content)
    results = scrape_yugabytedb_release_info(MOCK_URL)
    assert len(results) == 2
    assert results[0].series == "vA.2"
    assert results[1].series == "vE.2"
