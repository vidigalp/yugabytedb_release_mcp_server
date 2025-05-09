# YugabyteDB Release MCP Server

## Purpose

The YugabyteDB Release MCP (Multi-Context Provider) Server is designed to provide Large Language Models (LLMs) with contextual information related to YugabyteDB software releases. This enables LLMs to answer queries and generate content with up-to-date and accurate details about different YugabyteDB versions.

## Functionality

The MCP Server will initially provide the following information:

*   **Release Version (JSON):** Detailed information about specific YugabyteDB releases.
    *   `version`: The full version number, including build information if applicable (e.g., "2.25.1.0", "2.25.1.0-b381").
    *   `series`: The release series name as found in official documentation (e.g., "v2.14", "v2.20").
    *   `type`: The type of the release (e.g., PREVIEW, LTS, STS, NONE).
    *   `released`: The date when the version was officially released.
    *   `end_of_maintenance`: The date marking the end of the maintenance period for the version.
    *   `end_of_life`: The date marking the end of life (EOL) for the version.
    *   `status`: The current status of the release (e.g., ACTIVE, EOL).
*   **CVE List:** A list of Common Vulnerabilities and Exposures (CVEs) associated with YugabyteDB versions.
*   **Technical Advisories:** Access to technical advisories for specific versions (e.g., from [https://docs.yugabyte.com/preview/releases/techadvisories/](https://docs.yugabyte.com/preview/releases/techadvisories/)).
*   **Release Notes:** Links to or content from the official release notes for each version (e.g., [https://docs.yugabyte.com/preview/releases/ybdb-releases/v2.25/#change-log](https://docs.yugabyte.com/preview/releases/ybdb-releases/v2.25/#change-log)).

## Technical Stack

*   **Programming Language:** Python 3.12
*   **Package Manager:** `uv`

## Getting Started

(Details on setting up the virtual environment, installing dependencies, and running the server will be added here.)

### Prerequisites

*   Python 3.12
*   `uv` package manager

### Installation (Example)

```bash
# Clone the repository
git clone <repository-url>
cd yugabytedb_release_mcp_server

# Create a virtual environment and install dependencies using uv
uv venv
uv pip install -r requirements.txt # Assuming a requirements.txt file
```

## Usage

(Details on how to run the server and interact with its API endpoints will be added here.)

```bash
# Example command to run the server (to be defined)
python main.py
```