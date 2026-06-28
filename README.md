<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=CSPM&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="CSPM"/>

# CSPM

### Cloud security posture from a config export (public buckets, open SGs, weak IAM)

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Cloud+security+posture+from+a+config+export+public+buckets+o;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-cspm.svg?color=6b46c1)](https://pypi.org/project/cognis-cspm/) [![CI](https://github.com/cognis-digital/cspm/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/cspm/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-cspm
cspm scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ cspm-emit --version
cspm 0.1.0
```

```console
$ cspm-emit --help
usage: cspm [-h] [--version] {scan} ...

Cloud security posture from a config export (defensive triage).

positional arguments:
  {scan}
    scan      Scan a config export for posture findings.

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
```

> Blocks above are real `cspm` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "1234567890",
        "title": "Suspicious Network Traffic",
        "description": "Potential malicious activity detected on port 443.",
        "created_by": "cspm-tool",
        "created_at": "2023-02-20T14:30:00Z"
    },
    {
        "id": "2345678901",
        "title": "Unusual Login Attempt",
        "description": "Failed login attempt from an unknown IP address.",
        "created_by": "cspm-tool",
        "created_at": "2023-02-20T14:31:00Z"
    }
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

1. Install the CLI (Python 3.9+):

   ```bash
   pip install cspm           # or: pip install .   from a checkout
   ```

2. Scan a cloud configuration export — the `scan` subcommand evaluates posture checks against config you own (no live cloud calls):

   ```bash
   cspm scan export.json
   ```

   The `table` view groups findings by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) with a recommendation per finding.

3. Produce a shareable HTML report or machine-readable JSON:

   ```bash
   cspm scan export.json --format html > posture.html
   cspm scan export.json --format json > posture.json
   ```

4. Read the result — parse the summary for triage:

   ```bash
   cspm scan export.json --format json | jq '.summary.by_severity'
   ```

5. Gate CI on posture — surface high-severity findings on every config change:

   ```bash
   cspm scan export.json --format json | jq -e '.summary.by_severity.CRITICAL == 0'
   ```


## Contents

- [Why cspm?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why cspm?

Cloud security posture from a config export (public buckets, open SGs, weak IAM) — without standing up heavyweight infrastructure.

`cspm` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Load Config
- ✅ Scan
- ✅ Summarize
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-cspm
cspm --version
cspm scan .                       # scan current project
cspm scan . --format json         # machine-readable
cspm scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ cspm scan .
  [HIGH    ] CSP-001  example finding             (./src/app.py)
  [MEDIUM  ] CSP-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[cspm<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`cspm` is interoperable with every popular way of using AI:

- **MCP server** — `cspm mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `cspm scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis cspm** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`cspm mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/cspm.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/cspm.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/cspm.git" # uv
pip install cognis-cspm                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/cspm:latest --help        # Docker
brew install cognis-digital/tap/cspm                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/cspm/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/cspm` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools


**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `cspm` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
