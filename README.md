# skill-scanner

A [Claude skill](https://claude.ai) that automatically scans skill files for malware using the [VirusTotal API](https://www.virustotal.com/) before they are installed.

## What It Does

Every time a skill is created, uploaded, edited, or installed, this skill triggers automatically and:

1. Recursively collects all files in the skill directory
2. Computes SHA-256 hashes and checks VirusTotal for existing reports
3. Uploads unknown files to VT for fresh analysis
4. Returns a JSON report with per-file verdicts and an overall pass/fail
5. Blocks installation if any file is flagged as malicious

## Hybrid Workflow

Supports three scanning paths depending on your environment:

| Path | Environment | How It Works |
|------|-------------|--------------|
| **A — MCP** | Claude Desktop / Code | Fast hash lookups via [mcp-virustotal](https://github.com/BurtTheCoder/mcp-virustotal) |
| **B — Script** | Claude.ai web / iOS | Full upload-and-scan via `scripts/scan_skill.py` |
| **C — Hybrid** | Desktop / Code | MCP for known files, script fallback for unknowns |

## Installation

### As a Claude Skill

Download the `.skill` file from [Releases](https://github.com/nateritter/skill-scanner/releases) and upload it to Claude.

### MCP Server (Optional, for Desktop/Code)

```bash
npm install -g @burtthecoder/mcp-virustotal
```

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "mcp-virustotal",
      "env": {
        "VIRUSTOTAL_API_KEY": "your-key-here"
      }
    }
  }
}
```

## Usage

### Automatic

The skill triggers automatically when Claude creates, uploads, edits, or installs any skill.

### Manual

```bash
export VT_API_KEY="your-key"
python3 scripts/scan_skill.py ./path-to-skill/
```

### Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--wait` | 120 | Max seconds to wait for VT analysis per file |
| `--threshold` | 1 | Minimum malicious detections to flag a file |

## Requirements

- Python 3.10+
- `requests` library (auto-installed if missing)
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free tier works)

## License

MIT
