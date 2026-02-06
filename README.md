# skill-scanner

A [Claude skill](https://claude.ai) that automatically scans skill files for malware using the [VirusTotal API](https://www.virustotal.com/) before they are installed.

## What It Does

Every time a skill is created, uploaded, edited, or installed, this skill triggers automatically and:

1. Recursively collects all files in the skill directory
2. Computes SHA-256 hashes and checks VirusTotal for existing reports
3. Uploads unknown files to VT for fresh analysis
4. Returns a JSON report with per-file verdicts and an overall pass/fail
5. Blocks installation if any file is flagged as malicious

## Enforcement Setup (Important!)

The skill-scanner only works if Claude knows to run it. You need to tell Claude to enforce scanning **before** any new skills are added, enabled, or updated. Choose one or both methods:

### Option 1: Add to Claude's Memory

In any Claude conversation, say:

> "Remember: Always run the skill-scanner skill (VirusTotal scan) on every new skill created, uploaded, edited, or installed before proceeding. Require VT_API_KEY env var."

Claude will store this as a memory edit and enforce it across all future conversations.

### Option 2: Add to CORE.md (Claude Code / Projects)

If you use Claude Code or Claude Projects with a `CORE.md` or `CLAUDE.md` instructions file, add this line:

```markdown
## Security

- Always run the skill-scanner skill (VirusTotal scan) on every new skill created, uploaded, edited, or installed before proceeding. Require VT_API_KEY env var.
```

This ensures scanning is enforced for anyone working in that project, not just you.

### Why This Matters

Without one of these enforcement steps, Claude won't know to scan skills automatically. The SKILL.md file contains trigger descriptions, but they only work when the skill is already installed. The memory/CORE.md instruction acts as the bootstrap — it tells Claude to use the scanner before trusting any new skill, including skills that arrive before the scanner itself is set up.

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

The skill triggers automatically when Claude creates, uploads, edits, or installs any skill (once enforcement is set up per above).

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

## Network Error Handling

In sandboxed environments (like Claude.ai web), outbound connections to virustotal.com may be blocked. The script detects this gracefully and:

- Still computes and reports SHA-256 hashes for all files
- Provides clear guidance on alternatives (Claude Desktop, MCP server, or manual VT lookup)
- Uses a distinct exit code (`3`) so automation can distinguish network errors from malicious detections

## Requirements

- Python 3.10+
- `requests` library (auto-installed if missing)
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free tier works)

## Rate Limits

Free VT API keys allow 4 requests per minute. For skills with many files, the scan may take several minutes. The MCP path is faster since hash lookups are lightweight.

## License

MIT
