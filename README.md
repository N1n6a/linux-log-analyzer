# Linux Log Analyzer

A Flask-based web dashboard for analyzing Linux authentication logs (`/var/log/auth.log` or `secure`). Built to surface the kind of activity a SOC Tier 1 analyst would triage; brute-force attempts, privilege escalation abuse, and multi-stage attack chains, all ranked by severity.

## Features

- **Brute-force detection** — Time-windowed detection of repeated failed login attempts from same source
- **Sudo abuse flagging** — Flags risky/suspicious sudo commands, not just failed logins
- **Attack-chain correlation** — Links related events together to reconstruct multi-stage breach attempts, instead of showing isolated alerts
- **Severity scoring** — Ranks findings by risk level to mimic real SOC triage workflows
- **IP allowlisting** — Supports CIDR ranges, so trusted internal IPs don't clutter results
- **Gzip support** — Reads compressed `.gz` log files transparently
- **Searchable, paginated dashboard** — Browse result sets without a wall of text
- **CLI mode** — Run scans directly from the terminal without the web dashboard

## Project Structure

```
├── app.py             
├── log_analyzer.py    
├── templates/
│   └── index.html     
├── messy_auth.log     
└── requirements.txt
```

## Requirements

- Python 3.x
- Flask>=3.0,<4.0 (see `requirements.txt`)

## Download & Setup

Clone the repo:

```bash
git clone https://github.com/N1n6a/linux-log-analyzer.git
cd linux-log-analyzer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Web Dashboard Usage

Run the app:

```bash
python app.py
```

Then open `http://localhost:5000` in your browser.

1. Point the analyzer at a Linux auth log file (plain text or `.gz`).
2. The dashboard parses the log and surfaces:
   - Brute-force attempts, grouped by source IP and time window
   - Risky sudo commands
   - Correlated attack chains
3. Results are ranked by severity and searchable/paginated in the web UI.
4. Optionally, add trusted IP ranges to the allowlist to reduce noise from internal traffic.

## CLI Usage

For quick scans without the web dashboard, run the analyzer directly from the command line:

```bash
python log_analyzer.py -i <log_file> [options]
```

**Basic example (using the included sample log):**
```bash
python log_analyzer.py -i messy_auth.log
```

This generates `log_report.html` and `log_findings.json` in the current directory.

**Options:**

 `-i`, `--input` : Path(s) to log file(s) to analyze (`.log`, `.txt`, or `.gz`). Accepts multiple files. 
 `-o`, `--outdir` : Output directory for the report.
 `--html-name` : Filename for the HTML report. 
 `--json-name` : Filename for the JSON findings.
 `--brute-force-threshold` : Failed attempts from one IP to flag as brute force.
 `--brute-force-window` : Rolling time window (seconds) for brute-force detection.
 `--allowlist-ip` : IP(s) or CIDR range(s) to exclude from suspicious flagging (still counted in totals).
 `--correlation-window` : Lookback window (seconds) for flagging a success following a burst of failures.
 `--year` : Year to assume for timestamps that omit one. 

**Example with custom options:**
```bash
python log_analyzer.py -i messy_auth.log -o reports/ --brute-force-threshold 3 --allowlist-ip 10.0.0.0/8
```

A sample log file (`messy_auth.log`) is included in the repo so you can test the tool immediately without needing your own auth logs.
