# Security Report Automation Tools

Automation tools to parse and consolidate SonarQube and Mend (WhiteSource) security reports, enabling automated CVE detection and remediation tracking.

## Features

- **Multi-Source Parsing**: Parse security reports from SonarQube and Mend/WhiteSource
- **CVE Detection**: Automatically extract and identify CVEs from vulnerability reports
- **Report Consolidation**: Combine findings from multiple sources into a unified view
- **Remediation Tracking**: Track remediation status and progress over time
- **Automated Reporting**: Generate comprehensive security and remediation reports
- **CI/CD Integration**: GitHub Actions workflow for automated analysis

## Project Structure

```
.
├── src/
│   ├── __init__.py
│   ├── main.py                    # Main entry point
│   ├── sonarqube_parser.py        # SonarQube report parser
│   ├── mend_parser.py             # Mend/WhiteSource report parser
│   ├── cve_detector.py            # CVE detection and consolidation
│   └── remediation_tracker.py     # Remediation status tracking
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions CI workflow
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd new-project
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

The repository includes sample report files for testing:

```bash
# Run with sample reports (included in the repository)
python -m src.main \
  --sonarqube reports/sonarqube-report.json \
  --mend reports/mend-report.json
```

This will generate:
- `output/consolidated-report.json` - Consolidated vulnerability report
- `output/remediation-report.json` - Remediation tracking report
- `output/remediation_tracking.json` - Persistent remediation tracking data

## Usage

### Command Line

Run the automation tool with report files:

```bash
python -m src.main \
  --sonarqube reports/sonarqube-report.json \
  --mend reports/mend-report.json \
  --output output/consolidated-report.json \
  --remediation-tracking output/remediation_tracking.json \
  --remediation-report output/remediation-report.json
```

### Arguments

- `--sonarqube`: Path to SonarQube JSON report (default: `reports/sonarqube-report.json`)
- `--mend`: Path to Mend/WhiteSource JSON report (default: `reports/mend-report.json`)
- `--output`: Output path for consolidated report (default: `output/consolidated-report.json`)
- `--remediation-tracking`: Path to remediation tracking file (default: `output/remediation_tracking.json`)
- `--remediation-report`: Path for remediation status report (default: `output/remediation-report.json`)
- `--verbose`, `-v`: Enable verbose logging

### Example Output

The tool generates two main reports:

1. **Consolidated Report** (`consolidated-report.json`):
   - All vulnerabilities from both sources
   - Unique CVE listings
   - Severity-based prioritization
   - Affected components and libraries

2. **Remediation Report** (`remediation-report.json`):
   - Current remediation status
   - Open items requiring attention
   - Remediation statistics
   - Progress tracking

## GitHub Actions Workflow

The CI workflow automatically:
- Runs security analysis on pushes and pull requests
- Processes SonarQube and Mend reports (if available)
- Generates consolidated security reports
- Tracks remediation status over time
- Uploads reports as artifacts
- Comments on pull requests with security summaries

### Workflow Triggers

- Push to `main` or `master` branches
- Pull requests to `main` or `master` branches
- Daily scheduled runs (2 AM UTC)
- Manual trigger via `workflow_dispatch`

## Report Formats

### Sample Reports

Sample report files are included in the `reports/` directory:
- `reports/sonarqube-report.json` - Example SonarQube report with 6 security issues
- `reports/mend-report.json` - Example Mend/WhiteSource report with 6 vulnerabilities

You can use these samples to test the tool and understand the expected format.

### SonarQube Report

Expected JSON format with an `issues` array containing security-related issues:
```json
{
  "issues": [
    {
      "key": "issue-key",
      "rule": "security-rule-id",
      "severity": "CRITICAL",
      "component": "file/path",
      "message": "Vulnerability description CVE-2024-1234",
      "type": "VULNERABILITY"
    }
  ]
}
```

### Mend/WhiteSource Report

Expected JSON format with a `vulnerabilities` array:
```json
{
  "vulnerabilities": [
    {
      "name": "CVE-2024-1234",
      "cvss3_score": 9.8,
      "library": "library-name",
      "version": "1.0.0",
      "description": "Vulnerability description"
    }
  ]
}
```

## Remediation Tracking

The remediation tracker supports the following statuses:
- `OPEN`: Newly detected, not yet addressed
- `IN_PROGRESS`: Currently being worked on
- `REMEDIATED`: Successfully fixed
- `FALSE_POSITIVE`: Not a real vulnerability
- `ACCEPTED_RISK`: Risk accepted, no remediation planned

Update remediation status programmatically or manually edit the tracking JSON file.

## Development

### Running Tests

```bash
# Add test commands here when tests are added
```

### Adding Support for New Report Formats

1. Create a new parser module in `src/` following the pattern of existing parsers
2. Update `src/main.py` to include the new parser
3. Update `src/cve_detector.py` to consolidate from the new source

## License

[Specify license here]

## Contributing

[Contributing guidelines]
