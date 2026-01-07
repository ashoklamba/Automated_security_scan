#!/usr/bin/env python3
"""
Main automation script for parsing and consolidating SonarQube and Mend reports.
"""
import argparse
import logging
import sys
from pathlib import Path

from src.sonarqube_parser import SonarQubeParser
from src.mend_parser import MendParser
from src.cve_detector import CVEDetector
from src.remediation_tracker import RemediationTracker


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Parse and consolidate SonarQube and Mend security reports'
    )
    parser.add_argument(
        '--sonarqube',
        type=str,
        help='Path to SonarQube JSON report file',
        default='reports/sonarqube-report.json'
    )
    parser.add_argument(
        '--mend',
        type=str,
        help='Path to Mend/WhiteSource JSON report file',
        default='reports/mend-report.json'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output path for consolidated report',
        default='output/consolidated-report.json'
    )
    parser.add_argument(
        '--remediation-tracking',
        type=str,
        help='Path to remediation tracking file',
        default='output/remediation_tracking.json'
    )
    parser.add_argument(
        '--remediation-report',
        type=str,
        help='Path for remediation status report',
        default='output/remediation-report.json'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting security report consolidation...")
    
    # Parse SonarQube report
    sonarqube_issues = []
    sonarqube_path = Path(args.sonarqube)
    if sonarqube_path.exists():
        logger.info(f"Parsing SonarQube report: {sonarqube_path}")
        sonarqube_parser = SonarQubeParser(str(sonarqube_path))
        sonarqube_issues = sonarqube_parser.parse()
        logger.info(f"Found {len(sonarqube_issues)} SonarQube security issues")
        logger.info(f"Found {len(sonarqube_parser.get_cves())} unique CVEs in SonarQube report")
    else:
        logger.warning(f"SonarQube report not found: {sonarqube_path}")
    
    # Parse Mend report
    mend_vulns = []
    mend_path = Path(args.mend)
    if mend_path.exists():
        logger.info(f"Parsing Mend report: {mend_path}")
        mend_parser = MendParser(str(mend_path))
        mend_vulns = mend_parser.parse()
        logger.info(f"Found {len(mend_vulns)} Mend vulnerabilities")
        logger.info(f"Found {len(mend_parser.get_cves())} unique CVEs in Mend report")
    else:
        logger.warning(f"Mend report not found: {mend_path}")
    
    if not sonarqube_issues and not mend_vulns:
        logger.error("No reports found to process. Exiting.")
        sys.exit(1)
    
    # Consolidate vulnerabilities
    logger.info("Consolidating vulnerabilities...")
    detector = CVEDetector()
    consolidated = detector.consolidate(sonarqube_issues, mend_vulns)
    
    # Get statistics
    all_cves = detector.get_all_cves()
    critical_cves = detector.get_critical_cves()
    high_severity_cves = detector.get_high_severity_cves()
    
    logger.info(f"Consolidation complete:")
    logger.info(f"  - Total vulnerabilities: {len(consolidated)}")
    logger.info(f"  - Total CVEs: {len(all_cves)}")
    logger.info(f"  - Critical CVEs: {len(critical_cves)}")
    logger.info(f"  - High/Critical severity CVEs: {len(high_severity_cves)}")
    
    # Export consolidated report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    detector.export_json(str(output_path))
    logger.info(f"Consolidated report saved to: {output_path}")
    
    # Track remediations
    logger.info("Updating remediation tracking...")
    tracker = RemediationTracker(args.remediation_tracking)
    tracker.sync_with_vulnerabilities(consolidated)
    
    # Generate remediation report
    remediation_report_path = Path(args.remediation_report)
    remediation_report_path.parent.mkdir(parents=True, exist_ok=True)
    tracker.generate_remediation_report(str(remediation_report_path))
    logger.info(f"Remediation report saved to: {remediation_report_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("SECURITY REPORT SUMMARY")
    print("="*60)
    print(f"Total Vulnerabilities: {len(consolidated)}")
    print(f"Total CVEs: {len(all_cves)}")
    print(f"Critical CVEs: {len(critical_cves)}")
    print(f"High/Critical Severity: {len(high_severity_cves)}")
    print(f"\nOpen Remediations: {len(tracker.get_open_remediations())}")
    print(f"Remediated: {tracker.get_remediated_count()}")
    print(f"\nReports generated:")
    print(f"  - Consolidated: {output_path}")
    print(f"  - Remediation: {remediation_report_path}")
    print("="*60)
    
    # Exit with error code if critical vulnerabilities found
    if critical_cves:
        logger.warning(f"Found {len(critical_cves)} critical CVEs!")
        sys.exit(1)
    elif high_severity_cves:
        logger.warning(f"Found {len(high_severity_cves)} high severity CVEs!")
        sys.exit(2)
    
    logger.info("Security report consolidation completed successfully")
    sys.exit(0)


if __name__ == '__main__':
    main()
