"""
Mend (WhiteSource) Report Parser
Parses Mend/WhiteSource JSON reports and extracts security vulnerabilities and CVEs.
"""
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class MendVulnerability:
    """Represents a Mend/WhiteSource vulnerability."""
    name: str
    cve: Optional[str]
    cvss_score: Optional[float]
    severity: str
    library: str
    library_version: str
    description: str
    publish_date: Optional[str]
    fix_version: Optional[str]
    status: str
    project: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class MendParser:
    """Parser for Mend/WhiteSource reports."""
    
    def __init__(self, report_path: str):
        """
        Initialize the parser.
        
        Args:
            report_path: Path to the Mend/WhiteSource JSON report file
        """
        self.report_path = report_path
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[MendVulnerability] = []
    
    def parse(self) -> List[MendVulnerability]:
        """
        Parse the Mend/WhiteSource report.
        
        Returns:
            List of MendVulnerability objects
        """
        try:
            with open(self.report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.vulnerabilities = []
            
            # Handle different Mend report formats
            if 'vulnerabilities' in data:
                vulns_data = data['vulnerabilities']
            elif 'libraryVulnerabilities' in data:
                vulns_data = data['libraryVulnerabilities']
            elif isinstance(data, list):
                vulns_data = data
            else:
                self.logger.warning(f"Unexpected report format in {self.report_path}")
                return []
            
            for vuln_data in vulns_data:
                vulnerability = self._parse_vulnerability(vuln_data, data)
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
            
            self.logger.info(f"Parsed {len(self.vulnerabilities)} vulnerabilities from Mend report")
            return self.vulnerabilities
            
        except FileNotFoundError:
            self.logger.error(f"Mend report not found: {self.report_path}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Mend JSON: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing Mend report: {e}")
            return []
    
    def _parse_vulnerability(self, vuln_data: Dict, full_data: Dict) -> Optional[MendVulnerability]:
        """Parse a single vulnerability from the report."""
        try:
            # Extract CVE
            cve = (
                vuln_data.get('name') or
                vuln_data.get('vulnerabilityName') or
                vuln_data.get('cveName')
            )
            
            # Ensure it's a CVE format
            if cve and not cve.upper().startswith('CVE-'):
                cve = None
            
            # Extract CVSS score
            cvss_score = None
            if 'cvss3_score' in vuln_data:
                cvss_score = float(vuln_data['cvss3_score'])
            elif 'score' in vuln_data:
                cvss_score = float(vuln_data['score'])
            elif 'cvssScore' in vuln_data:
                cvss_score = float(vuln_data['cvssScore'])
            
            # Determine severity from CVSS or explicit severity
            severity = self._determine_severity(cvss_score, vuln_data.get('severity', ''))
            
            # Extract library information
            library = (
                vuln_data.get('library') or
                vuln_data.get('artifactId') or
                vuln_data.get('name', {}).get('name') if isinstance(vuln_data.get('name'), dict) else 'Unknown'
            )
            
            library_version = (
                vuln_data.get('version') or
                vuln_data.get('libraryVersion') or
                'Unknown'
            )
            
            # Extract project name
            project = full_data.get('projectName', 'Unknown') if isinstance(full_data, dict) else 'Unknown'
            
            return MendVulnerability(
                name=vuln_data.get('title', vuln_data.get('name', 'Unknown')),
                cve=cve,
                cvss_score=cvss_score,
                severity=severity,
                library=library,
                library_version=library_version,
                description=vuln_data.get('description', vuln_data.get('vulnerabilityDescription', '')),
                publish_date=vuln_data.get('publishDate') or vuln_data.get('publish_date'),
                fix_version=vuln_data.get('fixVersion') or vuln_data.get('fix_version'),
                status=vuln_data.get('status', 'OPEN'),
                project=project
            )
        except Exception as e:
            self.logger.warning(f"Failed to parse vulnerability: {e}")
            return None
    
    def _determine_severity(self, cvss_score: Optional[float], explicit_severity: str) -> str:
        """Determine severity from CVSS score or explicit severity."""
        if explicit_severity:
            return explicit_severity.upper()
        
        if cvss_score is None:
            return 'UNKNOWN'
        
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_cves(self) -> List[str]:
        """Extract all unique CVEs from parsed vulnerabilities."""
        cves = set()
        for vuln in self.vulnerabilities:
            if vuln.cve:
                cves.add(vuln.cve)
        return sorted(list(cves))
    
    def get_high_severity_vulnerabilities(self) -> List[MendVulnerability]:
        """Get vulnerabilities with high or critical severity."""
        return [
            vuln for vuln in self.vulnerabilities
            if vuln.severity in ['CRITICAL', 'HIGH']
        ]
