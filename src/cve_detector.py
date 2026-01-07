"""
CVE Detection and Consolidation Module
Consolidates vulnerabilities from multiple sources and tracks CVEs.
"""
import json
import logging
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict

from src.sonarqube_parser import SonarQubeIssue
from src.mend_parser import MendVulnerability


@dataclass
class ConsolidatedVulnerability:
    """Represents a consolidated vulnerability from multiple sources."""
    cve: Optional[str]
    title: str
    severity: str
    cvss_score: Optional[float]
    sources: List[str]  # ['sonarqube', 'mend']
    descriptions: List[str]
    affected_components: List[str]
    libraries: List[Dict[str, str]]  # [{'name': 'lib', 'version': '1.0'}]
    remediation_status: str
    first_detected: str
    last_updated: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class CVEDetector:
    """CVE detection and consolidation engine."""
    
    def __init__(self):
        """Initialize the CVE detector."""
        self.logger = logging.getLogger(__name__)
        self.consolidated_vulns: List[ConsolidatedVulnerability] = []
        self.cve_index: Dict[str, ConsolidatedVulnerability] = {}
    
    def consolidate(
        self,
        sonarqube_issues: List[SonarQubeIssue],
        mend_vulns: List[MendVulnerability]
    ) -> List[ConsolidatedVulnerability]:
        """
        Consolidate vulnerabilities from multiple sources.
        
        Args:
            sonarqube_issues: List of SonarQube issues
            mend_vulns: List of Mend vulnerabilities
        
        Returns:
            List of consolidated vulnerabilities
        """
        # Index by CVE
        cve_map: Dict[str, Dict] = defaultdict(lambda: {
            'cve': None,
            'title': '',
            'severity': 'UNKNOWN',
            'cvss_score': None,
            'sources': set(),
            'descriptions': [],
            'affected_components': [],
            'libraries': [],
            'first_detected': None,
            'last_updated': None
        })
        
        # Process SonarQube issues
        for issue in sonarqube_issues:
            cve_key = issue.cve or f"SONARQUBE-{issue.key}"
            entry = cve_map[cve_key]
            
            if issue.cve:
                entry['cve'] = issue.cve
            
            entry['sources'].add('sonarqube')
            entry['descriptions'].append(issue.message)
            entry['affected_components'].append(issue.component)
            
            # Update severity (take highest)
            entry['severity'] = self._max_severity(entry['severity'], issue.severity)
            
            if not entry['title']:
                entry['title'] = issue.message[:100] or f"SonarQube Issue: {issue.rule}"
            
            if not entry['first_detected'] or issue.creation_date < entry['first_detected']:
                entry['first_detected'] = issue.creation_date
            
            entry['last_updated'] = datetime.now().isoformat()
        
        # Process Mend vulnerabilities
        for vuln in mend_vulns:
            cve_key = vuln.cve or f"MEND-{vuln.name}-{vuln.library}"
            entry = cve_map[cve_key]
            
            if vuln.cve:
                entry['cve'] = vuln.cve
            
            entry['sources'].add('mend')
            entry['descriptions'].append(vuln.description)
            entry['libraries'].append({
                'name': vuln.library,
                'version': vuln.library_version,
                'fix_version': vuln.fix_version
            })
            
            # Update severity
            entry['severity'] = self._max_severity(entry['severity'], vuln.severity)
            
            # Update CVSS score (take highest)
            if vuln.cvss_score and (not entry['cvss_score'] or vuln.cvss_score > entry['cvss_score']):
                entry['cvss_score'] = vuln.cvss_score
            
            if not entry['title']:
                entry['title'] = vuln.name or f"Mend Vulnerability: {vuln.library}"
            
            if vuln.publish_date:
                if not entry['first_detected'] or vuln.publish_date < entry['first_detected']:
                    entry['first_detected'] = vuln.publish_date
            
            entry['last_updated'] = datetime.now().isoformat()
        
        # Convert to ConsolidatedVulnerability objects
        self.consolidated_vulns = []
        for cve_key, data in cve_map.items():
            consolidated = ConsolidatedVulnerability(
                cve=data['cve'],
                title=data['title'],
                severity=data['severity'],
                cvss_score=data['cvss_score'],
                sources=sorted(list(data['sources'])),
                descriptions=list(set(data['descriptions'])),  # Deduplicate
                affected_components=list(set(data['affected_components'])),  # Deduplicate
                libraries=data['libraries'],
                remediation_status='OPEN',
                first_detected=data['first_detected'] or datetime.now().isoformat(),
                last_updated=data['last_updated'] or datetime.now().isoformat()
            )
            self.consolidated_vulns.append(consolidated)
            
            if consolidated.cve:
                self.cve_index[consolidated.cve] = consolidated
        
        # Sort by severity and CVSS score
        self.consolidated_vulns.sort(
            key=lambda x: (
                self._severity_order(x.severity),
                -(x.cvss_score or 0)
            ),
            reverse=True
        )
        
        self.logger.info(f"Consolidated {len(self.consolidated_vulns)} unique vulnerabilities")
        return self.consolidated_vulns
    
    def _severity_order(self, severity: str) -> int:
        """Get numeric order for severity (higher = more severe)."""
        order = {
            'CRITICAL': 5,
            'BLOCKER': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0,
            'UNKNOWN': -1
        }
        return order.get(severity.upper(), -1)
    
    def _max_severity(self, current: str, new: str) -> str:
        """Return the more severe of two severity levels."""
        current_order = self._severity_order(current)
        new_order = self._severity_order(new)
        return new if new_order > current_order else current
    
    def get_all_cves(self) -> List[str]:
        """Get all unique CVEs."""
        cves = [vuln.cve for vuln in self.consolidated_vulns if vuln.cve]
        return sorted(list(set(cves)))
    
    def get_critical_cves(self) -> List[str]:
        """Get all critical CVEs."""
        return [
            vuln.cve for vuln in self.consolidated_vulns
            if vuln.cve and vuln.severity == 'CRITICAL'
        ]
    
    def get_high_severity_cves(self) -> List[str]:
        """Get all high and critical severity CVEs."""
        return [
            vuln.cve for vuln in self.consolidated_vulns
            if vuln.cve and vuln.severity in ['CRITICAL', 'HIGH']
        ]
    
    def export_json(self, output_path: str):
        """Export consolidated vulnerabilities to JSON."""
        data = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.consolidated_vulns),
            'total_cves': len(self.get_all_cves()),
            'critical_cves': len(self.get_critical_cves()),
            'vulnerabilities': [vuln.to_dict() for vuln in self.consolidated_vulns]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Exported consolidated report to {output_path}")
