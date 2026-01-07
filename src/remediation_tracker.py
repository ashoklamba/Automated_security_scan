"""
Remediation Tracking System
Tracks the status of CVE remediations over time.
"""
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path


@dataclass
class RemediationStatus:
    """Represents the remediation status of a vulnerability."""
    cve: str
    status: str  # OPEN, IN_PROGRESS, REMEDIATED, FALSE_POSITIVE, ACCEPTED_RISK
    remediation_date: Optional[str]
    remediation_notes: str
    assigned_to: Optional[str]
    priority: str
    first_detected: str
    last_updated: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class RemediationTracker:
    """Tracks remediation status of vulnerabilities."""
    
    def __init__(self, tracking_file: str = 'remediation_tracking.json'):
        """
        Initialize the remediation tracker.
        
        Args:
            tracking_file: Path to the JSON file storing remediation tracking data
        """
        self.tracking_file = Path(tracking_file)
        self.logger = logging.getLogger(__name__)
        self.remediations: Dict[str, RemediationStatus] = {}
        self.load()
    
    def load(self):
        """Load remediation tracking data from file."""
        if self.tracking_file.exists():
            try:
                with open(self.tracking_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                for cve, status_data in data.get('remediations', {}).items():
                    self.remediations[cve] = RemediationStatus(**status_data)
                
                self.logger.info(f"Loaded {len(self.remediations)} remediation records")
            except Exception as e:
                self.logger.warning(f"Failed to load remediation tracking: {e}")
                self.remediations = {}
        else:
            self.logger.info("No existing remediation tracking file found, starting fresh")
            self.remediations = {}
    
    def save(self):
        """Save remediation tracking data to file."""
        data = {
            'last_updated': datetime.now().isoformat(),
            'remediations': {
                cve: status.to_dict() for cve, status in self.remediations.items()
            }
        }
        
        # Create parent directory if it doesn't exist
        self.tracking_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.tracking_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Saved {len(self.remediations)} remediation records")
    
    def update_remediation_status(
        self,
        cve: str,
        status: str,
        remediation_notes: str = '',
        assigned_to: Optional[str] = None,
        priority: Optional[str] = None
    ):
        """
        Update the remediation status for a CVE.
        
        Args:
            cve: CVE identifier
            status: New status (OPEN, IN_PROGRESS, REMEDIATED, FALSE_POSITIVE, ACCEPTED_RISK)
            remediation_notes: Notes about the remediation
            assigned_to: Person/team assigned to remediation
            priority: Priority level
        """
        if cve in self.remediations:
            remediation = self.remediations[cve]
            remediation.status = status
            remediation.remediation_notes = remediation_notes
            remediation.last_updated = datetime.now().isoformat()
            
            if assigned_to:
                remediation.assigned_to = assigned_to
            
            if priority:
                remediation.priority = priority
            
            if status == 'REMEDIATED':
                remediation.remediation_date = datetime.now().isoformat()
        else:
            # Create new remediation record
            remediation = RemediationStatus(
                cve=cve,
                status=status,
                remediation_date=datetime.now().isoformat() if status == 'REMEDIATED' else None,
                remediation_notes=remediation_notes,
                assigned_to=assigned_to,
                priority=priority or 'MEDIUM',
                first_detected=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            )
            self.remediations[cve] = remediation
        
        self.save()
    
    def get_remediation_status(self, cve: str) -> Optional[RemediationStatus]:
        """Get remediation status for a CVE."""
        return self.remediations.get(cve)
    
    def get_open_remediations(self) -> List[RemediationStatus]:
        """Get all open remediation items."""
        return [
            status for status in self.remediations.values()
            if status.status in ['OPEN', 'IN_PROGRESS']
        ]
    
    def get_remediated_count(self) -> int:
        """Get count of remediated CVEs."""
        return len([
            status for status in self.remediations.values()
            if status.status == 'REMEDIATED'
        ])
    
    def sync_with_vulnerabilities(self, consolidated_vulns: List):
        """
        Sync remediation tracking with current vulnerabilities.
        Creates tracking records for new CVEs.
        
        Args:
            consolidated_vulns: List of ConsolidatedVulnerability objects
        """
        for vuln in consolidated_vulns:
            if vuln.cve and vuln.cve not in self.remediations:
                # Create new tracking record for new CVE
                remediation = RemediationStatus(
                    cve=vuln.cve,
                    status='OPEN',
                    remediation_date=None,
                    remediation_notes='',
                    assigned_to=None,
                    priority=self._severity_to_priority(vuln.severity),
                    first_detected=vuln.first_detected,
                    last_updated=datetime.now().isoformat()
                )
                self.remediations[vuln.cve] = remediation
            elif vuln.cve and vuln.cve in self.remediations:
                # Update last_updated if CVE still exists
                self.remediations[vuln.cve].last_updated = datetime.now().isoformat()
        
        self.save()
    
    def _severity_to_priority(self, severity: str) -> str:
        """Convert severity to priority."""
        mapping = {
            'CRITICAL': 'HIGH',
            'BLOCKER': 'HIGH',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'INFO': 'LOW',
            'UNKNOWN': 'MEDIUM'
        }
        return mapping.get(severity.upper(), 'MEDIUM')
    
    def generate_remediation_report(self, output_path: str):
        """Generate a remediation status report."""
        open_items = self.get_open_remediations()
        remediated_count = self.get_remediated_count()
        total_count = len(self.remediations)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_tracked': total_count,
                'open': len(open_items),
                'remediated': remediated_count,
                'remediation_rate': f"{(remediated_count / total_count * 100):.1f}%" if total_count > 0 else "0%"
            },
            'open_remediations': [item.to_dict() for item in sorted(open_items, key=lambda x: x.priority, reverse=True)],
            'all_remediations': [status.to_dict() for status in self.remediations.values()]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Generated remediation report: {output_path}")
