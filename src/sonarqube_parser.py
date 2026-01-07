"""
SonarQube Report Parser
Parses SonarQube JSON reports and extracts security vulnerabilities and CVEs.
"""
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class SonarQubeIssue:
    """Represents a SonarQube security issue."""
    key: str
    rule: str
    severity: str
    component: str
    line: Optional[int]
    message: str
    cwe: Optional[str]
    cve: Optional[str]
    status: str
    creation_date: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class SonarQubeParser:
    """Parser for SonarQube reports."""
    
    def __init__(self, report_path: str):
        """
        Initialize the parser.
        
        Args:
            report_path: Path to the SonarQube JSON report file
        """
        self.report_path = report_path
        self.logger = logging.getLogger(__name__)
        self.issues: List[SonarQubeIssue] = []
    
    def parse(self) -> List[SonarQubeIssue]:
        """
        Parse the SonarQube report.
        
        Returns:
            List of SonarQubeIssue objects
        """
        try:
            with open(self.report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.issues = []
            
            # Handle different SonarQube report formats
            if 'issues' in data:
                issues_data = data['issues']
            elif isinstance(data, list):
                issues_data = data
            else:
                self.logger.warning(f"Unexpected report format in {self.report_path}")
                return []
            
            for issue_data in issues_data:
                # Only process security-related issues
                if not self._is_security_issue(issue_data):
                    continue
                
                issue = self._parse_issue(issue_data)
                if issue:
                    self.issues.append(issue)
            
            self.logger.info(f"Parsed {len(self.issues)} security issues from SonarQube report")
            return self.issues
            
        except FileNotFoundError:
            self.logger.error(f"SonarQube report not found: {self.report_path}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse SonarQube JSON: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing SonarQube report: {e}")
            return []
    
    def _is_security_issue(self, issue_data: Dict) -> bool:
        """Check if an issue is security-related."""
        # Check rule type or tags
        rule_type = issue_data.get('type', '').lower()
        tags = issue_data.get('tags', [])
        
        return (
            'security' in rule_type or
            'vulnerability' in rule_type or
            any('security' in tag.lower() or 'vulnerability' in tag.lower() for tag in tags)
        )
    
    def _parse_issue(self, issue_data: Dict) -> Optional[SonarQubeIssue]:
        """Parse a single issue from the report."""
        try:
            # Extract CVE and CWE from message or rule
            message = issue_data.get('message', '')
            cve = self._extract_cve(message)
            cwe = issue_data.get('rule', '').split(':')[-1] if ':' in issue_data.get('rule', '') else None
            
            # Try to extract CWE from rule name or message
            if not cwe:
                cwe = self._extract_cwe(message)
            
            # Extract component path
            component = issue_data.get('component', '').split(':')[-1] if ':' in issue_data.get('component', '') else issue_data.get('component', 'Unknown')
            
            return SonarQubeIssue(
                key=issue_data.get('key', ''),
                rule=issue_data.get('rule', ''),
                severity=issue_data.get('severity', 'INFO').upper(),
                component=component,
                line=issue_data.get('line'),
                message=message,
                cwe=cwe,
                cve=cve,
                status=issue_data.get('status', 'OPEN'),
                creation_date=issue_data.get('creationDate', datetime.now().isoformat())
            )
        except Exception as e:
            self.logger.warning(f"Failed to parse issue: {e}")
            return None
    
    def _extract_cve(self, text: str) -> Optional[str]:
        """Extract CVE identifier from text."""
        import re
        # Match CVE-YYYY-NNNNN pattern
        match = re.search(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        return match.group(0).upper() if match else None
    
    def _extract_cwe(self, text: str) -> Optional[str]:
        """Extract CWE identifier from text."""
        import re
        # Match CWE-NNN pattern
        match = re.search(r'CWE-(\d+)', text, re.IGNORECASE)
        return f"CWE-{match.group(1)}" if match else None
    
    def get_cves(self) -> List[str]:
        """Extract all unique CVEs from parsed issues."""
        cves = set()
        for issue in self.issues:
            if issue.cve:
                cves.add(issue.cve)
        return sorted(list(cves))
    
    def get_high_severity_issues(self) -> List[SonarQubeIssue]:
        """Get issues with high or critical severity."""
        return [
            issue for issue in self.issues
            if issue.severity in ['CRITICAL', 'BLOCKER', 'HIGH']
        ]
