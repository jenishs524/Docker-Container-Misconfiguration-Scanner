#!/usr/bin/env python3
"""
Docker Container Misconfiguration Scanner
Works with or without Docker Python library
"""

import re
import json
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class SecurityFinding:
    """Security finding for container misconfigurations"""
    severity: str
    category: str
    title: str
    description: str
    remediation: str
    line_number: Optional[int] = None
    context: Optional[str] = None

class DockerScanner:
    """Advanced Docker container security scanner"""
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.rules = self._initialize_rules()
        self.severity_weights = {
            'CRITICAL': 10,
            'HIGH': 8,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 1
        }
        self.docker_available = self._check_docker()
    
    def _check_docker(self) -> bool:
        """Check if docker is available"""
        try:
            subprocess.run(['docker', '--version'], capture_output=True, check=True)
            print("[+] Docker CLI found")
            return True
        except:
            print("[!] Docker CLI not found - Only Dockerfile analysis available")
            return False
    
    def _initialize_rules(self) -> Dict:
        """Initialize comprehensive security rules"""
        return {
            'no_root_user': {
                'pattern': r'^USER\s+root\b',
                'severity': 'HIGH',
                'title': 'Container runs as root user',
                'description': 'Running as root inside containers can lead to privilege escalation',
                'remediation': 'Create and use a non-root user: USER appuser',
                'line_check': True,
                'negative': True
            },
            'latest_tag': {
                'pattern': r'FROM\s+.*:latest',
                'severity': 'HIGH',
                'title': 'Using latest tag in base image',
                'description': 'Latest tag can lead to inconsistent builds',
                'remediation': 'Use specific version tags: FROM ubuntu:22.04',
                'line_check': True
            },
            'expose_ssh': {
                'pattern': r'EXPOSE\s+22\b',
                'severity': 'CRITICAL',
                'title': 'SSH port exposed',
                'description': 'Exposing SSH port (22) can allow unauthorized access',
                'remediation': 'Remove SSH from container unless absolutely necessary',
                'line_check': True
            },
            'secrets_in_dockerfile': {
                'pattern': r'(PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=\s*["\']?[^"\'\s]+["\']?',
                'severity': 'CRITICAL',
                'title': 'Hardcoded secrets in Dockerfile',
                'description': 'Sensitive information should not be hardcoded',
                'remediation': 'Use build arguments or Docker secrets',
                'line_check': True
            },
            'healthcheck_missing': {
                'pattern': r'HEALTHCHECK',
                'severity': 'MEDIUM',
                'title': 'Missing health check',
                'description': 'Health check ensures container reliability',
                'remediation': 'Add HEALTHCHECK instruction',
                'line_check': True,
                'negative': True
            },
            'apt_unnecessary': {
                'pattern': r'apt-get\s+install\s+',
                'severity': 'MEDIUM',
                'title': 'Unnecessary packages installed',
                'description': 'Unnecessary packages increase attack surface',
                'remediation': 'Remove development tools and unused packages',
                'line_check': True
            },
            'pip_unpinned': {
                'pattern': r'pip\s+install\s+[^=]+$',
                'severity': 'MEDIUM',
                'title': 'Unpinned pip package versions',
                'description': 'Unpinned versions can lead to unexpected changes',
                'remediation': 'Pin package versions: pip install package==1.2.3',
                'line_check': True
            },
            'sensitive_env': {
                'pattern': r'ENV\s+[A-Z_]*(PASS|SECRET|KEY|TOKEN|AUTH)[A-Z_]*\s*=',
                'severity': 'CRITICAL',
                'title': 'Sensitive environment variables',
                'description': 'Sensitive values should not be in environment variables',
                'remediation': 'Use Docker secrets or .env files',
                'line_check': True
            },
            'shell_execution': {
                'pattern': r'(curl|wget)\s+.*\|.*\b(bash|sh)\b',
                'severity': 'CRITICAL',
                'title': 'Direct shell execution from web',
                'description': 'Downloading and executing scripts directly is dangerous',
                'remediation': 'Download, verify checksum, then execute',
                'line_check': True
            },
            'user_flag_missing': {
                'pattern': r'^USER\s+',
                'severity': 'HIGH',
                'title': 'Missing USER instruction',
                'description': 'Without USER instruction, container runs as root',
                'remediation': 'Add USER instruction to switch to non-root user',
                'line_check': True,
                'negative': True
            }
        }
    
    def scan_dockerfile(self, dockerfile_path: str) -> List[SecurityFinding]:
        """Scan Dockerfile for security issues"""
        print(f"[*] Scanning Dockerfile: {dockerfile_path}")
        
        if not os.path.exists(dockerfile_path):
            print(f"[-] Dockerfile not found: {dockerfile_path}")
            return []
        
        try:
            with open(dockerfile_path, 'r', encoding='utf-8') as f:
                content = f.readlines()
            
            findings = []
            
            for line_num, line in enumerate(content, 1):
                line_stripped = line.strip()
                
                for rule_name, rule in self.rules.items():
                    if not rule.get('line_check', True):
                        continue
                    
                    if rule.get('negative', False):
                        if not re.search(rule['pattern'], line_stripped, re.IGNORECASE):
                            if not self._has_finding_already(findings, rule_name):
                                findings.append(SecurityFinding(
                                    severity=rule['severity'],
                                    category=rule_name,
                                    title=rule['title'],
                                    description=rule['description'],
                                    remediation=rule['remediation'],
                                    line_number=line_num
                                ))
                    else:
                        if re.search(rule['pattern'], line_stripped, re.IGNORECASE):
                            findings.append(SecurityFinding(
                                severity=rule['severity'],
                                category=rule_name,
                                title=rule['title'],
                                description=rule['description'],
                                remediation=rule['remediation'],
                                line_number=line_num,
                                context=line_stripped[:50]
                            ))
            
            self.findings.extend(findings)
            print(f"[+] Found {len(findings)} issues in Dockerfile")
            return findings
            
        except Exception as e:
            print(f"[-] Error scanning Dockerfile: {e}")
            return []
    
    def _has_finding_already(self, findings: List[SecurityFinding], category: str) -> bool:
        """Check if a finding category already exists"""
        return any(f.category == category for f in findings)
    
    def generate_report(self) -> Dict:
        """Generate comprehensive security report"""
        if not self.findings:
            return {'status': 'No findings found'}
        
        severity_counts = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
        }
        
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
        
        risk_score = sum(
            self.severity_weights.get(finding.severity, 0)
            for finding in self.findings
        )
        
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'risk_score': risk_score,
            'risk_level': self._calculate_risk_level(risk_score),
            'findings': [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'remediation': f.remediation,
                    'line_number': f.line_number
                }
                for f in self.findings
            ],
            'recommendations': self._generate_recommendations()
        }
    
    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate overall risk level"""
        if risk_score > 30:
            return 'CRITICAL'
        elif risk_score > 20:
            return 'HIGH'
        elif risk_score > 10:
            return 'MEDIUM'
        elif risk_score > 5:
            return 'LOW'
        else:
            return 'GOOD'
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate recommendations"""
        recs = []
        
        critical = [f for f in self.findings if f.severity == 'CRITICAL']
        high = [f for f in self.findings if f.severity == 'HIGH']
        
        if critical:
            recs.append({
                'priority': 'IMMEDIATE',
                'action': f'Fix {len(critical)} critical findings'
            })
        
        if high:
            recs.append({
                'priority': 'HIGH',
                'action': f'Fix {len(high)} high priority findings'
            })
        
        recs.extend([
            {'priority': 'HIGH', 'action': 'Run containers with least privilege principle'},
            {'priority': 'MEDIUM', 'action': 'Use specific image tags instead of latest'},
            {'priority': 'MEDIUM', 'action': 'Regularly update base images'},
            {'priority': 'MEDIUM', 'action': 'Never store secrets in Dockerfiles'},
            {'priority': 'LOW', 'action': 'Add health checks to all containers'}
        ])
        
        return recs
    
    def export_report(self, filename: str = 'docker_scan_report.json'):
        """Export report to JSON file"""
        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {filename}")

# Main execution
if __name__ == "__main__":
    print("=" * 70)
    print("DOCKER CONTAINER MISCONFIGURATION SCANNER")
    print("=" * 70 + "\n")
    
    # Create scanner
    scanner = DockerScanner()
    
    # Example Dockerfile with security issues
    dockerfile_content = """FROM ubuntu:latest

# Install packages
RUN apt-get update && apt-get install -y openssh-server curl wget

# Set sensitive environment variable
ENV SECRET_KEY="supersecret123"
ENV ADMIN_PASSWORD="admin123"

# Expose SSH port
EXPOSE 22

# Dangerous shell execution
RUN curl -sSL https://example.com/install.sh | bash

CMD ["/usr/sbin/sshd", "-D"]
"""
    
    # Write Dockerfile
    with open('Dockerfile.test', 'w') as f:
        f.write(dockerfile_content)
    
    print("[*] Analyzing Dockerfile...\n")
    
    # Scan
    scanner.scan_dockerfile('Dockerfile.test')
    
    # Generate report
    report = scanner.generate_report()
    
    print(f"\n[+] Scan Results:")
    print(f"    Total Findings: {report['total_findings']}")
    print(f"    Risk Score: {report['risk_score']}")
    print(f"    Risk Level: {report['risk_level']}")
    
    print("\n[+] Severity Breakdown:")
    for severity, count in report['severity_counts'].items():
        if count > 0:
            print(f"    {severity}: {count}")
    
    if report['findings']:
        print("\n[!] Findings:")
        for finding in report['findings']:
            print(f"\n    [{finding['severity']}] {finding['title']}")
            print(f"    {finding['description']}")
            print(f"    Remediation: {finding['remediation']}")
            if finding['line_number']:
                print(f"    Line: {finding['line_number']}")
    
    # Export report
    scanner.export_report()
    
    # Cleanup
    os.remove('Dockerfile.test')
    
    print("\n[+] Key Features Demonstrated:")
    print("    ✓ Dockerfile Static Analysis")
    print("    ✓ Security Rule Enforcement")
    print("    ✓ Vulnerability Detection")
    print("    ✓ Best Practice Validation")
    print("    ✓ Comprehensive Reporting")
    print("    ✓ Remediation Recommendations")