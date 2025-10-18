#!/usr/bin/env python3
"""
Simplified Threat Modeling Analyzer
STRIDE-based threat analysis with minimal dependencies
"""

import os
import re
import json
import sqlite3
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, asdict

@dataclass
class ThreatFinding:
    """Represents a threat finding."""
    id: str
    project_name: str
    file_path: str
    line_number: int
    stride_category: str
    threat_name: str
    description: str
    severity: str
    confidence: float
    code_snippet: str
    cwe_id: str
    mitigation: str
    attack_vector: str

class SimpleThreatAnalyzer:
    """Simplified threat analyzer using STRIDE methodology."""

    def __init__(self):
        self.db_path = "simplified_threat_analysis.db"
        self.init_database()

        # STRIDE-based vulnerability patterns
        self.vulnerability_patterns = {
            'Spoofing': [
                (r'password\s*=\s*["\'][^"\']*["\']', 'Hardcoded password', 'CWE-798', 'High'),
                (r'api_key\s*=\s*["\'][^"\']*["\']', 'Hardcoded API key', 'CWE-798', 'High'),
                (r'auth\s*=\s*false', 'Authentication bypass', 'CWE-287', 'Critical'),
                (r'verify\s*=\s*false', 'Certificate verification disabled', 'CWE-295', 'High'),
            ],
            'Tampering': [
                (r'eval\s*\(', 'Code injection via eval', 'CWE-95', 'Critical'),
                (r'exec\s*\(', 'Code injection via exec', 'CWE-95', 'Critical'),
                (r'system\s*\(', 'Command injection', 'CWE-78', 'Critical'),
                (r'shell_exec\s*\(', 'Command injection', 'CWE-78', 'Critical'),
                (r'innerHTML\s*=', 'XSS via innerHTML', 'CWE-79', 'High'),
                (r'document\.write\s*\(', 'XSS via document.write', 'CWE-79', 'High'),
                (r'query\s*\+', 'SQL injection risk', 'CWE-89', 'High'),
                (r'SELECT\s+.*\+', 'SQL injection risk', 'CWE-89', 'High'),
            ],
            'Repudiation': [
                (r'(?i)log.*=.*null', 'Logging disabled', 'CWE-778', 'Medium'),
                (r'(?i)audit.*false', 'Audit trail disabled', 'CWE-778', 'Medium'),
            ],
            'Information_Disclosure': [
                (r'console\.log\s*\([^)]*password', 'Password logged', 'CWE-532', 'Medium'),
                (r'print\s*\([^)]*password', 'Password printed', 'CWE-532', 'Medium'),
                (r'error\s*\([^)]*\+', 'Information disclosure in errors', 'CWE-209', 'Medium'),
                (r'http://', 'Insecure HTTP usage', 'CWE-319', 'Medium'),
                (r'md5\s*\(', 'Weak hash algorithm', 'CWE-328', 'Medium'),
                (r'sha1\s*\(', 'Weak hash algorithm', 'CWE-328', 'Medium'),
            ],
            'Denial_of_Service': [
                (r'while\s+true', 'Infinite loop risk', 'CWE-835', 'Medium'),
                (r'for\s*\([^)]*;;[^)]*\)', 'Infinite loop risk', 'CWE-835', 'Medium'),
                (r'recursion.*depth', 'Stack overflow risk', 'CWE-674', 'Medium'),
            ],
            'Elevation_of_Privilege': [
                (r'sudo\s+', 'Privilege escalation risk', 'CWE-269', 'High'),
                (r'setuid\s*\(', 'Privilege escalation risk', 'CWE-269', 'High'),
                (r'admin\s*=\s*true', 'Privilege escalation risk', 'CWE-269', 'Critical'),
                (r'root\s*=\s*true', 'Privilege escalation risk', 'CWE-269', 'Critical'),
            ]
        }

        # File extension to language mapping
        self.language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.kt': 'Kotlin',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.cs': 'C#',
            '.cpp': 'C++',
            '.c': 'C'
        }

    def init_database(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_findings (
            id TEXT PRIMARY KEY,
            project_name TEXT,
            file_path TEXT,
            line_number INTEGER,
            stride_category TEXT,
            threat_name TEXT,
            description TEXT,
            severity TEXT,
            confidence REAL,
            code_snippet TEXT,
            cwe_id TEXT,
            mitigation TEXT,
            attack_vector TEXT,
            created_date TEXT
        )
        ''')

        conn.commit()
        conn.close()

    def analyze_project(self, project_path: Path) -> List[ThreatFinding]:
        """Analyze a project for security threats."""
        print(f"🔍 Analyzing project: {project_path.name}")

        findings = []

        # Find code files
        code_files = []
        for ext in self.language_map.keys():
            code_files.extend(project_path.rglob(f"*{ext}"))

        # Limit analysis to reasonable number of files
        code_files = code_files[:50]

        print(f"📄 Found {len(code_files)} code files to analyze")

        for file_path in code_files:
            try:
                file_findings = self.analyze_file(file_path, project_path.name)
                findings.extend(file_findings)
            except Exception as e:
                print(f"⚠️  Error analyzing {file_path}: {e}")

        # Store findings in database
        self.store_findings(findings)

        print(f"✅ Analysis complete. Found {len(findings)} potential threats")
        return findings

    def analyze_file(self, file_path: Path, project_name: str) -> List[ThreatFinding]:
        """Analyze a single file for threats."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            findings = []

            # Analyze for each STRIDE category
            for stride_category, patterns in self.vulnerability_patterns.items():
                for pattern, description, cwe_id, severity in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                    for match in matches:
                        line_number = content[:match.start()].count('\n') + 1
                        code_snippet = self.extract_code_snippet(content, line_number)

                        # Calculate confidence based on context
                        confidence = self.calculate_confidence(pattern, code_snippet, content)

                        # Skip low-confidence findings to reduce false positives
                        if confidence < 0.5:
                            continue

                        finding_id = hashlib.sha256(
                            f"{project_name}:{file_path}:{line_number}:{stride_category}".encode()
                        ).hexdigest()[:16]

                        finding = ThreatFinding(
                            id=finding_id,
                            project_name=project_name,
                            file_path=str(file_path.relative_to(Path.cwd())),
                            line_number=line_number,
                            stride_category=stride_category,
                            threat_name=description,
                            description=f"{description} detected in {self.get_language(file_path)} code",
                            severity=severity,
                            confidence=confidence,
                            code_snippet=code_snippet,
                            cwe_id=cwe_id,
                            mitigation=self.get_mitigation(cwe_id),
                            attack_vector=self.get_attack_vector(stride_category)
                        )

                        findings.append(finding)

            return findings

        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return []

    def extract_code_snippet(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Extract code snippet with context."""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)

        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{lines[i]}")

        return '\n'.join(snippet_lines)

    def calculate_confidence(self, pattern: str, snippet: str, full_content: str) -> float:
        """Calculate confidence score for a finding."""
        confidence = 0.7  # Base confidence

        snippet_lower = snippet.lower()
        content_lower = full_content.lower()

        # Increase confidence for high-risk patterns
        if any(risk_word in pattern.lower() for risk_word in ['eval', 'exec', 'system', 'admin']):
            confidence += 0.2

        # Increase confidence if found in user input handling
        if any(input_word in snippet_lower for input_word in ['input', 'request', 'param', 'user']):
            confidence += 0.1

        # Decrease confidence if mitigations are present
        if any(mitigation in content_lower for mitigation in ['sanitize', 'validate', 'escape', 'secure']):
            confidence -= 0.2

        # Decrease confidence for test files
        if any(test_word in snippet_lower for test_word in ['test', 'mock', 'stub']):
            confidence -= 0.3

        return max(0.1, min(1.0, confidence))

    def get_language(self, file_path: Path) -> str:
        """Get programming language from file extension."""
        return self.language_map.get(file_path.suffix.lower(), 'Unknown')

    def get_mitigation(self, cwe_id: str) -> str:
        """Get mitigation advice for CWE."""
        mitigations = {
            'CWE-78': 'Use parameterized commands, input validation, and avoid shell execution',
            'CWE-79': 'Implement proper output encoding and Content Security Policy',
            'CWE-89': 'Use parameterized queries and input validation',
            'CWE-95': 'Avoid dynamic code execution, use safe alternatives',
            'CWE-209': 'Implement proper error handling without information disclosure',
            'CWE-269': 'Apply principle of least privilege and proper access controls',
            'CWE-287': 'Implement strong authentication mechanisms',
            'CWE-295': 'Enable proper certificate validation',
            'CWE-319': 'Use HTTPS/TLS for all communications',
            'CWE-328': 'Use strong cryptographic algorithms (SHA-256, bcrypt)',
            'CWE-532': 'Avoid logging sensitive information',
            'CWE-674': 'Implement recursion limits and resource controls',
            'CWE-778': 'Implement comprehensive logging and audit trails',
            'CWE-798': 'Use environment variables or secure credential management',
            'CWE-835': 'Implement proper loop controls and timeouts'
        }
        return mitigations.get(cwe_id, 'Implement security best practices')

    def get_attack_vector(self, stride_category: str) -> str:
        """Get attack vector for STRIDE category."""
        vectors = {
            'Spoofing': 'Identity theft, credential compromise, session hijacking',
            'Tampering': 'Data modification, code injection, integrity violations',
            'Repudiation': 'Log tampering, evidence destruction, transaction denial',
            'Information_Disclosure': 'Data leakage, privacy violations, sensitive exposure',
            'Denial_of_Service': 'Resource exhaustion, service disruption, availability attacks',
            'Elevation_of_Privilege': 'Privilege escalation, unauthorized access, admin compromise'
        }
        return vectors.get(stride_category, 'Various attack methods')

    def store_findings(self, findings: List[ThreatFinding]):
        """Store findings in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for finding in findings:
            cursor.execute('''
            INSERT OR REPLACE INTO threat_findings
            (id, project_name, file_path, line_number, stride_category, threat_name,
             description, severity, confidence, code_snippet, cwe_id, mitigation,
             attack_vector, created_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding.id, finding.project_name, finding.file_path, finding.line_number,
                finding.stride_category, finding.threat_name, finding.description,
                finding.severity, finding.confidence, finding.code_snippet,
                finding.cwe_id, finding.mitigation, finding.attack_vector,
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

    def generate_report(self, findings: List[ThreatFinding], project_name: str, output_dir: Path):
        """Generate threat modeling reports."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate JSON report
        self.generate_json_report(findings, project_name, output_dir)

        # Generate HTML report
        self.generate_html_report(findings, project_name, output_dir)

        # Generate text summary
        self.generate_text_report(findings, project_name, output_dir)

    def generate_json_report(self, findings: List[ThreatFinding], project_name: str, output_dir: Path):
        """Generate JSON report."""
        report_data = {
            'project_name': project_name,
            'analysis_date': datetime.now().isoformat(),
            'methodology': 'STRIDE',
            'total_findings': len(findings),
            'severity_distribution': self.get_severity_distribution(findings),
            'stride_distribution': self.get_stride_distribution(findings),
            'findings': [asdict(finding) for finding in findings]
        }

        json_path = output_dir / f"{project_name}_threat_analysis.json"
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"📄 JSON report: {json_path}")

    def generate_html_report(self, findings: List[ThreatFinding], project_name: str, output_dir: Path):
        """Generate HTML report."""
        html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Threat Analysis Report - {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin-bottom: 20px; }}
        .finding {{ border-left: 4px solid #3498db; padding: 15px; margin: 10px 0; background: #f8f9fa; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #27ae60; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 10px; font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>STRIDE Threat Analysis Report</h1>
        <h2>Project: {project_name}</h2>
        <p>Generated: {timestamp}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Findings:</strong> {total_findings}</p>
        <p><strong>Critical:</strong> {critical_count} | <strong>High:</strong> {high_count} |
           <strong>Medium:</strong> {medium_count} | <strong>Low:</strong> {low_count}</p>
        <p><strong>Analysis Methodology:</strong> STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)</p>
    </div>

    <h2>STRIDE Category Distribution</h2>
    <table>
        <tr><th>STRIDE Category</th><th>Count</th><th>Description</th></tr>
        {stride_table_rows}
    </table>

    <h2>Detailed Findings</h2>
    {findings_html}
</body>
</html>
        '''

        # Calculate statistics
        severity_counts = self.get_severity_distribution(findings)
        stride_counts = self.get_stride_distribution(findings)

        # Generate STRIDE table rows
        stride_descriptions = {
            'Spoofing': 'Identity impersonation and authentication attacks',
            'Tampering': 'Data and code modification attacks',
            'Repudiation': 'Denial of actions and audit trail attacks',
            'Information_Disclosure': 'Unauthorized data access and privacy violations',
            'Denial_of_Service': 'Availability and resource exhaustion attacks',
            'Elevation_of_Privilege': 'Unauthorized privilege escalation'
        }

        stride_rows = []
        for category, count in stride_counts.items():
            description = stride_descriptions.get(category, 'Security threat category')
            stride_rows.append(f'<tr><td>{category}</td><td>{count}</td><td>{description}</td></tr>')

        # Generate findings HTML
        findings_html = []
        for i, finding in enumerate(sorted(findings, key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x.severity, 4)), 1):
            finding_html = f'''
            <div class="finding {finding.severity.lower()}">
                <h3>{i}. {finding.threat_name}</h3>
                <p><strong>Severity:</strong> {finding.severity} |
                   <strong>STRIDE Category:</strong> {finding.stride_category} |
                   <strong>CWE:</strong> {finding.cwe_id}</p>
                <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
                <p><strong>Confidence:</strong> {finding.confidence:.2f}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Attack Vector:</strong> {finding.attack_vector}</p>
                <div class="code">
                    <strong>Code Evidence:</strong><br>
                    <pre>{finding.code_snippet}</pre>
                </div>
                <p><strong>Mitigation:</strong> {finding.mitigation}</p>
            </div>
            '''
            findings_html.append(finding_html)

        html_content = html_template.format(
            project_name=project_name,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_findings=len(findings),
            critical_count=severity_counts.get('Critical', 0),
            high_count=severity_counts.get('High', 0),
            medium_count=severity_counts.get('Medium', 0),
            low_count=severity_counts.get('Low', 0),
            stride_table_rows='\n'.join(stride_rows),
            findings_html='\n'.join(findings_html)
        )

        html_path = output_dir / f"{project_name}_threat_analysis.html"
        with open(html_path, 'w') as f:
            f.write(html_content)

        print(f"🌐 HTML report: {html_path}")

    def generate_text_report(self, findings: List[ThreatFinding], project_name: str, output_dir: Path):
        """Generate text summary report."""
        report_lines = [
            f"THREAT MODELING REPORT - {project_name}",
            "=" * 60,
            f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Methodology: STRIDE",
            f"Total Findings: {len(findings)}",
            "",
            "SEVERITY DISTRIBUTION:",
        ]

        severity_counts = self.get_severity_distribution(findings)
        for severity, count in severity_counts.items():
            report_lines.append(f"  {severity}: {count}")

        report_lines.extend([
            "",
            "STRIDE CATEGORY DISTRIBUTION:",
        ])

        stride_counts = self.get_stride_distribution(findings)
        for category, count in stride_counts.items():
            report_lines.append(f"  {category}: {count}")

        report_lines.extend([
            "",
            "TOP FINDINGS BY SEVERITY:",
            "-" * 40,
        ])

        # Sort findings by severity
        sorted_findings = sorted(findings, key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x.severity, 4))

        for i, finding in enumerate(sorted_findings[:10], 1):  # Top 10 findings
            report_lines.extend([
                f"{i}. {finding.threat_name} ({finding.severity})",
                f"   File: {finding.file_path}:{finding.line_number}",
                f"   STRIDE: {finding.stride_category} | CWE: {finding.cwe_id}",
                f"   Description: {finding.description}",
                ""
            ])

        text_path = output_dir / f"{project_name}_threat_summary.txt"
        with open(text_path, 'w') as f:
            f.write('\n'.join(report_lines))

        print(f"📝 Text summary: {text_path}")

    def get_severity_distribution(self, findings: List[ThreatFinding]) -> Dict[str, int]:
        """Get severity distribution."""
        distribution = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in findings:
            if finding.severity in distribution:
                distribution[finding.severity] += 1
        return distribution

    def get_stride_distribution(self, findings: List[ThreatFinding]) -> Dict[str, int]:
        """Get STRIDE category distribution."""
        distribution = {}
        for finding in findings:
            category = finding.stride_category
            distribution[category] = distribution.get(category, 0) + 1
        return distribution

def main():
    """Main function to run threat analysis."""
    print("🚀 STRIDE Threat Modeling Analyzer")
    print("=" * 50)

    current_dir = Path.cwd()
    analyzer = SimpleThreatAnalyzer()

    # Find project directories
    project_dirs = [
        d for d in current_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.') and d.name != 'threat_reports'
        and d.name.endswith('-master')  # Focus on the master projects
    ]

    if not project_dirs:
        print("❌ No project directories found")
        return

    print(f"📁 Found {len(project_dirs)} projects to analyze:")
    for proj in project_dirs:
        print(f"   • {proj.name}")

    # Analyze each project
    all_findings = []
    reports_dir = current_dir / 'threat_reports'

    for project_dir in project_dirs:
        print(f"\n{'='*60}")
        print(f"🔍 ANALYZING PROJECT: {project_dir.name}")
        print(f"{'='*60}")

        try:
            # Analyze project
            findings = analyzer.analyze_project(project_dir)
            all_findings.extend(findings)

            if findings:
                # Generate reports
                project_reports_dir = reports_dir / project_dir.name
                analyzer.generate_report(findings, project_dir.name, project_reports_dir)

                print(f"📊 Found {len(findings)} threats:")
                severity_dist = analyzer.get_severity_distribution(findings)
                for severity, count in severity_dist.items():
                    if count > 0:
                        print(f"   • {severity}: {count}")
            else:
                print("✅ No security threats detected")

        except Exception as e:
            print(f"❌ Error analyzing {project_dir.name}: {e}")

    # Generate overall summary
    if all_findings:
        print(f"\n{'='*60}")
        print("📊 OVERALL ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"Total Projects Analyzed: {len(project_dirs)}")
        print(f"Total Threats Found: {len(all_findings)}")

        overall_severity = analyzer.get_severity_distribution(all_findings)
        print("\nOverall Severity Distribution:")
        for severity, count in overall_severity.items():
            if count > 0:
                print(f"  {severity}: {count}")

        overall_stride = analyzer.get_stride_distribution(all_findings)
        print("\nOverall STRIDE Distribution:")
        for category, count in overall_stride.items():
            print(f"  {category}: {count}")

        print(f"\n📁 All reports saved to: {reports_dir}")
        print("📄 Report types generated:")
        print("   • JSON: Machine-readable threat data")
        print("   • HTML: Interactive threat analysis report")
        print("   • TXT: Executive summary")

    print(f"\n✅ Threat modeling analysis complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()