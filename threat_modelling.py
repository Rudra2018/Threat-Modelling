#!/usr/bin/env python3
"""
Bali Threat Modeler: Definitive Edition
PASTA & STRIDE Threat Modeling with a Local AI Ensemble and Gemini Pro anrichment.
"""

# --- 1. Setup & Dependency Installation ---
import subprocess
import sys
import os

try:
    from rich.console import Console
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "rich"])
    from rich.console import Console

console = Console()

def install_dependencies():
    """Installs all necessary libraries with better error handling."""
    console.log("[bold cyan]Step 1: Installing dependencies...[/bold cyan]")
    dependencies = [
        "fpdf2", "vertexai", "google-cloud-aiplatform",
        "graphviz", "rich", "tqdm", "PyYAML", "requests"
    ]
    
    for dep in dependencies:
        try:
            __import__(dep.replace('-', '_'))
            console.log(f"[green]✅ {dep} already installed[/green]")
        except ImportError:
            try:
                console.log(f"[yellow]Installing {dep}...[/yellow]")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", dep])
                console.log(f"[green]✅ {dep} installed successfully[/green]")
            except subprocess.CalledProcessError as e:
                console.log(f"[red]❌ Failed to install {dep}: {e}[/red]")
                return False
    return True

dependencies_installed = install_dependencies()

if dependencies_installed:
    # --- All other imports ---
    import json
    import yaml
    import textwrap
    import graphviz
    import asyncio
    import requests
    import time
    import argparse
    import re
    import hashlib
    import uuid
    from datetime import datetime, timedelta
    from pathlib import Path
    from fpdf import FPDF
    from typing import List, Dict, Any, Tuple, Set, Optional, Union
    from dataclasses import dataclass, field, asdict
    from enum import Enum
    import sqlite3
    from urllib.parse import urlparse
    from vertexai import init as vertexai_init
    from vertexai.generative_models import GenerativeModel
    from tqdm.asyncio import tqdm_asyncio
    from asyncio import to_thread
    import warnings

    # --- Suppress Warnings ---
    warnings.filterwarnings("ignore")
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    
    gemini = None # Global Gemini model instance

    # --- Professional PDF Reporting Class ---
    class ReportPDF(FPDF):
        """Generates a professional PDF report with diagrams, evidence, and remediation."""
        def __init__(self, project_name: str, font_paths: Dict[str, Path]):
            super().__init__()
            self.project_name = project_name
            self.set_margins(20, 20, 20)
            self.add_font("DejaVu", "", str(font_paths["regular"]), uni=True)
            self.add_font("DejaVu", "B", str(font_paths["bold"]), uni=True)
            self.add_font("DejaVuMono", "", str(font_paths["mono"]), uni=True)
            self.set_auto_page_break(auto=True, margin=20)
            self.toc_items = []

        def header(self):
            if self.page_no() == 1: return
            self.set_font("DejaVu", "", 9)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f"Threat Model Report: {self.project_name}", 0, 0, 'L')
            self.cell(0, 10, f"Page {self.page_no()}", 0, 0, 'R')

        def add_cover_page(self, num_findings):
            self.add_page()
            self.set_font("DejaVu", "B", 36)
            self.set_y(80)
            self.cell(0, 20, "Threat Model Report", 0, 1, 'C')
            self.set_font("DejaVu", "", 18)
            self.cell(0, 15, self.project_name, 0, 1, 'C')
            self.ln(20)
            self.set_font("DejaVu", "", 11)
            self.cell(0, 10, f"Date Generated: {time.strftime('%B %d, %Y')}", 0, 1, 'C')
            self.cell(0, 10, "Methodology: PASTA & STRIDE", 0, 1, 'C')
            self.cell(0, 10, f"Total Confirmed Vulnerabilities: {num_findings}", 0, 1, 'C')

        def add_toc(self):
            if len(self.pages) <= 1: return
            original_page = self.page_no()
            self.insert_page(2)
            self.set_font("DejaVu", "B", 18)
            self.cell(0, 15, "Table of Contents", 0, 1, 'L')
            self.ln(5)
            self.set_font("DejaVu", "", 11)
            for title, page_num in self.toc_items:
                dots = "." * (80 - len(title))
                self.cell(0, 8, f"{title} {dots} {page_num}", 0, 1, 'L')
            self.page = original_page + 1

        def add_section_title(self, title: str):
            if self.page_no() > 1 and self.y > 220: self.add_page()
            self.set_font("DejaVu", "B", 18)
            self.set_text_color(0, 0, 0)
            self.cell(0, 15, title, 0, 1, 'L')
            self.line(self.get_x(), self.get_y(), self.get_x() + 170, self.get_y())
            self.ln(5)
            self.toc_items.append((title, self.page_no()))

        def add_methodology_section(self):
            self.add_page()
            self.add_section_title("Methodology")
            self.set_font("DejaVu", "", 11)
            methodology_text = (
                "This report follows the PASTA (Process for Attack Simulation and Threat Analysis) methodology. "
                "The analysis was conducted using a hybrid AI workflow:\n\n"
                "  •  **Stage III & IV (Decomposition & Threat Analysis):** An ensemble of local Ollama models performed a private, full-code analysis to identify system components, data flows, and potential threats classified by the STRIDE framework.\n\n"
                "  •  **Stage V (Vulnerability Analysis):** Google's Gemini Pro model was used to validate each potential threat by analyzing only the relevant code snippet, providing an expert second opinion and detailed remediation.\n\n"
                "  •  **Stage VI (Attack Modeling):** Gemini Pro was used to generate architectural diagrams based on the initial local analysis, visualizing data flows and threats."
            )
            self.multi_cell(0, 7, methodology_text)

        def add_diagram(self, diagram_path: Path):
            if diagram_path.exists():
                self.add_page()
                title = diagram_path.stem.replace("_", " ").title()
                self.set_font("DejaVu", "B", 14)
                self.cell(0, 15, title, 0, 1, 'C')
                img_w = 170
                x_pos = self.l_margin + (self.w - 2 * self.l_margin - img_w) / 2
                self.image(str(diagram_path), w=img_w, x=x_pos)
                self.ln(5)

        def add_compliance_summary(self, vulnerabilities: List[Dict[str, Any]], controls_mapping: Dict[str, List[str]]):
            \"\"\"Adds a comprehensive compliance summary section.\"\"\"\n            self.add_page()\n            self.add_section_title(\"Executive Summary & Compliance Overview\")\n            \n            # Risk distribution\n            severity_counts = {\"Critical\": 0, \"High\": 0, \"Medium\": 0, \"Low\": 0}\n            owasp_categories = set()\n            mitre_techniques = set()\n            \n            for vuln in vulnerabilities:\n                severity_counts[vuln.get('severity', 'Low')] += 1\n                if vuln.get('owasp'):\n                    for owasp in vuln['owasp'] if isinstance(vuln['owasp'], list) else [vuln['owasp']]:\n                        owasp_categories.add(owasp.get('owasp_category', ''))\n                if vuln.get('mitre_attack'):\n                    for mitre in vuln['mitre_attack'] if isinstance(vuln['mitre_attack'], list) else [vuln['mitre_attack']]:\n                        mitre_techniques.add(mitre.get('technique_id', ''))\n            \n            self.set_font(\"DejaVu\", \"\", 11)\n            summary_text = f\"\"\"\n            RISK ASSESSMENT SUMMARY:\n            • Critical: {severity_counts['Critical']} vulnerabilities\n            • High: {severity_counts['High']} vulnerabilities  \n            • Medium: {severity_counts['Medium']} vulnerabilities\n            • Low: {severity_counts['Low']} vulnerabilities\n            \n            FRAMEWORK COVERAGE:\n            • OWASP Top 10: {len(owasp_categories)} categories affected\n            • MITRE ATT&CK: {len(mitre_techniques)} techniques identified\n            • NIST Controls: {len(set().union(*controls_mapping.values()))} controls recommended\n            \n            COMPLIANCE STATUS:\n            • SOC 2: {'CRITICAL - Immediate attention required' if severity_counts['Critical'] > 0 else 'REVIEW REQUIRED'}\n            • ISO 27001: {'NON-COMPLIANT' if severity_counts['Critical'] + severity_counts['High'] > 5 else 'REQUIRES REVIEW'}\n            • PCI DSS: {'CRITICAL GAPS' if any('injection' in str(v).lower() or 'crypto' in str(v).lower() for v in vulnerabilities) else 'REVIEW NEEDED'}\n            \"\"\"\n            self.multi_cell(0, 6, summary_text)\n        \n        def add_framework_mapping_section(self, vulnerabilities: List[Dict[str, Any]]):\n            \"\"\"Adds detailed framework mapping section.\"\"\"\n            self.add_page()\n            self.add_section_title(\"Security Framework Mappings\")\n            \n            # OWASP Top 10 Section\n            self.set_font(\"DejaVu\", \"B\", 12)\n            self.cell(0, 10, \"OWASP Top 10 2021 Mapping\", 0, 1)\n            self.set_font(\"DejaVu\", \"\", 10)\n            \n            owasp_summary = {}\n            for vuln in vulnerabilities:\n                if vuln.get('owasp'):\n                    owasp_list = vuln['owasp'] if isinstance(vuln['owasp'], list) else [vuln['owasp']]\n                    for owasp in owasp_list:\n                        category = owasp.get('owasp_category', 'Unknown')\n                        if category not in owasp_summary:\n                            owasp_summary[category] = 0\n                        owasp_summary[category] += 1\n            \n            for category, count in sorted(owasp_summary.items()):\n                self.cell(0, 6, f\"• {category}: {count} vulnerabilities\", 0, 1)\n            \n            # MITRE ATT&CK Section\n            self.ln(5)\n            self.set_font(\"DejaVu\", \"B\", 12)\n            self.cell(0, 10, \"MITRE ATT&CK Technique Mapping\", 0, 1)\n            self.set_font(\"DejaVu\", \"\", 10)\n            \n            mitre_summary = {}\n            for vuln in vulnerabilities:\n                if vuln.get('mitre_attack'):\n                    mitre_list = vuln['mitre_attack'] if isinstance(vuln['mitre_attack'], list) else [vuln['mitre_attack']]\n                    for mitre in mitre_list:\n                        technique = f\"{mitre.get('technique_id', '')}: {mitre.get('technique_name', '')}\"\n                        if technique not in mitre_summary:\n                            mitre_summary[technique] = 0\n                        mitre_summary[technique] += 1\n            \n            for technique, count in sorted(mitre_summary.items()):\n                self.cell(0, 6, f\"• {technique}: {count} instances\", 0, 1)\n        \n        def add_risk_matrix(self, vulnerabilities: List[Dict[str, Any]]):\n            \"\"\"Adds a risk assessment matrix.\"\"\"\n            self.add_page()\n            self.add_section_title(\"Risk Assessment Matrix\")\n            \n            # Calculate risk metrics\n            total_risk_score = sum(vuln.get('risk_score', 0) for vuln in vulnerabilities)\n            avg_cvss = sum(vuln.get('cvss_score', 0.0) for vuln in vulnerabilities) / max(len(vulnerabilities), 1)\n            \n            self.set_font(\"DejaVu\", \"\", 11)\n            risk_text = f\"\"\"\n            QUANTITATIVE RISK ASSESSMENT:\n            \n            • Total Risk Score: {total_risk_score}/1000\n            • Average CVSS Score: {avg_cvss:.1f}/10.0\n            • Risk Level: {'EXTREME' if total_risk_score > 700 else 'HIGH' if total_risk_score > 400 else 'MODERATE' if total_risk_score > 200 else 'LOW'}\n            \n            BUSINESS IMPACT ASSESSMENT:\n            • Confidentiality Impact: {'HIGH' if any(v.get('cvss_score', 0) > 7 for v in vulnerabilities) else 'MEDIUM'}\n            • Integrity Impact: {'HIGH' if any('tampering' in str(v).lower() for v in vulnerabilities) else 'MEDIUM'}\n            • Availability Impact: {'HIGH' if any('denial' in str(v).lower() for v in vulnerabilities) else 'MEDIUM'}\n            \n            REMEDIATION PRIORITY:\n            • Immediate (0-30 days): {sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')} items\n            • Short-term (1-3 months): {sum(1 for v in vulnerabilities if v.get('severity') == 'High')} items  \n            • Long-term (3-12 months): {sum(1 for v in vulnerabilities if v.get('severity') in ['Medium', 'Low'])} items\n            \"\"\"\n            self.multi_cell(0, 6, risk_text)\n\n        def add_validated_finding(self, index: int, finding: Dict[str, Any]):
            if self.y > 180: self.add_page()
            severity = finding.get('severity', 'Unknown')
            color_map = {"Critical": (217, 0, 0), "High": (255, 102, 0), "Medium": (255, 191, 0), "Low": (0, 128, 0)}
            
            self.set_fill_color(*color_map.get(severity, (128, 128, 128)))
            self.set_text_color(255, 255, 255)
            self.set_font("DejaVu", "B", 12)
            self.cell(0, 10, f" {index}. {finding.get('vulnerability_name', 'N/A')}", 0, 1, 'L', fill=True)
            self.ln(3)

            self.set_text_color(0, 0, 0)
            details = [
                ("Severity:", severity),
                ("STRIDE Category:", finding.get('stride_category', 'N/A')),
                ("CWE:", finding.get('cwe', 'N/A')),
                ("Detected By:", ', '.join(finding.get('detected_by', ['N/A']))),
                ("Location:", f"{finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}")
            ]
            for title, value in details:
                self.set_font("DejaVu", "B", 10); self.cell(40, 7, title, 0, 0)
                self.set_font("DejaVu", "", 10); self.multi_cell(0, 7, value, 0, 1)

            self.ln(2); self.set_font("DejaVu", "B", 10); self.cell(0, 7, "Description:", 0, 1)
            self.set_font("DejaVu", "", 10); self.multi_cell(0, 6, textwrap.fill(finding.get('description', 'N/A'), width=100))

            if finding.get('snippet'):
                self.ln(2); self.set_font("DejaVu", "B", 10); self.cell(0, 7, "Evidence (Code Snippet):", 0, 1)
                self.set_font("DejaVuMono", "", 8); self.set_fill_color(245, 245, 245)
                self.multi_cell(0, 5, finding['snippet'].strip(), border=1, fill=True)

            self.ln(2); self.set_font("DejaVu", "B", 10); self.cell(0, 7, "Remediation Summary:", 0, 1)
            self.set_font("DejaVu", "", 10); self.multi_cell(0, 6, textwrap.fill(finding.get('mitigation', 'N/A'), width=100))
            self.ln(8)

    def validate_path(path: str) -> Path:
        """Validates and secures file paths to prevent path traversal."""
        try:
            path_obj = Path(path).resolve()
            # Prevent path traversal attacks
            if '..' in str(path_obj) or str(path_obj).startswith('/'):
                if not str(path_obj).startswith('/Users') and not str(path_obj).startswith('/tmp'):
                    raise ValueError(f"Invalid path detected: {path}")
            return path_obj
        except Exception as e:
            raise ValueError(f"Path validation failed: {e}")
    
    def safe_read_text(file_path: Path, max_size: int = 50000) -> str:
        """Safely reads text files with size limits and encoding handling."""
        try:
            if not file_path.exists() or file_path.stat().st_size > max_size:
                return ""
            return file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            console.log(f"[yellow]Warning: Could not read {file_path}: {e}[/yellow]")
            return ""

    def get_json_from_response(text: str) -> Dict[str, Any] | None:
        """Extracts JSON from AI response text, handling various formats."""
        try:
            # Try direct JSON parsing first
            return json.loads(text.strip())
        except json.JSONDecodeError:
            # Look for JSON within code blocks or text
            patterns = [
                r'```(?:json)?\s*({.*?})\s*```',
                r'({\s*".*?"\s*:.*?})',
                r'JSON:\s*({.*?})'
            ]
            for pattern in patterns:
                match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
                if match:
                    try:
                        return json.loads(match.group(1))
                    except json.JSONDecodeError:
                        continue
            console.log(f"[yellow]Warning: Could not extract JSON from response: {text[:200]}...[/yellow]")
            return None
        except Exception as e:
            console.log(f"[yellow]Warning: JSON parsing error: {e}[/yellow]")
            return None
            
    def load_config(config_path: str = "threat_model_config.yaml") -> Dict[str, Any]:
        """Loads configuration from YAML file with defaults."""
        default_config = {
            "max_file_size": 50000,
            "timeout": 300,
            "max_models": 5,
            "max_dirs": 10,
            "max_files_per_dir": 5,
            "priority_files": [
                "pom.xml", "package.json", "go.mod", "docker-compose.yml", 
                "Dockerfile", "main.go", "main.py", "index.js", "index.ts", 
                "requirements.txt", "Cargo.toml", "build.gradle", "CMakeLists.txt"
            ],
            "severity_order": {"Critical": 0, "High": 1, "Medium": 2, "Low": 3},
            "color_map": {
                "Critical": [217, 0, 0], "High": [255, 102, 0], 
                "Medium": [255, 191, 0], "Low": [0, 128, 0]
            },
            "font_urls": {
                "regular": "https://github.com/senotrusov/dejavu-fonts-ttf/raw/refs/heads/master/ttf/DejaVuSans.ttf",
                "bold": "https://github.com/senotrusov/dejavu-fonts-ttf/raw/refs/heads/master/ttf/DejaVuSans-Bold.ttf",
                "mono": "https://github.com/senotrusov/dejavu-fonts-ttf/raw/refs/heads/master/ttf/DejaVuSansMono.ttf"
            }
        }
        
        try:
            if Path(config_path).exists():
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    default_config.update(user_config)
                    console.log(f"[green]Configuration loaded from {config_path}[/green]")
            else:
                console.log(f"[yellow]Config file {config_path} not found, using defaults[/yellow]")
        except Exception as e:
            console.log(f"[yellow]Error loading config: {e}. Using defaults.[/yellow]")
            
        return default_config

    # --- Enhanced Threat Intelligence and Framework Integration ---
    
    class RiskLevel(Enum):
        """Risk level enumeration for consistent risk assessment."""
        CRITICAL = "Critical"
        HIGH = "High"
        MEDIUM = "Medium"
        LOW = "Low"
        INFO = "Info"
    
    @dataclass
    class OwaspMapping:
        """OWASP Top 10 vulnerability mapping."""
        owasp_category: str
        owasp_id: str
        description: str
        impact: str
        likelihood: str
        

    @dataclass
    class MitreAttack:
        """MITRE ATT&CK framework mapping."""
        technique_id: str
        technique_name: str
        tactic: str
        description: str
        detection: str
        mitigation: str
        
    @dataclass
    class NistControl:
        """NIST Cybersecurity Framework control mapping."""
        function: str  # Identify, Protect, Detect, Respond, Recover
        category: str
        subcategory: str
        control_id: str
        description: str
        implementation_guidance: str
    
    @dataclass
    class ThreatIntelligence:
        """Threat intelligence data structure."""
        indicator: str
        indicator_type: str  # IP, domain, hash, etc.
        threat_actor: str
        campaign: str
        confidence: int  # 0-100
        last_seen: datetime
        source: str
        
    def get_owasp_top10_mapping() -> Dict[str, OwaspMapping]:
        """Returns OWASP Top 10 2021 vulnerability mappings."""
        return {
            "A01_2021": OwaspMapping(
                "Broken Access Control", "A01:2021",
                "Failures typically lead to unauthorized information disclosure, modification or destruction of all data.",
                "High", "Common"
            ),
            "A02_2021": OwaspMapping(
                "Cryptographic Failures", "A02:2021",
                "Sensitive data exposure due to weak cryptographic implementation.",
                "High", "Common"
            ),
            "A03_2021": OwaspMapping(
                "Injection", "A03:2021",
                "Application accepts hostile data without validation, filtering, or sanitization.",
                "High", "Common"
            ),
            "A04_2021": OwaspMapping(
                "Insecure Design", "A04:2021",
                "Missing or ineffective control design to prevent attacks.",
                "High", "Common"
            ),
            "A05_2021": OwaspMapping(
                "Security Misconfiguration", "A05:2021",
                "Insecure default configurations, incomplete configurations, or misconfigured HTTP headers.",
                "Medium", "Common"
            ),
            "A06_2021": OwaspMapping(
                "Vulnerable and Outdated Components", "A06:2021",
                "Applications with known vulnerable components.",
                "Medium", "Widespread"
            ),
            "A07_2021": OwaspMapping(
                "Identification and Authentication Failures", "A07:2021",
                "Confirmation of user's identity, authentication, and session management.",
                "High", "Common"
            ),
            "A08_2021": OwaspMapping(
                "Software and Data Integrity Failures", "A08:2021",
                "Code and infrastructure that does not protect against integrity violations.",
                "High", "Uncommon"
            ),
            "A09_2021": OwaspMapping(
                "Security Logging and Monitoring Failures", "A09:2021",
                "Insufficient logging, detection, monitoring and active response.",
                "Medium", "Widespread"
            ),
            "A10_2021": OwaspMapping(
                "Server-Side Request Forgery", "A10:2021",
                "SSRF flaws allow attackers to send crafted requests from the server.",
                "Medium", "Uncommon"
            )
        }
    
    def get_mitre_attack_mapping() -> Dict[str, MitreAttack]:
        """Returns common MITRE ATT&CK technique mappings."""
        return {
            "T1190": MitreAttack(
                "T1190", "Exploit Public-Facing Application", "Initial Access",
                "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
                "Monitor application logs for unusual activity patterns",
                "Implement proper input validation and regular security updates"
            ),
            "T1055": MitreAttack(
                "T1055", "Process Injection", "Privilege Escalation",
                "Adversaries may inject code into processes in order to evade process-based defenses.",
                "Monitor for unusual process behavior and memory modifications",
                "Implement application isolation and least privilege principles"
            ),
            "T1078": MitreAttack(
                "T1078", "Valid Accounts", "Persistence",
                "Adversaries may obtain and abuse credentials of existing accounts.",
                "Monitor for unusual login patterns and credential usage",
                "Implement multi-factor authentication and regular access reviews"
            ),
            "T1083": MitreAttack(
                "T1083", "File and Directory Discovery", "Discovery",
                "Adversaries may enumerate files and directories to find sensitive data.",
                "Monitor file system access patterns",
                "Implement proper file system permissions and access controls"
            ),
            "T1041": MitreAttack(
                "T1041", "Exfiltration Over C2 Channel", "Exfiltration",
                "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "Monitor network traffic for unusual data transfers",
                "Implement data loss prevention and network segmentation"
            )
        }
    
    def get_nist_controls() -> Dict[str, NistControl]:
        """Returns NIST Cybersecurity Framework control mappings."""
        return {
            "ID.AM-1": NistControl(
                "Identify", "Asset Management", "ID.AM-1", "ID.AM-1",
                "Physical devices and systems within the organization are inventoried",
                "Maintain an up-to-date inventory of all physical devices and systems"
            ),
            "PR.AC-1": NistControl(
                "Protect", "Access Control", "PR.AC-1", "PR.AC-1",
                "Identities and credentials are issued, managed, verified, revoked",
                "Implement identity and access management systems with proper lifecycle management"
            ),
            "DE.CM-1": NistControl(
                "Detect", "Continuous Monitoring", "DE.CM-1", "DE.CM-1",
                "The network is monitored to detect potential cybersecurity events",
                "Deploy network monitoring tools and establish baseline behavior patterns"
            ),
            "RS.RP-1": NistControl(
                "Respond", "Response Planning", "RS.RP-1", "RS.RP-1",
                "Response plan is executed during or after an incident",
                "Develop, test, and maintain incident response procedures"
            ),
            "RC.RP-1": NistControl(
                "Recover", "Recovery Planning", "RC.RP-1", "RC.RP-1",
                "Recovery plan is executed during or after a cybersecurity incident",
                "Establish recovery procedures and regularly test backup systems"
            )
        }
    
    def calculate_cvss_score(attack_vector: str, attack_complexity: str, privileges_required: str, 
                           user_interaction: str, scope: str, confidentiality: str, 
                           integrity: str, availability: str) -> float:
        """Calculate CVSS v3.1 base score."""
        # CVSS v3.1 scoring logic (simplified)
        av_scores = {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2}
        ac_scores = {"Low": 0.77, "High": 0.44}
        pr_scores = {"None": 0.85, "Low": 0.62, "High": 0.27}
        ui_scores = {"None": 0.85, "Required": 0.62}
        impact_scores = {"None": 0, "Low": 0.22, "High": 0.56}
        
        exploitability = 8.22 * av_scores.get(attack_vector, 0.85) * ac_scores.get(attack_complexity, 0.77) * \
                        pr_scores.get(privileges_required, 0.85) * ui_scores.get(user_interaction, 0.85)
        
        impact = 1 - ((1 - impact_scores.get(confidentiality, 0)) * 
                     (1 - impact_scores.get(integrity, 0)) * 
                     (1 - impact_scores.get(availability, 0)))
        
        if scope == "Changed":
            impact = 7.52 * (impact - 0.029) - 3.25 * pow(impact - 0.02, 15)
        else:
            impact = 6.42 * impact
            
        if impact <= 0:
            return 0.0
            
        if scope == "Changed":
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)
            
        return round(base_score, 1)
    
    def map_vulnerability_to_frameworks(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a vulnerability to various security frameworks."""
        owasp_mappings = get_owasp_top10_mapping()
        mitre_mappings = get_mitre_attack_mapping()
        nist_controls = get_nist_controls()
        
        # Smart mapping based on vulnerability characteristics
        cwe = vulnerability.get('cwe', '')
        description = vulnerability.get('description', '').lower()
        
        framework_mapping = {
            'owasp': [],
            'mitre_attack': [],
            'nist': [],
            'cvss_score': 0.0,
            'risk_score': 0
        }
        
        # OWASP mapping logic
        if 'injection' in description or 'CWE-89' in cwe:
            framework_mapping['owasp'].append(owasp_mappings['A03_2021'])
        elif 'access' in description or 'authorization' in description:
            framework_mapping['owasp'].append(owasp_mappings['A01_2021'])
        elif 'crypto' in description or 'encryption' in description:
            framework_mapping['owasp'].append(owasp_mappings['A02_2021'])
        elif 'authentication' in description or 'session' in description:
            framework_mapping['owasp'].append(owasp_mappings['A07_2021'])
        elif 'configuration' in description:
            framework_mapping['owasp'].append(owasp_mappings['A05_2021'])
        elif 'component' in description or 'dependency' in description:
            framework_mapping['owasp'].append(owasp_mappings['A06_2021'])
        
        # MITRE ATT&CK mapping
        if 'web' in description or 'application' in description:
            framework_mapping['mitre_attack'].append(mitre_mappings['T1190'])
        elif 'process' in description or 'injection' in description:
            framework_mapping['mitre_attack'].append(mitre_mappings['T1055'])
        elif 'credential' in description or 'authentication' in description:
            framework_mapping['mitre_attack'].append(mitre_mappings['T1078'])
        elif 'file' in description or 'directory' in description:
            framework_mapping['mitre_attack'].append(mitre_mappings['T1083'])
        
        # NIST controls mapping
        framework_mapping['nist'].extend([
            nist_controls['ID.AM-1'],
            nist_controls['PR.AC-1'],
            nist_controls['DE.CM-1']
        ])
        
        # Calculate CVSS score (simplified logic)
        severity = vulnerability.get('severity', 'Medium')
        if severity == 'Critical':
            framework_mapping['cvss_score'] = calculate_cvss_score(
                "Network", "Low", "None", "None", "Changed", "High", "High", "High")
        elif severity == 'High':
            framework_mapping['cvss_score'] = calculate_cvss_score(
                "Network", "Low", "Low", "None", "Unchanged", "High", "High", "Low")
        elif severity == 'Medium':
            framework_mapping['cvss_score'] = calculate_cvss_score(
                "Network", "High", "Low", "Required", "Unchanged", "Low", "Low", "None")
        else:
            framework_mapping['cvss_score'] = calculate_cvss_score(
                "Local", "High", "High", "Required", "Unchanged", "Low", "None", "None")
        
        # Custom risk scoring
        framework_mapping['risk_score'] = min(100, int(framework_mapping['cvss_score'] * 10))
        
        return framework_mapping
    
    def create_security_controls_database() -> sqlite3.Connection:\n        \"\"\"Creates and populates a SQLite database with security controls mapping.\"\"\"\n        conn = sqlite3.connect(':memory:')\n        cursor = conn.cursor()\n        \n        # Create tables\n        cursor.execute('''\n        CREATE TABLE vulnerabilities (\n            id TEXT PRIMARY KEY,\n            name TEXT,\n            cwe TEXT,\n            owasp_category TEXT,\n            cvss_score REAL,\n            severity TEXT,\n            description TEXT,\n            file_path TEXT,\n            line_number INTEGER,\n            created_date TEXT\n        )\n        ''')\n        \n        cursor.execute('''\n        CREATE TABLE security_controls (\n            control_id TEXT PRIMARY KEY,\n            framework TEXT,\n            category TEXT,\n            description TEXT,\n            implementation_guidance TEXT,\n            effectiveness_score INTEGER\n        )\n        ''')\n        \n        cursor.execute('''\n        CREATE TABLE vulnerability_controls (\n            vulnerability_id TEXT,\n            control_id TEXT,\n            applicability_score REAL,\n            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),\n            FOREIGN KEY (control_id) REFERENCES security_controls(control_id)\n        )\n        ''')\n        \n        # Populate security controls\n        nist_controls = get_nist_controls()\n        for control_id, control in nist_controls.items():\n            cursor.execute(\n                \"INSERT INTO security_controls VALUES (?, ?, ?, ?, ?, ?)\",\n                (control_id, \"NIST\", control.category, control.description, \n                 control.implementation_guidance, 85)\n            )\n        \n        conn.commit()\n        return conn\n    \n    def map_vulnerabilities_to_controls(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:\n        \"\"\"Maps vulnerabilities to applicable security controls.\"\"\"\n        conn = create_security_controls_database()\n        cursor = conn.cursor()\n        \n        vulnerability_controls = {}\n        \n        for vuln in vulnerabilities:\n            vuln_id = vuln.get('vulnerability_id', 'unknown')\n            vulnerability_controls[vuln_id] = []\n            \n            # Store vulnerability in database\n            cursor.execute(\n                \"INSERT OR REPLACE INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\",\n                (\n                    vuln_id, vuln.get('vulnerability_name', ''), vuln.get('cwe', ''),\n                    vuln.get('owasp', {}).get('owasp_category', '') if vuln.get('owasp') else '',\n                    vuln.get('cvss_score', 0.0), vuln.get('severity', ''),\n                    vuln.get('description', ''), vuln.get('file', ''),\n                    vuln.get('line', 0), vuln.get('discovered_date', '')\n                )\n            )\n            \n            # Map to controls based on characteristics\n            cwe = vuln.get('cwe', '')\n            description = vuln.get('description', '').lower()\n            \n            # Query relevant controls\n            if 'access' in description or 'authorization' in description:\n                cursor.execute(\"SELECT control_id FROM security_controls WHERE category LIKE '%Access%'\")\n            elif 'crypto' in description or 'encryption' in description:\n                cursor.execute(\"SELECT control_id FROM security_controls WHERE description LIKE '%crypt%' OR description LIKE '%encrypt%'\")\n            elif 'monitoring' in description or 'logging' in description:\n                cursor.execute(\"SELECT control_id FROM security_controls WHERE category LIKE '%Monitor%'\")\n            else:\n                cursor.execute(\"SELECT control_id FROM security_controls WHERE effectiveness_score >= 80\")\n            \n            controls = [row[0] for row in cursor.fetchall()]\n            vulnerability_controls[vuln_id].extend(controls)\n            \n            # Store mappings\n            for control_id in controls:\n                cursor.execute(\n                    \"INSERT INTO vulnerability_controls VALUES (?, ?, ?)\",\n                    (vuln_id, control_id, 0.8)  # Default applicability score\n                )\n        \n        conn.commit()\n        conn.close()\n        return vulnerability_controls\n    \n    def save_default_config(config_path: str = "threat_model_config.yaml"):
        """Saves a default configuration file for user customization."""
        if Path(config_path).exists():
            return
            
        config = load_config()
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            console.log(f"[green]Default configuration saved to {config_path}[/green]")
        except Exception as e:
            console.log(f"[yellow]Error saving config: {e}[/yellow]")

    @dataclass
    class RawThreat:
        \"\"\"Represents a potential threat identified by local models.\"\"\"\n        service: str\n        file: str\n        line: int\n        stride_category: str\n        threat_description: str\n        snippet: str\n        detected_by: List[str] = field(default_factory=list)

    @dataclass
    class ValidatedVulnerability:
        \"\"\"Represents a validated vulnerability confirmed by Gemini.\"\"\"\n        stride_category: str\n        is_vulnerability: bool\n        severity: str\n        cwe: str\n        description: str\n        mitigation: str\n        service: str\n        file: str\n        line: int\n        snippet: str\n        detected_by: List[str]

    def discover_ollama_models() -> List[str]:
        """Automatically discovers all locally available Ollama models."""
        console.log("[bold cyan]Auto-discovering local Ollama models...[/bold cyan]")
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, check=True)
            models = [line.split()[0] for line in result.stdout.strip().split('\n')[1:]]
            if not models:
                console.log("[bold red]FATAL: No Ollama models found. Please run 'ollama pull <model_name>' first.[/bold red]")
                sys.exit(1)
            console.log(f"[green]✅ Found {len(models)} models: {', '.join(models)}[/green]")
            return models
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            console.log(f"[bold red]FATAL: Failed to list Ollama models. Is Ollama installed and in your PATH? Error: {e}[/bold red]")
            sys.exit(1)

    async def _run_single_model_analysis(model: str, context: str) -> Dict[str, Any]:
        """Helper to run analysis for one model asynchronously."""
        console.log(f"[ensemble] Analyzing with {model}...")
        prompt = f"""
        As a security architect (PASTA Stage IV), analyze the provided file contexts for comprehensive threat modeling.
        
        INSTRUCTIONS:
        1. Decompose the application architecture (PASTA Stage III)
        2. Identify security threats using STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
        3. Consider attack chains and kill chains - how threats can be chained together
        4. Analyze data flows and trust boundaries
        5. Consider both technical and business logic vulnerabilities
        
        ENHANCED ANALYSIS AREAS:
        - Authentication and authorization mechanisms
        - Input validation and sanitization
        - Cryptographic implementations
        - Session management
        - Error handling and information disclosure
        - Business logic flaws
        - Infrastructure and configuration issues
        - Third-party components and dependencies
        
        File Context: {context}
        
        Respond ONLY with a single JSON object:
        {{
          "services": [{{"name": "...", "type": "...", "trust_level": "...", "data_classification": "..."}}],
          "interactions": [{{"source": "...", "target": "...", "protocol": "...", "data_flow": "...", "trust_boundary_crossed": true}}],
          "threats": [{{"service": "...", "file": "...", "line": 123, "stride_category": "...", "threat_description": "...", "snippet": "...", "attack_chain": ["step1", "step2"], "business_impact": "..."}}]
        }}
        """
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, lambda: requests.post(
                "http://127.0.0.1:11434/api/generate",
                json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
                timeout=300  # Reduced timeout for better responsiveness
            ))
            response.raise_for_status()
            analysis = json.loads(response.json()["response"])
            for threat in analysis.get("threats", []): threat['detected_by'] = [model]
            return analysis
        except requests.exceptions.ConnectionError:
            console.log(f"\n[bold red]FATAL: Ollama connection failed for model {model}. Is Ollama running on port 11434?[/bold red]")
            sys.exit(1)
        except requests.exceptions.Timeout:
            console.log(f"[yellow]Warning: Timeout occurred for model {model}. Skipping...[/yellow]")
            return {}
        except json.JSONDecodeError as e:
            console.log(f"[yellow]Warning: Invalid JSON response from model {model}: {e}[/yellow]")
            return {}
        except Exception as e:
            console.log(f"[yellow]Warning: Analysis failed for model {model}: {type(e).__name__}: {e}[/yellow]")
            return {}
    
    # --- Threat Intelligence Integration ---
    
    async def fetch_threat_intelligence() -> List[ThreatIntelligence]:
        """Fetches threat intelligence from multiple sources."""
        # Simulated threat intelligence (in production, integrate with real feeds)
        mock_intel = [
            ThreatIntelligence(
                "192.168.1.100", "IP", "APT29", "CozyBear Campaign", 85,
                datetime.now() - timedelta(days=2), "MISP"
            ),
            ThreatIntelligence(
                "malicious-domain.com", "Domain", "Lazarus Group", "Financial Sector Attack", 92,
                datetime.now() - timedelta(hours=6), "CyberThreatIntel"
            ),
            ThreatIntelligence(
                "e3b0c44298fc1c149afbf4c8996fb924", "Hash", "Unknown", "Malware Campaign", 78,
                datetime.now() - timedelta(days=1), "VirusTotal"
            )
        ]
        return mock_intel
    
    def correlate_threats_with_intelligence(vulnerabilities: List[Dict[str, Any]], 
                                           threat_intel: List[ThreatIntelligence]) -> Dict[str, List[str]]:
        """Correlates identified vulnerabilities with threat intelligence."""
        correlations = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('vulnerability_id', 'unknown')
            correlations[vuln_id] = []
            
            vuln_desc = vuln.get('description', '').lower()
            
            for intel in threat_intel:
                correlation_score = 0
                reasons = []
                
                if intel.confidence > 80:
                    if 'injection' in vuln_desc and 'web' in intel.campaign.lower():
                        correlation_score = 0.8
                        reasons.append("Web application attack pattern match")
                    elif 'authentication' in vuln_desc and 'credential' in intel.campaign.lower():
                        correlation_score = 0.7
                        reasons.append("Credential-based attack correlation")
                    elif 'crypto' in vuln_desc and any(actor in intel.threat_actor for actor in ['APT', 'Lazarus']):
                        correlation_score = 0.6
                        reasons.append("Advanced persistent threat correlation")
                
                if correlation_score > 0.5:
                    correlations[vuln_id].append({
                        'threat_actor': intel.threat_actor,
                        'campaign': intel.campaign,
                        'correlation_score': correlation_score,
                        'reasons': reasons,
                        'confidence': intel.confidence,
                        'source': intel.source
                    })
        
        return correlations

    @dataclass
    class AttackChain:
        """Represents a sequence of attack steps forming a kill chain."""
        chain_id: str
        name: str
        steps: List[str]
        likelihood: float
        impact: str
        mitre_tactics: List[str]
        
    def generate_attack_trees(threats: List[RawThreat]) -> List[AttackChain]:
        """Generate attack chains and kill chains from identified threats."""
        chains = []
        
        # Group threats by attack patterns
        injection_threats = [t for t in threats if 'injection' in t.threat_description.lower()]
        auth_threats = [t for t in threats if any(word in t.threat_description.lower() for word in ['auth', 'session', 'login'])]
        access_threats = [t for t in threats if 'access' in t.threat_description.lower()]
        
        # Create attack chains
        if injection_threats and access_threats:
            chains.append(AttackChain(
                "CHAIN-001", "Injection to Privilege Escalation",
                ["Initial compromise via injection", "Lateral movement", "Privilege escalation", "Data exfiltration"],
                0.7, "High", ["Initial Access", "Privilege Escalation", "Exfiltration"]
            ))
        
        if auth_threats:
            chains.append(AttackChain(
                "CHAIN-002", "Authentication Bypass Chain",
                ["Credential discovery", "Session hijacking", "Account takeover", "Persistent access"],
                0.6, "High", ["Credential Access", "Persistence", "Lateral Movement"]
            ))
            
        return chains
    
    def aggregate_threats(all_analyses: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[RawThreat]]:
        """Deduplicates and aggregates threats found by multiple models."""
        if not all_analyses: return {}, []
        final_analysis = {"services": all_analyses[0].get("services", []), "interactions": all_analyses[0].get("interactions", [])}
        aggregated_threats = {}
        for analysis in all_analyses:
            for threat in analysis.get("threats", []):
                key = (threat.get("file"), threat.get("line"), threat.get("stride_category"))
                if key not in aggregated_threats:
                    aggregated_threats[key] = threat
                else:
                    aggregated_threats[key]['detected_by'] = list(set(aggregated_threats[key]['detected_by'] + threat.get('detected_by', [])))
        
        raw_threats = [RawThreat(**t) for t in aggregated_threats.values()]
        
        # Generate attack chains
        attack_chains = generate_attack_trees(raw_threats)
        final_analysis['attack_chains'] = [asdict(chain) for chain in attack_chains]
        
        return final_analysis, raw_threats

    async def analyze_threats_with_ensemble(root: Path, models: List[str], max_file_size: int = 50000) -> Tuple[Dict[str, Any], List[RawThreat]]:
        console.log(f"[bold cyan]PASTA Stage III & IV: Starting ensemble analysis with {len(models)} models...[/bold cyan]")
        
        # Enhanced file discovery with performance optimizations
        priority_files = [
            "pom.xml", "package.json", "go.mod", "docker-compose.yml", "Dockerfile", 
            "main.go", "main.py", "index.js", "index.ts", "requirements.txt", 
            "Cargo.toml", "build.gradle", "CMakeLists.txt"
        ]
        
        context_files = []
        processed_files = set()
        
        # Limit analysis to reasonable scope
        max_dirs = 10
        max_files_per_dir = 5
        
        sub_projects = [d for d in root.iterdir() if d.is_dir()][:max_dirs] or [root]
        
        for project_dir in sub_projects:
            files_processed = 0
            for p_file in priority_files:
                if files_processed >= max_files_per_dir:
                    break
                    
                file_path = project_dir / p_file
                if file_path.exists() and file_path.is_file() and file_path not in processed_files:
                    content = safe_read_text(file_path, max_file_size)
                    if content:
                        # Truncate large files for context efficiency
                        truncated_content = content[:2000] if len(content) > 2000 else content
                        context_files.append(f"--- File: {file_path.relative_to(root)} ---\n```\n{truncated_content}\n```")
                        processed_files.add(file_path)
                        files_processed += 1
        
        if not context_files:
            console.log("[yellow]Warning: No relevant files found for analysis[/yellow]")
            return {}, []
            
        context = "\n\n".join(context_files)
        console.log(f"[green]Analyzing {len(context_files)} files across {len(sub_projects)} directories[/green]")

        # Run analyses with semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(3)  # Limit to 3 concurrent model calls
        async def limited_analysis(model):
            async with semaphore:
                return await _run_single_model_analysis(model, context)
        
        tasks = [limited_analysis(model) for model in models]
        all_analyses = await tqdm_asyncio.gather(*tasks, desc="Running Ensemble Analysis")
        return aggregate_threats([res for res in all_analyses if res])

    # --- Enhanced Validation with Framework Mapping ---
    async def validate_threat_with_gemini(threat: RawThreat) -> Dict | None:
        prompt = f"""
        As a senior application security expert (PASTA Stage V), validate this potential threat flagged by the models: {', '.join(threat.detected_by)}.
        Is this a real, exploitable vulnerability in the provided code snippet?

        Threat Category (STRIDE): {threat.stride_category}
        Threat Description: {threat.threat_description}
        File: {threat.file}
        Code Snippet (Evidence):\n```\n{threat.snippet}\n```

        Respond ONLY with a valid JSON object:
        {{
          "vulnerability_name": "...", "is_vulnerability": boolean, "reasoning": "...", 
          "cwe": "CWE-XXX", "severity": "High", "description": "...", "mitigation": "..."
        }}
        """
        try:
            response = await to_thread(gemini.generate_content, prompt)
            data = get_json_from_response(response.text)
            if data and data.get("is_vulnerability"):
                # Carry over all necessary fields for the final report
                data['stride_category'] = threat.stride_category
                data['service'] = threat.service; data['file'] = threat.file; data['line'] = threat.line
                data['snippet'] = threat.snippet; data['detected_by'] = threat.detected_by
                
                # Add enhanced framework mappings
                framework_mappings = map_vulnerability_to_frameworks(data)
                data.update(framework_mappings)
                
                # Generate unique vulnerability ID
                data['vulnerability_id'] = f"BALI-{hashlib.sha256(f'{threat.file}:{threat.line}:{threat.stride_category}'.encode()).hexdigest()[:8]}"
                data['discovered_date'] = datetime.now().isoformat()
                
                return data
        except Exception as e: console.log(f"[yellow]Warning: Gemini validation error: {e}[/yellow]")
        return None

    async def generate_diagrams_with_gemini(analysis: Dict[str, Any], output_path: Path, project_name: str) -> List[Path]:
        console.log("[bold cyan]PASTA Stage VI: Modeling attack vectors with Gemini-enhanced diagrams...[/bold cyan]")
        diagram_paths = []
        prompt = f"""
        As a system architect (PASTA Stage VI), use the following system analysis to generate diagrams in Graphviz DOT language. Create a Data Flow Diagram (DFD) and a Threat Model diagram visualizing the STRIDE threats.
        System Analysis JSON:\n```json\n{json.dumps(analysis, indent=2)}\n```
        Respond ONLY with a single JSON object:\n{{ "dfd_dot": "digraph G {{ ... }}", "threat_model_dot": "digraph G {{ ... }}" }}
        """
        response_text = await to_thread(gemini.generate_content, prompt)
        if response_text and (diagram_codes := get_json_from_response(response_text.text)):
            for key, dot_code in diagram_codes.items():
                name = key.replace('_dot', '')
                diagram_base_path = output_path / f"{project_name}_{name}"
                try:
                    source = graphviz.Source(dot_code)
                    source.render(str(diagram_base_path), format='png', cleanup=True)
                    final_path = diagram_base_path.with_suffix('.png')
                    if final_path.exists():
                        diagram_paths.append(final_path)
                        console.log(f"[green]✅ Diagram '{final_path.name}' generated.[/green]")
                except Exception as e: console.log(f"[red]Diagram rendering failed for {name}: {e}[/red]")
        return diagram_paths

    async def main():
        parser = argparse.ArgumentParser(description="Bali PASTA & STRIDE AI Threat Modeler (Ensemble Edition)")
        parser.add_argument("--local-path", required=True, help="Path to a local directory containing project(s) to analyze.")
        parser.add_argument("--gcp-project-id", required=True, help="Your Google Cloud Project ID.")
        parser.add_argument("--gcp-region", default="us-central1", help="Your Google Cloud region.")
        parser.add_argument("--max-file-size", type=int, help="Maximum file size to analyze (bytes)")
        parser.add_argument("--timeout", type=int, help="Timeout for AI model calls (seconds)")
        parser.add_argument("--config", default="threat_model_config.yaml", help="Configuration file path")
        parser.add_argument("--save-config", action="store_true", help="Save default configuration file and exit")
        args = parser.parse_args()
        
        # Handle config file generation
        if args.save_config:
            save_default_config(args.config)
            return
            
        # Load configuration
        config = load_config(args.config)
        
        # Override config with command line arguments
        if args.max_file_size:
            config['max_file_size'] = args.max_file_size
        if args.timeout:
            config['timeout'] = args.timeout
        
        # Input validation
        try:
            project_dir = validate_path(args.local_path)
            if not project_dir.exists() or not project_dir.is_dir():
                console.log(f"[bold red]Error: Directory {args.local_path} does not exist or is not a directory[/bold red]")
                return
            
            if not re.match(r'^[a-z][a-z0-9-]*[a-z0-9]$', args.gcp_project_id):
                console.log(f"[bold red]Error: Invalid GCP project ID format: {args.gcp_project_id}[/bold red]")
                return
                
        except ValueError as e:
            console.log(f"[bold red]Error: {e}[/bold red]")
            return

        # --- Setup Phase ---
        console.log("\n[bold cyan]Step 2: Setting up environment...[/bold cyan]")
        report_dir = project_dir.parent / "threat_reports"
        font_dir = project_dir.parent / "threat_report_fonts"
        report_dir.mkdir(parents=True, exist_ok=True)
        font_dir.mkdir(parents=True, exist_ok=True)
        
        font_paths = {"regular": font_dir / "DejaVuSans.ttf", "bold": font_dir / "DejaVuSans-Bold.ttf", "mono": font_dir / "DejaVuSansMono.ttf"}
        for url, path in [
            ("https://github.com/senotrusov/dejavu-fonts-ttf/raw/refs/heads/master/ttf/DejaVuSans.ttf", font_paths["regular"]),
            ("https://github.com/senotrusov/dejavu-fonts-ttf/raw/refs/heads/master/ttf/DejaVuSans-Bold.ttf", font_paths["bold"]),
            ("https://github.com/senotrusov/dejavu-fonts-ttf/raw/refs/heads/master/ttf/DejaVuSansMono.ttf", font_paths["mono"])
        ]:
            if not path.exists():
                console.log(f"Downloading font: {path.name}...")
                path.write_bytes(requests.get(url).content)

        global gemini
        try:
            console.log("\n[bold cyan]Step 3: Initializing Gemini Pro model...[/bold cyan]")
            vertexai_init(project=args.gcp_project_id, location=args.gcp_region)
            gemini = GenerativeModel("gemini-1.5-pro")
            console.log("[green]✅ Gemini initialized successfully.[/green]")
        except Exception as e:
            console.log(f"[bold red]FATAL: Gemini initialization failed. Have you run 'gcloud auth application-default login'? Error: {e}[/bold red]")
            return

        # --- Analysis Phase ---
        ollama_models = discover_ollama_models()
        # Limit number of models for performance
        if len(ollama_models) > 5:
            console.log(f"[yellow]Using first 5 models out of {len(ollama_models)} for performance[/yellow]")
            ollama_models = ollama_models[:5]
            
        project_name = project_dir.name
        output_path = report_dir / project_name
        output_path.mkdir(parents=True, exist_ok=True)
        
        final_analysis, raw_threats = await analyze_threats_with_ensemble(project_dir, ollama_models, config['max_file_size'])
        if not final_analysis: console.log("[bold red]Exiting due to analysis failure.[/bold red]"); return
        console.log(f"[green]PASTA Stage IV complete. Found {len(raw_threats)} unique potential threats.[/green]")
        
        # --- Concurrent Validation and Diagramming ---
        console.log("[bold cyan]PASTA Stage V & VI: Starting concurrent validation and diagramming...[/bold cyan]")
        tasks_to_run = [validate_threat_with_gemini(t) for t in raw_threats]
        tasks_to_run.append(generate_diagrams_with_gemini(final_analysis, output_path, project_name))

        results = await tqdm_asyncio.gather(*tasks_to_run, desc="Processing with Gemini")
        
        validated_results = [res for res in results if isinstance(res, dict)]
        diagram_paths = next((res for res in results if isinstance(res, list)), [])
        
        validated_vulnerabilities = [ValidatedVulnerability(**v) for v in validated_results]
        console.log(f"[green]PASTA Stage V complete. Confirmed {len(validated_vulnerabilities)} vulnerabilities.[/green]")
        
        # --- Enhanced Analysis Integration ---
        console.log("[bold cyan]Integrating threat intelligence and security controls...[/bold cyan]")
        
        # Fetch threat intelligence
        threat_intel = await fetch_threat_intelligence()
        
        # Map vulnerabilities to security controls
        validated_results_dicts = [asdict(v) for v in validated_vulnerabilities]
        controls_mapping = map_vulnerabilities_to_controls(validated_results_dicts)
        
        # Correlate with threat intelligence
        threat_correlations = correlate_threats_with_intelligence(validated_results_dicts, threat_intel)
        
        console.log(f"[green]Enhanced analysis complete. {len(threat_intel)} threat intel indicators processed.[/green]")
        
        # --- Comprehensive Reporting Phase (PASTA Stage VII) ---
        console.log("[bold cyan]PASTA Stage VII: Generating comprehensive PDF report...[/bold cyan]")
        pdf = ReportPDF(project_name, font_paths)
        pdf.add_cover_page(len(validated_vulnerabilities))
        
        # Add executive summary with compliance overview
        if validated_results_dicts:
            pdf.add_compliance_summary(validated_results_dicts, controls_mapping)
            pdf.add_risk_matrix(validated_results_dicts)
        
        pdf.add_methodology_section()
        
        # Add framework mappings
        if validated_results_dicts:
            pdf.add_framework_mapping_section(validated_results_dicts)
        
        if diagram_paths:
            pdf.add_section_title("PASTA Stage VI: Architectural Diagrams")
            for path in diagram_paths: pdf.add_diagram(path)
        
        if validated_vulnerabilities:
            pdf.add_section_title("PASTA Stage V: Enhanced Vulnerability Findings")
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_findings = sorted(validated_vulnerabilities, key=lambda x: severity_order.get(x.severity, 4))
            for i, f_obj in enumerate(sorted_findings, 1):
                # Add enhanced data including framework mappings
                enhanced_finding = asdict(f_obj)
                if hasattr(f_obj, 'vulnerability_id'):
                    vuln_id = f_obj.vulnerability_id
                    enhanced_finding['security_controls'] = controls_mapping.get(vuln_id, [])
                    enhanced_finding['threat_correlations'] = threat_correlations.get(vuln_id, [])
                pdf.add_validated_finding(i, enhanced_finding)
        
        pdf.add_toc()
        pdf_output_path = report_dir / f"{project_name}_Enhanced_Threat_Model_Report.pdf"
        pdf.output(str(pdf_output_path))
        console.log(f"[bold green]✅ Success! Enhanced report saved to {pdf_output_path}[/bold green]")
        
        # Generate additional outputs
        json_output_path = report_dir / f"{project_name}_threat_model_data.json"
        with open(json_output_path, 'w') as f:
            json.dump({
                'vulnerabilities': validated_results_dicts,
                'controls_mapping': controls_mapping,
                'threat_intelligence': [asdict(intel) for intel in threat_intel],
                'threat_correlations': threat_correlations,
                'attack_chains': final_analysis.get('attack_chains', []),
                'metadata': {
                    'analysis_date': datetime.now().isoformat(),
                    'models_used': ollama_models,
                    'total_vulnerabilities': len(validated_vulnerabilities),
                    'risk_score': sum(v.get('risk_score', 0) for v in validated_results_dicts)
                }
            }, indent=2, default=str)
        console.log(f"[green]✅ JSON data exported to {json_output_path}[/green]")

    if __name__ == "__main__":
        try:
            # nest_asyncio is helpful in environments like Jupyter/Colab
            try:
                import nest_asyncio
                nest_asyncio.apply()
            except ImportError:
                pass
            asyncio.run(main())
        except Exception as e:
            console.log(f"[bold red]An unexpected error occurred in the main execution block: {e}[/bold red]")

else:
    console.log("[bold red]Exiting because dependencies could not be installed.[/bold red]")