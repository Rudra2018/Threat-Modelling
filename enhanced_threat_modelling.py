#!/usr/bin/env python3
"""
Enhanced AI-Assisted Threat Modeling Tool
STRIDE Methodology with Claude Integration & Advanced Context Analysis
"""

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
    console.log("[bold cyan]Installing dependencies...[/bold cyan]")
    dependencies = [
        "fpdf2", "graphviz", "rich", "tqdm", "PyYAML", "requests",
        "anthropic", "networkx", "matplotlib", "seaborn", "plotly",
        "tree-sitter", "python-magic", "pygments", "tabulate", "click",
        "jinja2", "markdown", "weasyprint", "reportlab", "pillow"
    ]

    for dep in dependencies:
        try:
            __import__(dep.replace('-', '_').replace('python_', ''))
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
    import sqlite3
    import threading
    from datetime import datetime, timedelta
    from pathlib import Path
    from fpdf import FPDF
    from typing import List, Dict, Any, Tuple, Set, Optional, Union
    from dataclasses import dataclass, field, asdict
    from enum import Enum
    from urllib.parse import urlparse
    from tqdm.asyncio import tqdm_asyncio
    from asyncio import to_thread
    import warnings
    import networkx as nx
    import matplotlib.pyplot as plt
    import seaborn as sns
    import plotly.graph_objects as go
    import plotly.offline as pyo
    from anthropic import Anthropic
    import magic
    from pygments import highlight
    from pygments.lexers import get_lexer_by_name, guess_lexer
    from pygments.formatters import TerminalFormatter
    from tabulate import tabulate
    import click
    from jinja2 import Template
    import markdown

    # Suppress Warnings
    warnings.filterwarnings("ignore")
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'

    # Global variables
    claude_client = None
    threat_db = None

    @dataclass
    class CodeContext:
        """Enhanced code context with relationships and dependencies."""
        file_path: str
        language: str
        functions: List[Dict[str, Any]]
        classes: List[Dict[str, Any]]
        imports: List[str]
        exports: List[str]
        dependencies: List[str]
        data_flows: List[Dict[str, Any]]
        security_patterns: List[str]
        vulnerabilities: List[Dict[str, Any]]
        complexity_score: int
        risk_indicators: List[str]

    @dataclass
    class StrideCategory:
        """STRIDE threat categories with detailed analysis."""
        category: str
        threats: List[str]
        mitigations: List[str]
        attack_vectors: List[str]
        business_impact: str
        technical_impact: str
        likelihood: str

    @dataclass
    class ThreatModel:
        """Complete threat model with enhanced analysis."""
        project_name: str
        architecture_components: List[Dict[str, Any]]
        data_flows: List[Dict[str, Any]]
        trust_boundaries: List[Dict[str, Any]]
        stride_threats: List[Dict[str, Any]]
        attack_chains: List[Dict[str, Any]]
        vulnerabilities: List[Dict[str, Any]]
        risk_assessment: Dict[str, Any]
        mitigations: List[Dict[str, Any]]
        compliance_mapping: Dict[str, Any]

    def get_stride_categories() -> Dict[str, StrideCategory]:
        """Returns comprehensive STRIDE threat categories."""
        return {
            "Spoofing": StrideCategory(
                "Spoofing",
                ["Identity spoofing", "Authentication bypass", "Credential theft", "Session hijacking"],
                ["Strong authentication", "Multi-factor authentication", "Certificate validation", "Token-based auth"],
                ["Credential stuffing", "Phishing", "Man-in-the-middle", "Session fixation"],
                "Identity theft, unauthorized access", "System compromise", "High"
            ),
            "Tampering": StrideCategory(
                "Tampering",
                ["Data modification", "Code injection", "Configuration tampering", "Memory corruption"],
                ["Input validation", "Code signing", "Integrity checks", "Secure coding"],
                ["SQL injection", "XSS", "Buffer overflow", "Race conditions"],
                "Data corruption, financial loss", "System instability", "High"
            ),
            "Repudiation": StrideCategory(
                "Repudiation",
                ["Log tampering", "Transaction denial", "Audit trail gaps", "Digital signature bypass"],
                ["Comprehensive logging", "Digital signatures", "Audit trails", "Non-repudiation protocols"],
                ["Log injection", "Timestamp manipulation", "Evidence destruction"],
                "Legal liability, compliance violations", "Forensic analysis compromise", "Medium"
            ),
            "Information_Disclosure": StrideCategory(
                "Information Disclosure",
                ["Data leakage", "Privacy violation", "Sensitive data exposure", "Side-channel attacks"],
                ["Encryption", "Access controls", "Data classification", "Secure communication"],
                ["SQL injection", "Directory traversal", "Memory dumps", "Error messages"],
                "Privacy violations, competitive disadvantage", "Data breach", "High"
            ),
            "Denial_of_Service": StrideCategory(
                "Denial of Service",
                ["Resource exhaustion", "Service disruption", "System overload", "Network flooding"],
                ["Rate limiting", "Resource monitoring", "Load balancing", "Circuit breakers"],
                ["DDoS attacks", "Resource bombs", "Algorithmic complexity", "Memory exhaustion"],
                "Service unavailability, revenue loss", "System downtime", "Medium"
            ),
            "Elevation_of_Privilege": StrideCategory(
                "Elevation of Privilege",
                ["Privilege escalation", "Admin access", "Root compromise", "Role confusion"],
                ["Least privilege", "Role-based access", "Privilege separation", "Regular audits"],
                ["Buffer overflow", "Race conditions", "Configuration errors", "Insecure defaults"],
                "Complete system compromise", "Full system control", "Critical"
            )
        }

    class ThreatDatabase:
        """SQLite database for storing threat intelligence and analysis results."""

        def __init__(self, db_path: str = "threat_intelligence.db"):
            self.db_path = db_path
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.lock = threading.Lock()
            self._initialize_schema()

        def _initialize_schema(self):
            """Initialize database schema."""
            with self.lock:
                cursor = self.conn.cursor()

                # Projects table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    language TEXT,
                    framework TEXT,
                    created_date TEXT,
                    last_analyzed TEXT,
                    risk_score INTEGER DEFAULT 0
                )
                ''')

                # Code contexts table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS code_contexts (
                    id TEXT PRIMARY KEY,
                    project_id TEXT,
                    file_path TEXT,
                    language TEXT,
                    complexity_score INTEGER,
                    functions_count INTEGER,
                    classes_count INTEGER,
                    imports_count INTEGER,
                    context_data TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id)
                )
                ''')

                # Threats table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id TEXT PRIMARY KEY,
                    project_id TEXT,
                    stride_category TEXT,
                    threat_name TEXT,
                    description TEXT,
                    severity TEXT,
                    likelihood TEXT,
                    impact TEXT,
                    cwe TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    code_snippet TEXT,
                    attack_vector TEXT,
                    mitigation TEXT,
                    verified BOOLEAN DEFAULT FALSE,
                    false_positive BOOLEAN DEFAULT FALSE,
                    created_date TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects(id)
                )
                ''')

                # Vulnerabilities table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    threat_id TEXT,
                    project_id TEXT,
                    vulnerability_name TEXT,
                    cvss_score REAL,
                    exploitability_score REAL,
                    confidence_score REAL,
                    poc_available BOOLEAN DEFAULT FALSE,
                    poc_code TEXT,
                    remediation_effort TEXT,
                    business_impact TEXT,
                    detected_by TEXT,
                    validated_by TEXT,
                    FOREIGN KEY (threat_id) REFERENCES threats(id),
                    FOREIGN KEY (project_id) REFERENCES projects(id)
                )
                ''')

                self.conn.commit()

        def store_project(self, project_data: Dict[str, Any]) -> str:
            """Store project information."""
            with self.lock:
                cursor = self.conn.cursor()
                project_id = project_data.get('id', str(uuid.uuid4()))
                cursor.execute('''
                INSERT OR REPLACE INTO projects
                (id, name, path, language, framework, created_date, last_analyzed, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    project_id, project_data.get('name', ''), project_data.get('path', ''),
                    project_data.get('language', ''), project_data.get('framework', ''),
                    datetime.now().isoformat(), datetime.now().isoformat(),
                    project_data.get('risk_score', 0)
                ))
                self.conn.commit()
                return project_id

        def store_threat(self, threat_data: Dict[str, Any]) -> str:
            """Store threat information."""
            with self.lock:
                cursor = self.conn.cursor()
                threat_id = threat_data.get('id', str(uuid.uuid4()))
                cursor.execute('''
                INSERT OR REPLACE INTO threats
                (id, project_id, stride_category, threat_name, description, severity,
                 likelihood, impact, cwe, file_path, line_number, code_snippet,
                 attack_vector, mitigation, verified, false_positive, created_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat_id, threat_data.get('project_id', ''), threat_data.get('stride_category', ''),
                    threat_data.get('threat_name', ''), threat_data.get('description', ''),
                    threat_data.get('severity', ''), threat_data.get('likelihood', ''),
                    threat_data.get('impact', ''), threat_data.get('cwe', ''),
                    threat_data.get('file_path', ''), threat_data.get('line_number', 0),
                    threat_data.get('code_snippet', ''), threat_data.get('attack_vector', ''),
                    threat_data.get('mitigation', ''), threat_data.get('verified', False),
                    threat_data.get('false_positive', False), datetime.now().isoformat()
                ))
                self.conn.commit()
                return threat_id

        def get_project_threats(self, project_id: str) -> List[Dict[str, Any]]:
            """Get all threats for a project."""
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT * FROM threats WHERE project_id = ? AND false_positive = FALSE
                ORDER BY severity DESC, likelihood DESC
                ''', (project_id,))
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        def mark_false_positive(self, threat_id: str, reason: str = ""):
            """Mark a threat as false positive."""
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                UPDATE threats SET false_positive = TRUE,
                mitigation = COALESCE(mitigation, '') || ' [FALSE POSITIVE: ' || ? || ']'
                WHERE id = ?
                ''', (reason, threat_id))
                self.conn.commit()

        def get_statistics(self, project_id: str = None) -> Dict[str, Any]:
            """Get threat statistics."""
            with self.lock:
                cursor = self.conn.cursor()
                where_clause = "WHERE project_id = ?" if project_id else ""
                params = (project_id,) if project_id else ()

                cursor.execute(f'''
                SELECT
                    COUNT(*) as total_threats,
                    SUM(CASE WHEN verified = TRUE THEN 1 ELSE 0 END) as verified_threats,
                    SUM(CASE WHEN false_positive = TRUE THEN 1 ELSE 0 END) as false_positives,
                    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_threats,
                    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high_threats,
                    SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium_threats,
                    SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low_threats
                FROM threats {where_clause}
                ''', params)

                result = cursor.fetchone()
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))

    class CodeAnalyzer:
        """Advanced code analysis with context awareness and dependency tracking."""

        def __init__(self):
            self.language_patterns = {
                'python': {
                    'function': r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                    'class': r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(:]',
                    'import': r'(?:from\s+[\w.]+\s+)?import\s+([\w.,\s*]+)',
                    'vulnerability_patterns': [
                        (r'eval\s*\(', 'Code injection via eval()'),
                        (r'exec\s*\(', 'Code injection via exec()'),
                        (r'os\.system\s*\(', 'Command injection'),
                        (r'subprocess\..*shell\s*=\s*True', 'Shell injection'),
                        (r'pickle\.loads?\s*\(', 'Unsafe deserialization'),
                        (r'yaml\.load\s*\((?!.*Loader)', 'Unsafe YAML loading'),
                        (r'sql.*\+.*input', 'Potential SQL injection'),
                        (r'open\s*\(\s*["\'].*\+', 'Path traversal risk'),
                    ]
                },
                'javascript': {
                    'function': r'(?:function\s+([a-zA-Z_][a-zA-Z0-9_]*)|([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function|\(.*\)\s*=>\s*)',
                    'class': r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                    'import': r'(?:import\s+.*\s+from\s+["\']([^"\']+)["\']|require\s*\(\s*["\']([^"\']+)["\'])',
                    'vulnerability_patterns': [
                        (r'eval\s*\(', 'Code injection via eval()'),
                        (r'innerHTML\s*=', 'XSS via innerHTML'),
                        (r'document\.write\s*\(', 'XSS via document.write'),
                        (r'\.html\s*\(.*\+', 'Potential XSS'),
                        (r'JSON\.parse\s*\(.*input', 'JSON injection'),
                        (r'localStorage\..*=.*input', 'Client-side injection'),
                        (r'window\.location.*=.*input', 'Open redirect'),
                    ]
                },
                'java': {
                    'function': r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                    'class': r'(?:public|private)?\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                    'import': r'import\s+([\w.]+)',
                    'vulnerability_patterns': [
                        (r'Runtime\.getRuntime\(\)\.exec', 'Command injection'),
                        (r'ProcessBuilder.*\.start\(\)', 'Command injection'),
                        (r'Statement.*execute.*\+', 'SQL injection'),
                        (r'PreparedStatement.*setString.*\+', 'SQL injection'),
                        (r'ObjectInputStream\.readObject', 'Unsafe deserialization'),
                        (r'Class\.forName\s*\(', 'Dynamic class loading'),
                        (r'System\.getProperty\s*\(.*input', 'Property injection'),
                    ]
                }
            }

        def detect_language(self, file_path: Path) -> str:
            """Detect programming language of file."""
            try:
                if file_path.suffix:
                    extension_map = {
                        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                        '.java': 'java', '.kt': 'kotlin', '.go': 'go',
                        '.php': 'php', '.rb': 'ruby', '.cs': 'csharp',
                        '.cpp': 'cpp', '.c': 'c', '.h': 'c'
                    }
                    return extension_map.get(file_path.suffix.lower(), 'unknown')

                # Use magic for files without extensions
                mime = magic.from_file(str(file_path), mime=True)
                if 'text' in mime:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')[:1000]
                    if 'def ' in content and 'import ' in content:
                        return 'python'
                    elif 'function ' in content or 'const ' in content:
                        return 'javascript'
                    elif 'public class' in content:
                        return 'java'

            except Exception:
                pass
            return 'unknown'

        def analyze_code_context(self, file_path: Path) -> CodeContext:
            """Perform comprehensive code analysis."""
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                language = self.detect_language(file_path)

                if language == 'unknown':
                    return CodeContext(
                        str(file_path), language, [], [], [], [], [], [], [], [], 0, []
                    )

                patterns = self.language_patterns.get(language, {})

                # Extract functions
                functions = []
                if 'function' in patterns:
                    for match in re.finditer(patterns['function'], content, re.MULTILINE):
                        func_name = match.group(1) or match.group(2) if match.lastindex > 1 else match.group(1)
                        if func_name:
                            functions.append({
                                'name': func_name,
                                'line': content[:match.start()].count('\n') + 1,
                                'complexity': self._calculate_complexity(match.group(0))
                            })

                # Extract classes
                classes = []
                if 'class' in patterns:
                    for match in re.finditer(patterns['class'], content, re.MULTILINE):
                        classes.append({
                            'name': match.group(1),
                            'line': content[:match.start()].count('\n') + 1
                        })

                # Extract imports
                imports = []
                if 'import' in patterns:
                    for match in re.finditer(patterns['import'], content, re.MULTILINE):
                        imports.append(match.group(1))

                # Analyze vulnerabilities
                vulnerabilities = []
                if 'vulnerability_patterns' in patterns:
                    for pattern, description in patterns['vulnerability_patterns']:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            line_num = content[:match.start()].count('\n') + 1
                            snippet = self._extract_code_snippet(content, line_num)
                            vulnerabilities.append({
                                'pattern': pattern,
                                'description': description,
                                'line': line_num,
                                'snippet': snippet,
                                'confidence': self._calculate_confidence(pattern, snippet)
                            })

                # Calculate complexity and risk
                complexity = len(functions) + len(classes) + len(imports)
                risk_indicators = self._identify_risk_indicators(content, language)

                return CodeContext(
                    str(file_path), language, functions, classes, imports, [],
                    [], [], [], vulnerabilities, complexity, risk_indicators
                )

            except Exception as e:
                console.log(f"[yellow]Error analyzing {file_path}: {e}[/yellow]")
                return CodeContext(str(file_path), 'unknown', [], [], [], [], [], [], [], [], 0, [])

        def _calculate_complexity(self, code_snippet: str) -> int:
            """Calculate code complexity score."""
            complexity = 0
            complexity += code_snippet.count('if ')
            complexity += code_snippet.count('for ')
            complexity += code_snippet.count('while ')
            complexity += code_snippet.count('try')
            complexity += code_snippet.count('except')
            complexity += code_snippet.count('catch')
            return complexity

        def _extract_code_snippet(self, content: str, line_num: int, context_lines: int = 3) -> str:
            """Extract code snippet with context."""
            lines = content.split('\n')
            start = max(0, line_num - context_lines - 1)
            end = min(len(lines), line_num + context_lines)
            return '\n'.join(lines[start:end])

        def _calculate_confidence(self, pattern: str, snippet: str) -> float:
            """Calculate confidence score for vulnerability detection."""
            base_confidence = 0.7

            # Increase confidence for more specific patterns
            if 'input' in snippet.lower():
                base_confidence += 0.2
            if any(word in snippet.lower() for word in ['user', 'request', 'param']):
                base_confidence += 0.1
            if 'sanitize' in snippet.lower() or 'validate' in snippet.lower():
                base_confidence -= 0.3

            return min(1.0, max(0.1, base_confidence))

        def _identify_risk_indicators(self, content: str, language: str) -> List[str]:
            """Identify security risk indicators in code."""
            risk_indicators = []
            content_lower = content.lower()

            # Common risk patterns
            if 'password' in content_lower and 'hard' in content_lower:
                risk_indicators.append("Hardcoded credentials detected")
            if 'api_key' in content_lower or 'secret' in content_lower:
                risk_indicators.append("Potential secret exposure")
            if 'admin' in content_lower and 'bypass' in content_lower:
                risk_indicators.append("Admin bypass pattern")
            if 'debug' in content_lower and ('true' in content_lower or 'on' in content_lower):
                risk_indicators.append("Debug mode enabled")
            if 'http://' in content_lower:
                risk_indicators.append("Insecure HTTP usage")
            if 'md5' in content_lower or 'sha1' in content_lower:
                risk_indicators.append("Weak cryptographic hash")

            return risk_indicators

    class StrideAnalyzer:
        """STRIDE-focused threat analysis with context awareness."""

        def __init__(self, claude_client: Anthropic):
            self.claude_client = claude_client
            self.stride_categories = get_stride_categories()

        async def analyze_stride_threats(self, code_context: CodeContext, project_context: Dict[str, Any]) -> List[Dict[str, Any]]:
            """Analyze STRIDE threats with context awareness."""
            threats = []

            # Analyze each STRIDE category
            for category_name, category in self.stride_categories.items():
                category_threats = await self._analyze_stride_category(
                    category_name, code_context, project_context
                )
                threats.extend(category_threats)

            # Validate threats with Claude
            validated_threats = []
            for threat in threats:
                validation = await self._validate_threat_with_claude(threat, code_context)
                if validation and validation.get('is_valid_threat', False):
                    threat.update(validation)
                    validated_threats.append(threat)

            return validated_threats

        async def _analyze_stride_category(self, category: str, code_context: CodeContext,
                                         project_context: Dict[str, Any]) -> List[Dict[str, Any]]:
            """Analyze specific STRIDE category."""
            threats = []

            # Pattern-based detection for each category
            if category == "Spoofing":
                threats.extend(self._detect_spoofing_threats(code_context))
            elif category == "Tampering":
                threats.extend(self._detect_tampering_threats(code_context))
            elif category == "Repudiation":
                threats.extend(self._detect_repudiation_threats(code_context))
            elif category == "Information_Disclosure":
                threats.extend(self._detect_info_disclosure_threats(code_context))
            elif category == "Denial_of_Service":
                threats.extend(self._detect_dos_threats(code_context))
            elif category == "Elevation_of_Privilege":
                threats.extend(self._detect_privilege_escalation_threats(code_context))

            return threats

        def _detect_spoofing_threats(self, context: CodeContext) -> List[Dict[str, Any]]:
            """Detect spoofing-related threats."""
            threats = []

            # Check for authentication weaknesses
            for vuln in context.vulnerabilities:
                if any(term in vuln['description'].lower() for term in ['auth', 'login', 'session']):
                    threats.append({
                        'stride_category': 'Spoofing',
                        'threat_name': f"Authentication bypass via {vuln['description']}",
                        'file_path': context.file_path,
                        'line_number': vuln['line'],
                        'code_snippet': vuln['snippet'],
                        'description': f"Potential authentication bypass: {vuln['description']}",
                        'severity': self._calculate_severity(vuln['confidence'], 'Spoofing'),
                        'attack_vector': "Credential theft, session hijacking",
                        'confidence': vuln['confidence']
                    })

            return threats

        def _detect_tampering_threats(self, context: CodeContext) -> List[Dict[str, Any]]:
            """Detect tampering-related threats."""
            threats = []

            for vuln in context.vulnerabilities:
                if any(term in vuln['description'].lower() for term in ['injection', 'eval', 'exec']):
                    threats.append({
                        'stride_category': 'Tampering',
                        'threat_name': f"Data tampering via {vuln['description']}",
                        'file_path': context.file_path,
                        'line_number': vuln['line'],
                        'code_snippet': vuln['snippet'],
                        'description': f"Code/data injection vulnerability: {vuln['description']}",
                        'severity': self._calculate_severity(vuln['confidence'], 'Tampering'),
                        'attack_vector': "Code injection, data modification",
                        'confidence': vuln['confidence']
                    })

            return threats

        def _detect_repudiation_threats(self, context: CodeContext) -> List[Dict[str, Any]]:
            """Detect repudiation-related threats."""
            threats = []

            # Check for logging issues
            content = Path(context.file_path).read_text(encoding='utf-8', errors='ignore')
            if 'log' not in content.lower() and len(context.functions) > 5:
                threats.append({
                    'stride_category': 'Repudiation',
                    'threat_name': "Insufficient logging and monitoring",
                    'file_path': context.file_path,
                    'line_number': 1,
                    'code_snippet': content[:200] + "...",
                    'description': "Lack of proper logging mechanisms for audit trails",
                    'severity': 'Medium',
                    'attack_vector': "Log tampering, evidence destruction",
                    'confidence': 0.6
                })

            return threats

        def _detect_info_disclosure_threats(self, context: CodeContext) -> List[Dict[str, Any]]:
            """Detect information disclosure threats."""
            threats = []

            # Check for sensitive data exposure
            for indicator in context.risk_indicators:
                if any(term in indicator.lower() for term in ['secret', 'password', 'key']):
                    threats.append({
                        'stride_category': 'Information_Disclosure',
                        'threat_name': f"Sensitive information exposure: {indicator}",
                        'file_path': context.file_path,
                        'line_number': 1,
                        'code_snippet': "",
                        'description': f"Potential sensitive data exposure: {indicator}",
                        'severity': 'High',
                        'attack_vector': "Source code analysis, configuration review",
                        'confidence': 0.8
                    })

            return threats

        def _detect_dos_threats(self, context: CodeContext) -> List[Dict[str, Any]]:
            """Detect denial of service threats."""
            threats = []

            # Check for resource exhaustion patterns
            content = Path(context.file_path).read_text(encoding='utf-8', errors='ignore')
            if any(pattern in content.lower() for pattern in ['while true', 'infinite', 'recursion']):
                threats.append({
                    'stride_category': 'Denial_of_Service',
                    'threat_name': "Potential resource exhaustion",
                    'file_path': context.file_path,
                    'line_number': 1,
                    'code_snippet': content[:200] + "...",
                    'description': "Code patterns that may lead to resource exhaustion",
                    'severity': 'Medium',
                    'attack_vector': "Resource bombs, algorithmic complexity attacks",
                    'confidence': 0.5
                })

            return threats

        def _detect_privilege_escalation_threats(self, context: CodeContext) -> List[Dict[str, Any]]:
            """Detect privilege escalation threats."""
            threats = []

            for vuln in context.vulnerabilities:
                if any(term in vuln['description'].lower() for term in ['admin', 'root', 'privilege']):
                    threats.append({
                        'stride_category': 'Elevation_of_Privilege',
                        'threat_name': f"Privilege escalation via {vuln['description']}",
                        'file_path': context.file_path,
                        'line_number': vuln['line'],
                        'code_snippet': vuln['snippet'],
                        'description': f"Potential privilege escalation: {vuln['description']}",
                        'severity': 'Critical',
                        'attack_vector': "Buffer overflow, race conditions, misconfigurations",
                        'confidence': vuln['confidence']
                    })

            return threats

        def _calculate_severity(self, confidence: float, stride_category: str) -> str:
            """Calculate threat severity based on confidence and category."""
            category_weights = {
                'Spoofing': 0.8, 'Tampering': 0.9, 'Repudiation': 0.6,
                'Information_Disclosure': 0.8, 'Denial_of_Service': 0.7, 'Elevation_of_Privilege': 1.0
            }

            weighted_score = confidence * category_weights.get(stride_category, 0.7)

            if weighted_score >= 0.8:
                return 'Critical'
            elif weighted_score >= 0.6:
                return 'High'
            elif weighted_score >= 0.4:
                return 'Medium'
            else:
                return 'Low'

        async def _validate_threat_with_claude(self, threat: Dict[str, Any], context: CodeContext) -> Dict[str, Any]:
            """Validate threat using Claude API with enhanced context."""
            try:
                prompt = f"""
                As a senior security architect, analyze this potential security threat identified in the codebase:

                THREAT DETAILS:
                - STRIDE Category: {threat['stride_category']}
                - Threat Name: {threat['threat_name']}
                - File: {threat['file_path']}
                - Line: {threat['line_number']}
                - Description: {threat['description']}
                - Initial Confidence: {threat['confidence']}

                CODE CONTEXT:
                ```{context.language}
                {threat['code_snippet']}
                ```

                ADDITIONAL CONTEXT:
                - Programming Language: {context.language}
                - File Functions: {len(context.functions)} functions
                - File Classes: {len(context.classes)} classes
                - Dependencies: {', '.join(context.imports[:5])}
                - Risk Indicators: {', '.join(context.risk_indicators)}

                Please provide a comprehensive analysis in JSON format:
                {{
                    "is_valid_threat": boolean,
                    "confidence_score": 0.0-1.0,
                    "severity": "Critical|High|Medium|Low",
                    "cwe_id": "CWE-XXX",
                    "cvss_score": 0.0-10.0,
                    "exploitability": "High|Medium|Low",
                    "business_impact": "description",
                    "technical_impact": "description",
                    "likelihood": "High|Medium|Low",
                    "attack_complexity": "High|Medium|Low",
                    "proof_of_concept": "step-by-step exploitation",
                    "detailed_description": "comprehensive threat analysis",
                    "mitigation_strategies": ["strategy1", "strategy2"],
                    "remediation_effort": "High|Medium|Low",
                    "false_positive_analysis": "why this might be false positive",
                    "additional_context_needed": "what additional info would help"
                }}
                """

                response = await to_thread(
                    self.claude_client.messages.create,
                    model="claude-3-sonnet-20240229",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )

                response_text = response.content[0].text

                # Extract JSON from response
                try:
                    # Try to find JSON in the response
                    json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                    if json_match:
                        return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass

                console.log(f"[yellow]Warning: Could not parse Claude response for threat validation[/yellow]")
                return None

            except Exception as e:
                console.log(f"[yellow]Warning: Claude validation failed: {e}[/yellow]")
                return None

    class EnhancedReportGenerator:
        """Generate comprehensive threat modeling reports with visualizations."""

        def __init__(self, output_dir: Path):
            self.output_dir = output_dir
            self.output_dir.mkdir(parents=True, exist_ok=True)

        def generate_comprehensive_report(self, threat_model: ThreatModel) -> Dict[str, Path]:
            """Generate all report formats."""
            report_paths = {}

            # Generate PDF report
            pdf_path = self._generate_pdf_report(threat_model)
            report_paths['pdf'] = pdf_path

            # Generate interactive HTML report
            html_path = self._generate_html_report(threat_model)
            report_paths['html'] = html_path

            # Generate threat model diagrams
            diagrams = self._generate_threat_diagrams(threat_model)
            report_paths['diagrams'] = diagrams

            # Generate data flow diagrams
            dfd_path = self._generate_data_flow_diagram(threat_model)
            report_paths['dfd'] = dfd_path

            # Generate JSON export
            json_path = self._generate_json_export(threat_model)
            report_paths['json'] = json_path

            return report_paths

        def _generate_pdf_report(self, threat_model: ThreatModel) -> Path:
            """Generate detailed PDF report."""
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors

            pdf_path = self.output_dir / f"{threat_model.project_name}_threat_model_report.pdf"
            doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=1
            )
            story.append(Paragraph(f"Threat Model Report: {threat_model.project_name}", title_style))
            story.append(Spacer(1, 20))

            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading1']))
            summary_text = f"""
            This report presents a comprehensive threat model analysis for {threat_model.project_name}
            using the STRIDE methodology. The analysis identified {len(threat_model.vulnerabilities)}
            verified vulnerabilities across {len(threat_model.stride_threats)} potential threat vectors.

            Risk Level: {threat_model.risk_assessment.get('overall_risk', 'Medium')}
            Total Components Analyzed: {len(threat_model.architecture_components)}
            Data Flows Identified: {len(threat_model.data_flows)}
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 20))

            # STRIDE Analysis Summary
            story.append(Paragraph("STRIDE Analysis Summary", styles['Heading1']))

            stride_data = []
            stride_data.append(['STRIDE Category', 'Threats Found', 'Severity Distribution'])

            for category in ['Spoofing', 'Tampering', 'Repudiation', 'Information_Disclosure',
                           'Denial_of_Service', 'Elevation_of_Privilege']:
                category_threats = [t for t in threat_model.stride_threats if t.get('stride_category') == category]
                severity_dist = {}
                for threat in category_threats:
                    sev = threat.get('severity', 'Unknown')
                    severity_dist[sev] = severity_dist.get(sev, 0) + 1

                severity_text = ', '.join([f"{k}: {v}" for k, v in severity_dist.items()])
                stride_data.append([category, str(len(category_threats)), severity_text])

            stride_table = Table(stride_data)
            stride_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(stride_table)
            story.append(Spacer(1, 20))

            # Detailed Vulnerability Findings
            story.append(Paragraph("Detailed Vulnerability Findings", styles['Heading1']))

            for i, vuln in enumerate(sorted(threat_model.vulnerabilities,
                                          key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x.get('severity', 'Low'), 4)), 1):

                story.append(Paragraph(f"{i}. {vuln.get('threat_name', 'Unknown Threat')}", styles['Heading2']))

                vuln_details = f"""
                <b>Severity:</b> {vuln.get('severity', 'Unknown')}<br/>
                <b>STRIDE Category:</b> {vuln.get('stride_category', 'Unknown')}<br/>
                <b>CWE:</b> {vuln.get('cwe_id', 'Unknown')}<br/>
                <b>CVSS Score:</b> {vuln.get('cvss_score', 'N/A')}<br/>
                <b>File:</b> {vuln.get('file_path', 'Unknown')}<br/>
                <b>Line:</b> {vuln.get('line_number', 'Unknown')}<br/>
                <br/>
                <b>Description:</b><br/>
                {vuln.get('detailed_description', vuln.get('description', 'No description available'))}
                <br/><br/>
                <b>Business Impact:</b><br/>
                {vuln.get('business_impact', 'Impact assessment not available')}
                <br/><br/>
                <b>Proof of Concept:</b><br/>
                {vuln.get('proof_of_concept', 'POC not available')}
                <br/><br/>
                <b>Mitigation Strategies:</b><br/>
                {'; '.join(vuln.get('mitigation_strategies', ['No mitigation provided']))}
                """

                story.append(Paragraph(vuln_details, styles['Normal']))
                story.append(Spacer(1, 15))

            doc.build(story)
            return pdf_path

        def _generate_html_report(self, threat_model: ThreatModel) -> Path:
            """Generate interactive HTML report."""
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Threat Model Report - {{ project_name }}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
                    .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
                    .threat { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
                    .critical { border-left: 4px solid #e74c3c; }
                    .high { border-left: 4px solid #f39c12; }
                    .medium { border-left: 4px solid #f1c40f; }
                    .low { border-left: 4px solid #27ae60; }
                    .code { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; font-family: monospace; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Threat Model Report: {{ project_name }}</h1>
                    <p>Generated on {{ generation_date }}</p>
                </div>

                <div class="section">
                    <h2>Executive Summary</h2>
                    <p>Total Vulnerabilities Found: {{ total_vulnerabilities }}</p>
                    <p>Overall Risk Level: {{ overall_risk }}</p>
                    <p>Analysis Methodology: STRIDE</p>
                </div>

                <div class="section">
                    <h2>STRIDE Analysis Overview</h2>
                    <table>
                        <tr><th>Category</th><th>Threats Found</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
                        {% for category, stats in stride_stats.items() %}
                        <tr>
                            <td>{{ category }}</td>
                            <td>{{ stats.total }}</td>
                            <td>{{ stats.critical }}</td>
                            <td>{{ stats.high }}</td>
                            <td>{{ stats.medium }}</td>
                            <td>{{ stats.low }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>

                <div class="section">
                    <h2>Detailed Vulnerability Findings</h2>
                    {% for vuln in vulnerabilities %}
                    <div class="threat {{ vuln.severity.lower() }}">
                        <h3>{{ vuln.threat_name }}</h3>
                        <p><strong>Severity:</strong> {{ vuln.severity }}</p>
                        <p><strong>STRIDE Category:</strong> {{ vuln.stride_category }}</p>
                        <p><strong>CWE:</strong> {{ vuln.cwe_id }}</p>
                        <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}</p>
                        <p><strong>File:</strong> {{ vuln.file_path }}:{{ vuln.line_number }}</p>
                        <p><strong>Description:</strong> {{ vuln.detailed_description }}</p>

                        {% if vuln.code_snippet %}
                        <h4>Code Evidence:</h4>
                        <div class="code">{{ vuln.code_snippet }}</div>
                        {% endif %}

                        <h4>Proof of Concept:</h4>
                        <p>{{ vuln.proof_of_concept }}</p>

                        <h4>Mitigation:</h4>
                        <ul>
                        {% for mitigation in vuln.mitigation_strategies %}
                            <li>{{ mitigation }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endfor %}
                </div>
            </body>
            </html>
            """

            # Prepare template data
            stride_stats = {}
            for category in ['Spoofing', 'Tampering', 'Repudiation', 'Information_Disclosure',
                           'Denial_of_Service', 'Elevation_of_Privilege']:
                category_threats = [t for t in threat_model.stride_threats if t.get('stride_category') == category]
                stats = {'total': len(category_threats), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for threat in category_threats:
                    severity = threat.get('severity', 'Low').lower()
                    if severity in stats:
                        stats[severity] += 1
                stride_stats[category] = stats

            template = Template(html_template)
            html_content = template.render(
                project_name=threat_model.project_name,
                generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_vulnerabilities=len(threat_model.vulnerabilities),
                overall_risk=threat_model.risk_assessment.get('overall_risk', 'Medium'),
                stride_stats=stride_stats,
                vulnerabilities=threat_model.vulnerabilities
            )

            html_path = self.output_dir / f"{threat_model.project_name}_threat_model_report.html"
            html_path.write_text(html_content, encoding='utf-8')
            return html_path

        def _generate_threat_diagrams(self, threat_model: ThreatModel) -> List[Path]:
            """Generate threat model diagrams."""
            diagram_paths = []

            # Create STRIDE threat diagram
            stride_path = self._generate_stride_diagram(threat_model)
            if stride_path:
                diagram_paths.append(stride_path)

            # Create attack chain diagram
            attack_chain_path = self._generate_attack_chain_diagram(threat_model)
            if attack_chain_path:
                diagram_paths.append(attack_chain_path)

            return diagram_paths

        def _generate_stride_diagram(self, threat_model: ThreatModel) -> Path:
            """Generate STRIDE threat visualization."""
            plt.figure(figsize=(12, 8))

            # Count threats by STRIDE category
            stride_counts = {}
            for threat in threat_model.stride_threats:
                category = threat.get('stride_category', 'Unknown')
                stride_counts[category] = stride_counts.get(category, 0) + 1

            categories = list(stride_counts.keys())
            counts = list(stride_counts.values())

            # Create bar chart
            bars = plt.bar(categories, counts, color=['#e74c3c', '#f39c12', '#f1c40f', '#27ae60', '#3498db', '#9b59b6'])

            plt.title(f'STRIDE Threat Distribution - {threat_model.project_name}', fontsize=16, fontweight='bold')
            plt.xlabel('STRIDE Categories', fontweight='bold')
            plt.ylabel('Number of Threats', fontweight='bold')
            plt.xticks(rotation=45, ha='right')

            # Add value labels on bars
            for bar, count in zip(bars, counts):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                        str(count), ha='center', va='bottom', fontweight='bold')

            plt.tight_layout()

            diagram_path = self.output_dir / f"{threat_model.project_name}_stride_diagram.png"
            plt.savefig(diagram_path, dpi=300, bbox_inches='tight')
            plt.close()

            return diagram_path

        def _generate_attack_chain_diagram(self, threat_model: ThreatModel) -> Path:
            """Generate attack chain visualization."""
            G = nx.DiGraph()

            # Add nodes for each threat
            for i, threat in enumerate(threat_model.stride_threats):
                node_id = f"T{i}"
                G.add_node(node_id,
                          label=threat.get('threat_name', f'Threat {i}')[:30],
                          category=threat.get('stride_category', 'Unknown'),
                          severity=threat.get('severity', 'Medium'))

            # Add edges based on attack chains
            for chain in threat_model.attack_chains:
                steps = chain.get('steps', [])
                for i in range(len(steps) - 1):
                    G.add_edge(f"T{i}", f"T{i+1}")

            plt.figure(figsize=(14, 10))
            pos = nx.spring_layout(G, k=2, iterations=50)

            # Color nodes by severity
            color_map = {'Critical': '#e74c3c', 'High': '#f39c12', 'Medium': '#f1c40f', 'Low': '#27ae60'}
            node_colors = [color_map.get(G.nodes[node].get('severity', 'Medium'), '#95a5a6') for node in G.nodes()]

            nx.draw(G, pos, node_color=node_colors, node_size=1000,
                   with_labels=True, font_size=8, font_weight='bold',
                   arrows=True, arrowsize=20, edge_color='gray')

            plt.title(f'Attack Chain Diagram - {threat_model.project_name}', fontsize=16, fontweight='bold')

            # Add legend
            legend_elements = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10, label=severity)
                             for severity, color in color_map.items()]
            plt.legend(handles=legend_elements, loc='upper right')

            plt.tight_layout()

            diagram_path = self.output_dir / f"{threat_model.project_name}_attack_chain_diagram.png"
            plt.savefig(diagram_path, dpi=300, bbox_inches='tight')
            plt.close()

            return diagram_path

        def _generate_data_flow_diagram(self, threat_model: ThreatModel) -> Path:
            """Generate data flow diagram."""
            dot = graphviz.Digraph(comment=f'Data Flow Diagram - {threat_model.project_name}')
            dot.attr(rankdir='TB', size='12,8')

            # Add nodes for components
            for component in threat_model.architecture_components:
                comp_name = component.get('name', 'Unknown')
                comp_type = component.get('type', 'component')

                if comp_type == 'database':
                    dot.node(comp_name, comp_name, shape='cylinder', style='filled', fillcolor='lightblue')
                elif comp_type == 'external':
                    dot.node(comp_name, comp_name, shape='box', style='filled', fillcolor='lightcoral')
                elif comp_type == 'process':
                    dot.node(comp_name, comp_name, shape='ellipse', style='filled', fillcolor='lightgreen')
                else:
                    dot.node(comp_name, comp_name, shape='box', style='filled', fillcolor='lightyellow')

            # Add edges for data flows
            for flow in threat_model.data_flows:
                source = flow.get('source', 'Unknown')
                target = flow.get('target', 'Unknown')
                data_type = flow.get('data_type', 'data')

                # Color edges by trust boundary crossing
                color = 'red' if flow.get('crosses_trust_boundary', False) else 'black'
                dot.edge(source, target, label=data_type, color=color)

            # Add trust boundaries
            for boundary in threat_model.trust_boundaries:
                boundary_name = boundary.get('name', 'Trust Boundary')
                dot.attr('graph', label=f'Trust Boundaries: {boundary_name}')

            diagram_path = self.output_dir / f"{threat_model.project_name}_data_flow_diagram"
            dot.render(diagram_path, format='png', cleanup=True)

            return Path(f"{diagram_path}.png")

        def _generate_json_export(self, threat_model: ThreatModel) -> Path:
            """Generate JSON export of threat model."""
            export_data = {
                'project_name': threat_model.project_name,
                'generation_date': datetime.now().isoformat(),
                'methodology': 'STRIDE',
                'architecture_components': threat_model.architecture_components,
                'data_flows': threat_model.data_flows,
                'trust_boundaries': threat_model.trust_boundaries,
                'stride_threats': threat_model.stride_threats,
                'attack_chains': threat_model.attack_chains,
                'vulnerabilities': threat_model.vulnerabilities,
                'risk_assessment': threat_model.risk_assessment,
                'mitigations': threat_model.mitigations,
                'compliance_mapping': threat_model.compliance_mapping,
                'statistics': {
                    'total_threats': len(threat_model.stride_threats),
                    'total_vulnerabilities': len(threat_model.vulnerabilities),
                    'severity_distribution': self._calculate_severity_distribution(threat_model.vulnerabilities),
                    'stride_distribution': self._calculate_stride_distribution(threat_model.stride_threats)
                }
            }

            json_path = self.output_dir / f"{threat_model.project_name}_threat_model_data.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)

            return json_path

        def _calculate_severity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
            """Calculate severity distribution."""
            distribution = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Low')
                if severity in distribution:
                    distribution[severity] += 1
            return distribution

        def _calculate_stride_distribution(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
            """Calculate STRIDE category distribution."""
            distribution = {}
            for threat in threats:
                category = threat.get('stride_category', 'Unknown')
                distribution[category] = distribution.get(category, 0) + 1
            return distribution

    async def analyze_project(project_path: Path, claude_api_key: str) -> ThreatModel:
        """Main function to analyze a project and generate threat model."""
        global claude_client, threat_db

        # Initialize Claude client
        claude_client = Anthropic(api_key=claude_api_key)

        # Initialize threat database
        threat_db = ThreatDatabase()

        console.log(f"[bold cyan]Starting STRIDE threat analysis for: {project_path.name}[/bold cyan]")

        # Store project in database
        project_data = {
            'name': project_path.name,
            'path': str(project_path),
            'language': 'mixed',
            'framework': 'unknown'
        }
        project_id = threat_db.store_project(project_data)

        # Initialize analyzers
        code_analyzer = CodeAnalyzer()
        stride_analyzer = StrideAnalyzer(claude_client)

        # Analyze code files
        code_contexts = []
        all_threats = []
        all_vulnerabilities = []

        # Find relevant files
        file_patterns = ['*.py', '*.js', '*.ts', '*.java', '*.php', '*.go', '*.rb', '*.cs']
        relevant_files = []

        for pattern in file_patterns:
            relevant_files.extend(project_path.rglob(pattern))

        # Limit analysis scope
        relevant_files = relevant_files[:50]  # Analyze up to 50 files

        console.log(f"[green]Found {len(relevant_files)} relevant files for analysis[/green]")

        # Analyze each file
        with console.status("[bold green]Analyzing code files...") as status:
            for file_path in relevant_files:
                try:
                    status.update(f"Analyzing {file_path.name}...")

                    # Analyze code context
                    context = code_analyzer.analyze_code_context(file_path)
                    if context.language != 'unknown':
                        code_contexts.append(context)

                        # Analyze STRIDE threats for this file
                        file_threats = await stride_analyzer.analyze_stride_threats(
                            context, {'project_id': project_id}
                        )

                        # Store threats in database
                        for threat in file_threats:
                            threat['project_id'] = project_id
                            threat_id = threat_db.store_threat(threat)
                            threat['id'] = threat_id

                            # Add to collections
                            all_threats.append(threat)
                            if threat.get('is_valid_threat', False):
                                all_vulnerabilities.append(threat)

                except Exception as e:
                    console.log(f"[yellow]Warning: Error analyzing {file_path}: {e}[/yellow]")

        # Build architecture model
        architecture_components = []
        data_flows = []
        trust_boundaries = []

        # Identify components based on code analysis
        for context in code_contexts:
            component = {
                'name': Path(context.file_path).stem,
                'type': 'process',
                'language': context.language,
                'functions': len(context.functions),
                'classes': len(context.classes),
                'complexity': context.complexity_score,
                'risk_level': 'High' if context.risk_indicators else 'Medium'
            }
            architecture_components.append(component)

        # Create simple data flows (this could be enhanced with static analysis)
        for i, comp1 in enumerate(architecture_components):
            for comp2 in architecture_components[i+1:]:
                if comp1['language'] == comp2['language']:  # Simple heuristic
                    data_flow = {
                        'source': comp1['name'],
                        'target': comp2['name'],
                        'data_type': 'API calls',
                        'protocol': 'HTTP',
                        'crosses_trust_boundary': comp1['risk_level'] != comp2['risk_level']
                    }
                    data_flows.append(data_flow)

        # Define trust boundaries
        trust_boundaries = [
            {'name': 'Application Boundary', 'description': 'Separates internal application from external interfaces'},
            {'name': 'Data Boundary', 'description': 'Separates data processing from data storage'}
        ]

        # Generate attack chains
        attack_chains = []
        spoofing_threats = [t for t in all_threats if t.get('stride_category') == 'Spoofing']
        tampering_threats = [t for t in all_threats if t.get('stride_category') == 'Tampering']

        if spoofing_threats and tampering_threats:
            attack_chains.append({
                'name': 'Authentication Bypass to Data Tampering',
                'description': 'Attacker bypasses authentication and then tampers with data',
                'steps': [
                    'Exploit authentication weakness',
                    'Gain unauthorized access',
                    'Tamper with sensitive data',
                    'Cover tracks'
                ],
                'likelihood': 'Medium',
                'impact': 'High'
            })

        # Calculate risk assessment
        risk_assessment = {
            'total_threats': len(all_threats),
            'verified_vulnerabilities': len(all_vulnerabilities),
            'critical_count': len([v for v in all_vulnerabilities if v.get('severity') == 'Critical']),
            'high_count': len([v for v in all_vulnerabilities if v.get('severity') == 'High']),
            'overall_risk': 'High' if any(v.get('severity') == 'Critical' for v in all_vulnerabilities) else 'Medium'
        }

        # Generate mitigations
        mitigations = []
        for vuln in all_vulnerabilities:
            for strategy in vuln.get('mitigation_strategies', []):
                mitigation = {
                    'vulnerability_id': vuln.get('id'),
                    'strategy': strategy,
                    'effort': vuln.get('remediation_effort', 'Medium'),
                    'priority': vuln.get('severity', 'Medium')
                }
                mitigations.append(mitigation)

        # Compliance mapping (simplified)
        compliance_mapping = {
            'OWASP_Top_10': [],
            'NIST_CSF': [],
            'ISO_27001': []
        }

        # Create threat model
        threat_model = ThreatModel(
            project_name=project_path.name,
            architecture_components=architecture_components,
            data_flows=data_flows,
            trust_boundaries=trust_boundaries,
            stride_threats=all_threats,
            attack_chains=attack_chains,
            vulnerabilities=all_vulnerabilities,
            risk_assessment=risk_assessment,
            mitigations=mitigations,
            compliance_mapping=compliance_mapping
        )

        console.log(f"[bold green]Analysis complete! Found {len(all_vulnerabilities)} verified vulnerabilities[/bold green]")

        return threat_model

    async def main():
        """Main function."""
        parser = argparse.ArgumentParser(description="Enhanced AI-Assisted Threat Modeling Tool")
        parser.add_argument("--project-path", required=True, help="Path to project directory")
        parser.add_argument("--claude-api-key", required=True, help="Claude API key")
        parser.add_argument("--output-dir", default="./threat_reports", help="Output directory for reports")
        args = parser.parse_args()

        # Validate inputs
        project_path = Path(args.project_path)
        if not project_path.exists() or not project_path.is_dir():
            console.log(f"[bold red]Error: Project path {project_path} does not exist or is not a directory[/bold red]")
            return

        output_dir = Path(args.output_dir)

        try:
            # Analyze all projects in directory
            if any(d.is_dir() and not d.name.startswith('.') for d in project_path.iterdir()):
                # Multiple projects
                projects_to_analyze = [d for d in project_path.iterdir()
                                     if d.is_dir() and not d.name.startswith('.')]
                console.log(f"[bold cyan]Found {len(projects_to_analyze)} projects to analyze[/bold cyan]")
            else:
                # Single project
                projects_to_analyze = [project_path]

            for project in projects_to_analyze:
                console.log(f"\n[bold cyan]{'='*60}[/bold cyan]")
                console.log(f"[bold cyan]Analyzing Project: {project.name}[/bold cyan]")
                console.log(f"[bold cyan]{'='*60}[/bold cyan]")

                # Analyze project
                threat_model = await analyze_project(project, args.claude_api_key)

                # Generate reports
                project_output_dir = output_dir / project.name
                report_generator = EnhancedReportGenerator(project_output_dir)
                report_paths = report_generator.generate_comprehensive_report(threat_model)

                console.log(f"\n[bold green]Reports generated for {project.name}:[/bold green]")
                for report_type, path in report_paths.items():
                    if isinstance(path, list):
                        console.log(f"  {report_type}: {len(path)} files")
                        for p in path:
                            console.log(f"    - {p}")
                    else:
                        console.log(f"  {report_type}: {path}")

            console.log(f"\n[bold green]✅ All analyses complete! Reports saved to {output_dir}[/bold green]")

        except Exception as e:
            console.log(f"[bold red]Error during analysis: {e}[/bold red]")
            import traceback
            traceback.print_exc()

    if __name__ == "__main__":
        asyncio.run(main())

else:
    console.log("[bold red]Exiting because dependencies could not be installed.[/bold red]")