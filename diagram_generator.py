#!/usr/bin/env python3
"""
Threat Modeling Diagram Generator
Generates User Interaction, Data Flow, and Threat Model diagrams using Mermaid
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from rich.console import Console
from rich.progress import track

console = Console()

class DiagramGenerator:
    """Generates high-resolution threat modeling diagrams using Mermaid CLI"""

    def __init__(self, output_dir: str = "diagram_images"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.mermaid_config = {
            "theme": "default",
            "themeVariables": {
                "fontSize": "18px",
                "fontFamily": "Arial, sans-serif"
            },
            "flowchart": {
                "useMaxWidth": False,
                "htmlLabels": True,
                "curve": "basis"
            }
        }
        self._setup_mermaid()

    def _setup_mermaid(self):
        """Install and configure Mermaid CLI"""
        try:
            # Check if mermaid CLI is available
            result = subprocess.run(['mmdc', '--version'],
                                 capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise FileNotFoundError("Mermaid CLI not found")
            console.print("[green]✅ Mermaid CLI is available[/green]")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print("[yellow]📦 Installing Mermaid CLI...[/yellow]")
            try:
                subprocess.run(['npm', 'install', '-g', '@mermaid-js/mermaid-cli'],
                             check=True, timeout=300)
                console.print("[green]✅ Mermaid CLI installed successfully[/green]")
            except subprocess.CalledProcessError as e:
                console.print(f"[red]❌ Failed to install Mermaid CLI: {e}[/red]")
                raise

        # Create mermaid config file
        config_path = Path("mermaid_config.json")
        with open(config_path, 'w') as f:
            json.dump(self.mermaid_config, f, indent=2)
        self.config_path = config_path

    def generate_user_interaction_diagram(self, project_name: str, users: List[str],
                                        modules: List[str], **kwargs) -> str:
        """Generate user interaction diagram"""
        mermaid_content = self._create_user_interaction_mermaid(
            project_name, users, modules, **kwargs)
        return self._render_diagram(mermaid_content, f"{project_name}_User_Interaction")

    def generate_data_flow_diagram(self, project_name: str, components: Dict[str, List],
                                 **kwargs) -> str:
        """Generate data flow diagram"""
        mermaid_content = self._create_data_flow_mermaid(
            project_name, components, **kwargs)
        return self._render_diagram(mermaid_content, f"{project_name}_Data_Flow")

    def generate_threat_model_diagram(self, project_name: str, threats: List[Dict],
                                    **kwargs) -> str:
        """Generate threat model diagram"""
        mermaid_content = self._create_threat_model_mermaid(
            project_name, threats, **kwargs)
        return self._render_diagram(mermaid_content, f"{project_name}_Threat_Model")

    def _create_user_interaction_mermaid(self, project_name: str, users: List[str],
                                       modules: List[str], **kwargs) -> str:
        """Create mermaid syntax for user interaction diagram"""

        user_icons = {
            "patient": "👤 Patient User",
            "doctor": "👨‍⚕️ Doctor User",
            "admin": "👨‍💼 Admin User",
            "insurance": "🏢 Insurance Partner",
            "hospital_admin": "👨‍💼 Hospital Admin",
            "medical_staff": "👨‍⚕️ Medical Staff",
            "billing": "💰 Billing Department",
            "it_admin": "💻 IT Administrator"
        }

        module_icons = {
            "cms": "📝 CMS Module",
            "labs": "🧪 Labs Module",
            "hospital": "🏥 Hospital Module",
            "pharmacy": "💊 Pharmacy Module",
            "finance": "💰 Finance Module",
            "insurance": "🛡️ Insurance Module",
            "authentication": "🔐 Authentication",
            "dashboard": "📊 Dashboard"
        }

        mermaid = ["graph TD"]

        # Add users
        user_nodes = []
        for i, user in enumerate(users):
            user_key = user.lower().replace(" ", "_")
            icon = user_icons.get(user_key, f"👤 {user}")
            node = f'    {chr(65+i)}["{icon}"]'
            mermaid.append(node)
            user_nodes.append(chr(65+i))

        # Add login/auth flow
        mermaid.append(f'    Z["🔐 Login Screen"]')
        for node in user_nodes:
            mermaid.append(f'    {node} --> Z')

        mermaid.append(f'    Z --> AA["🔑 Authentication Service"]')
        mermaid.append(f'    AA --> BB["📊 Main Dashboard"]')

        # Add modules
        module_nodes = []
        for i, module in enumerate(modules):
            module_key = module.lower().replace(" ", "_")
            icon = module_icons.get(module_key, f"📦 {module}")
            node_id = chr(67+i)  # Start from C
            mermaid.append(f'    BB --> {node_id}["{icon}"]')
            module_nodes.append(node_id)

        # Add styling
        mermaid.extend([
            "",
            "    classDef patient fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000",
            "    classDef doctor fill:#e8f5e8,stroke:#388e3c,stroke-width:3px,color:#000",
            "    classDef admin fill:#fff3e0,stroke:#f57c00,stroke-width:3px,color:#000",
            "    classDef system fill:#f5f5f5,stroke:#424242,stroke-width:2px,color:#000",
            "",
            f"    class {user_nodes[0] if user_nodes else 'A'} patient",
            f"    class {','.join(user_nodes[1:3])} doctor" if len(user_nodes) > 1 else "",
            f"    class {','.join(user_nodes[3:])} admin" if len(user_nodes) > 3 else "",
            f"    class Z,AA,BB,{','.join(module_nodes)} system"
        ])

        return '\n'.join(filter(None, mermaid))

    def _create_data_flow_mermaid(self, project_name: str, components: Dict[str, List],
                                **kwargs) -> str:
        """Create mermaid syntax for data flow diagram"""

        mermaid = ["graph TD"]

        # Add main components
        if "frontend" in components:
            mermaid.append('    A["🌐 Frontend Application"] --> B["🚪 API Gateway"]')

        if "services" in components:
            mermaid.append('    B --> C["⚙️ Services Layer"]')
            for i, service in enumerate(components["services"][:6]):  # Limit to 6 for clarity
                service_id = chr(68+i)  # Start from D
                mermaid.append(f'    C --> {service_id}["🔧 {service}"]')

        if "databases" in components:
            for i, db in enumerate(components["databases"][:6]):
                db_id = chr(74+i)  # Start from J
                service_id = chr(68+i)
                mermaid.append(f'    {service_id} --> {db_id}["🗄️ {db}"]')

        if "external" in components:
            for i, ext in enumerate(components["external"][:4]):
                ext_id = chr(80+i)  # Start from P
                mermaid.append(f'    B --> {ext_id}["🔗 {ext}"]')

        # Add styling
        mermaid.extend([
            "",
            "    classDef frontend fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000",
            "    classDef gateway fill:#fff3e0,stroke:#f57c00,stroke-width:3px,color:#000",
            "    classDef service fill:#e8f5e8,stroke:#388e3c,stroke-width:2px,color:#000",
            "    classDef database fill:#f5f5f5,stroke:#424242,stroke-width:2px,color:#000",
            "    classDef external fill:#fff9c4,stroke:#f9a825,stroke-width:2px,color:#000",
            "",
            "    class A frontend",
            "    class B gateway",
            "    class C,D,E,F,G,H,I service",
            "    class J,K,L,M,N,O database",
            "    class P,Q,R,S external"
        ])

        return '\n'.join(mermaid)

    def _create_threat_model_mermaid(self, project_name: str, threats: List[Dict],
                                   **kwargs) -> str:
        """Create mermaid syntax for threat model diagram"""

        mermaid = ["graph TD"]

        # Count threats by severity
        critical_count = sum(1 for t in threats if t.get('severity', '').lower() == 'critical')
        high_count = sum(1 for t in threats if t.get('severity', '').lower() == 'high')
        medium_count = sum(1 for t in threats if t.get('severity', '').lower() == 'medium')

        # Add main flow
        mermaid.extend([
            '    A["👤 User"] --> B["🌐 Application"]',
            '    B --> C["⚙️ System Components"]'
        ])

        # Add threat nodes based on severity
        threat_nodes = []
        if critical_count > 0:
            mermaid.append('    C -->|"🚨 CRITICAL Threats"| D["💀 Critical Vulnerabilities"]')
            threat_nodes.append('D')

        if high_count > 0:
            mermaid.append('    C -->|"🔴 HIGH Threats"| E["⚠️ High Risk Issues"]')
            threat_nodes.append('E')

        if medium_count > 0:
            mermaid.append('    C -->|"🟡 MEDIUM Threats"| F["⚠️ Medium Risk Issues"]')
            threat_nodes.append('F')

        # Add impact nodes
        if critical_count > 0:
            mermaid.append('    D --> G["💥 System Compromise"]')

        # Add subgraphs for threat categories
        if critical_count > 0:
            mermaid.extend([
                "",
                f'    subgraph "🚨 CRITICAL THREATS ({critical_count})"',
                "        D",
                "        G",
                "    end"
            ])

        if medium_count > 0:
            mermaid.extend([
                "",
                f'    subgraph "⚠️ MEDIUM THREATS ({medium_count})"',
                "        F",
                "    end"
            ])

        # Add styling based on threat severity
        mermaid.extend([
            "",
            "    classDef user fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000",
            "    classDef critical fill:#f44336,stroke:#b71c1c,stroke-width:4px,color:#fff,font-weight:bold",
            "    classDef high fill:#ff5722,stroke:#d84315,stroke-width:4px,color:#fff,font-weight:bold",
            "    classDef medium fill:#ff9800,stroke:#e65100,stroke-width:3px,color:#000",
            "    classDef system fill:#f5f5f5,stroke:#424242,stroke-width:2px,color:#000",
            "",
            "    class A user",
            "    class B,C system"
        ])

        if 'D' in threat_nodes:
            mermaid.append("    class D,G critical")
        if 'E' in threat_nodes:
            mermaid.append("    class E high")
        if 'F' in threat_nodes:
            mermaid.append("    class F medium")

        return '\n'.join(mermaid)

    def _render_diagram(self, mermaid_content: str, diagram_name: str) -> str:
        """Render mermaid diagram to PNG"""

        # Create temporary mermaid file
        mmd_file = Path(f"{diagram_name}.mmd")
        with open(mmd_file, 'w') as f:
            f.write(mermaid_content)

        # Generate PNG
        output_file = self.output_dir / f"{diagram_name}.png"

        try:
            cmd = [
                'mmdc',
                '-i', str(mmd_file),
                '-o', str(output_file),
                '-w', '1920',
                '-H', '1080',
                '-s', '2',
                '-c', str(self.config_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                console.print(f"[red]❌ Failed to generate {diagram_name}: {result.stderr}[/red]")
                return None

            console.print(f"[green]✅ Generated {output_file}[/green]")
            return str(output_file)

        except subprocess.TimeoutExpired:
            console.print(f"[red]❌ Timeout generating {diagram_name}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]❌ Error generating {diagram_name}: {e}[/red]")
            return None
        finally:
            # Clean up temporary file
            if mmd_file.exists():
                mmd_file.unlink()

    def generate_all_diagrams(self, project_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate all three types of diagrams for a project"""

        project_name = project_data.get('name', 'Unknown')
        console.print(f"[bold cyan]🎨 Generating diagrams for {project_name}[/bold cyan]")

        results = {}

        # Generate User Interaction Diagram
        if 'users' in project_data and 'modules' in project_data:
            result = self.generate_user_interaction_diagram(
                project_name,
                project_data['users'],
                project_data['modules']
            )
            if result:
                results['user_interaction'] = result

        # Generate Data Flow Diagram
        if 'components' in project_data:
            result = self.generate_data_flow_diagram(
                project_name,
                project_data['components']
            )
            if result:
                results['data_flow'] = result

        # Generate Threat Model Diagram
        if 'threats' in project_data:
            result = self.generate_threat_model_diagram(
                project_name,
                project_data['threats']
            )
            if result:
                results['threat_model'] = result

        return results

    def cleanup(self):
        """Clean up temporary files"""
        if hasattr(self, 'config_path') and self.config_path.exists():
            self.config_path.unlink()


def main():
    """Example usage of the diagram generator"""

    # Example project data
    example_projects = [
        {
            "name": "Batavia_Client",
            "users": ["patient", "doctor", "admin", "insurance"],
            "modules": ["cms", "labs", "hospital", "pharmacy", "finance", "insurance"],
            "components": {
                "frontend": ["Angular App"],
                "services": ["CMS Service", "Labs Service", "Hospital Service", "Pharmacy Service"],
                "databases": ["User DB", "CMS DB", "Labs DB", "Hospital DB"],
                "external": ["Third-party CMS", "Lab Partners", "Hospital Partners"]
            },
            "threats": [
                {"severity": "high", "type": "Spoofing", "description": "Hardcoded credentials"},
                {"severity": "medium", "type": "Information Disclosure", "description": "HTTP usage"}
            ]
        }
    ]

    generator = DiagramGenerator()

    try:
        for project in example_projects:
            results = generator.generate_all_diagrams(project)
            console.print(f"[green]✅ Generated {len(results)} diagrams for {project['name']}[/green]")

    finally:
        generator.cleanup()


if __name__ == "__main__":
    main()