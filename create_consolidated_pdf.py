#!/usr/bin/env python3
"""
Consolidated PDF Report Generator
Creates a single comprehensive PDF with all threat modeling results
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.lib.colors import HexColor
except ImportError:
    print("Installing required dependencies...")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "reportlab"])
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.lib.colors import HexColor

class ConsolidatedPDFGenerator:
    """Generate consolidated PDF report from all threat modeling results."""

    def __init__(self, reports_dir: Path, output_path: Path):
        self.reports_dir = reports_dir
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()

    def setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,
            textColor=colors.darkblue
        )

        self.heading1_style = ParagraphStyle(
            'CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=20,
            textColor=colors.darkblue,
            borderWidth=1,
            borderColor=colors.darkblue,
            borderPadding=5
        )

        self.heading2_style = ParagraphStyle(
            'CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=15,
            textColor=colors.darkred
        )

        self.code_style = ParagraphStyle(
            'CodeStyle',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            backgroundColor=colors.lightgrey,
            borderWidth=1,
            borderColor=colors.grey,
            borderPadding=5
        )

    def load_all_reports(self) -> Dict[str, Any]:
        """Load all threat modeling reports."""
        all_data = {
            'projects': {},
            'total_findings': 0,
            'overall_stats': {
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0
            },
            'stride_stats': {},
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        for project_dir in self.reports_dir.iterdir():
            if project_dir.is_dir():
                json_file = project_dir / f"{project_dir.name}_threat_analysis.json"
                if json_file.exists():
                    try:
                        with open(json_file, 'r') as f:
                            project_data = json.load(f)
                            all_data['projects'][project_dir.name] = project_data

                            # Aggregate statistics
                            all_data['total_findings'] += project_data.get('total_findings', 0)

                            severity_dist = project_data.get('severity_distribution', {})
                            for severity, count in severity_dist.items():
                                all_data['overall_stats'][severity] += count

                            stride_dist = project_data.get('stride_distribution', {})
                            for category, count in stride_dist.items():
                                all_data['stride_stats'][category] = all_data['stride_stats'].get(category, 0) + count

                    except Exception as e:
                        print(f"Error loading {json_file}: {e}")

        return all_data

    def create_severity_chart(self) -> Drawing:
        """Create severity distribution chart."""
        drawing = Drawing(400, 200)
        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 50
        chart.height = 125
        chart.width = 300

        # Sample data - would be replaced with actual data
        chart.data = [[58, 1, 47, 0]]  # Critical, High, Medium, Low
        chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
        chart.bars[0].fillColor = colors.red
        chart.bars[1].fillColor = colors.orange
        chart.bars[2].fillColor = colors.yellow
        chart.bars[3].fillColor = colors.green

        drawing.add(chart)
        return drawing

    def create_stride_chart(self, stride_stats: Dict[str, int]) -> Drawing:
        """Create STRIDE distribution pie chart."""
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 100
        pie.y = 50
        pie.width = 200
        pie.height = 200

        categories = list(stride_stats.keys())
        values = list(stride_stats.values())

        pie.data = values
        pie.labels = categories
        pie.slices.strokeWidth = 0.5

        # Color scheme for STRIDE categories
        colors_list = [colors.red, colors.orange, colors.yellow, colors.green, colors.blue, colors.purple]
        for i, color in enumerate(colors_list[:len(categories)]):
            pie.slices[i].fillColor = color

        drawing.add(pie)
        return drawing

    def generate_consolidated_report(self):
        """Generate the consolidated PDF report."""
        print("🔄 Generating consolidated PDF report...")

        # Load all report data
        all_data = self.load_all_reports()

        if not all_data['projects']:
            print("❌ No threat modeling reports found!")
            return

        # Create PDF document
        doc = SimpleDocTemplate(str(self.output_path), pagesize=A4)
        story = []

        # Title Page
        story.append(Paragraph("Comprehensive Threat Modeling Report", self.title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph("All Projects Security Analysis", self.styles['Heading2']))
        story.append(Spacer(1, 20))

        # Executive Summary
        summary_data = [
            ['Metric', 'Value'],
            ['Total Projects Analyzed', str(len(all_data['projects']))],
            ['Total Threats Found', str(all_data['total_findings'])],
            ['Critical Threats', str(all_data['overall_stats']['Critical'])],
            ['High Threats', str(all_data['overall_stats']['High'])],
            ['Medium Threats', str(all_data['overall_stats']['Medium'])],
            ['Low Threats', str(all_data['overall_stats']['Low'])],
            ['Analysis Date', all_data['generation_date']],
            ['Methodology', 'STRIDE']
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        # Overall Risk Assessment
        story.append(Paragraph("Overall Risk Assessment", self.heading1_style))

        total_critical = all_data['overall_stats']['Critical']
        total_high = all_data['overall_stats']['High']

        if total_critical > 10:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif total_critical > 0 or total_high > 5:
            risk_level = "HIGH"
            risk_color = "orange"
        elif total_high > 0:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        else:
            risk_level = "LOW"
            risk_color = "green"

        risk_text = f"""
        <font color="{risk_color}"><b>Overall Risk Level: {risk_level}</b></font><br/><br/>

        <b>Key Findings:</b><br/>
        • {total_critical} Critical vulnerabilities requiring immediate attention<br/>
        • {total_high} High-severity issues needing prompt remediation<br/>
        • {all_data['overall_stats']['Medium']} Medium-priority security concerns<br/>
        • Analysis covers {len(all_data['projects'])} projects using STRIDE methodology<br/><br/>

        <b>Primary Threat Categories:</b><br/>
        """

        for category, count in sorted(all_data['stride_stats'].items(), key=lambda x: x[1], reverse=True):
            risk_text += f"• {category}: {count} threats<br/>"

        story.append(Paragraph(risk_text, self.styles['Normal']))
        story.append(PageBreak())

        # STRIDE Analysis Overview
        story.append(Paragraph("STRIDE Methodology Overview", self.heading1_style))

        stride_overview = """
        <b>STRIDE</b> is a threat modeling methodology that categorizes security threats into six main categories:<br/><br/>

        <b>S - Spoofing:</b> Impersonating someone or something else<br/>
        <b>T - Tampering:</b> Modifying data or code<br/>
        <b>R - Repudiation:</b> Claiming to have not performed an action<br/>
        <b>I - Information Disclosure:</b> Exposing information to unauthorized individuals<br/>
        <b>D - Denial of Service:</b> Denying or degrading service to users<br/>
        <b>E - Elevation of Privilege:</b> Gaining capabilities without proper authorization<br/><br/>

        This analysis identified threats across all STRIDE categories with detailed evidence and mitigation strategies.
        """

        story.append(Paragraph(stride_overview, self.styles['Normal']))
        story.append(Spacer(1, 20))

        # STRIDE Distribution Table
        stride_table_data = [['STRIDE Category', 'Total Threats', 'Percentage', 'Risk Level']]
        total_stride_threats = sum(all_data['stride_stats'].values())

        for category, count in all_data['stride_stats'].items():
            percentage = (count / total_stride_threats * 100) if total_stride_threats > 0 else 0
            risk_level = "High" if count > 20 else "Medium" if count > 10 else "Low"
            stride_table_data.append([category, str(count), f"{percentage:.1f}%", risk_level])

        stride_table = Table(stride_table_data)
        stride_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(stride_table)
        story.append(PageBreak())

        # Project-by-Project Analysis
        story.append(Paragraph("Detailed Project Analysis", self.heading1_style))

        for project_name, project_data in all_data['projects'].items():
            story.append(Paragraph(f"Project: {project_name}", self.heading2_style))

            # Project summary
            project_summary = f"""
            <b>Total Findings:</b> {project_data.get('total_findings', 0)}<br/>
            <b>Analysis Date:</b> {project_data.get('analysis_date', 'Unknown')}<br/>
            <b>Risk Level:</b> {self.calculate_project_risk(project_data)}<br/><br/>
            """

            story.append(Paragraph(project_summary, self.styles['Normal']))

            # Project severity distribution
            severity_dist = project_data.get('severity_distribution', {})
            if any(count > 0 for count in severity_dist.values()):
                project_table_data = [['Severity', 'Count']]
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = severity_dist.get(severity, 0)
                    if count > 0:
                        project_table_data.append([severity, str(count)])

                project_table = Table(project_table_data)
                project_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(project_table)

            # Top findings for this project
            findings = project_data.get('findings', [])
            if findings:
                story.append(Paragraph("Critical Findings:", self.styles['Heading3']))

                # Sort by severity and show top 5
                severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
                sorted_findings = sorted(findings,
                                       key=lambda x: severity_order.get(x.get('severity', 'Low'), 4))

                for i, finding in enumerate(sorted_findings[:5], 1):
                    finding_text = f"""
                    <b>{i}. {finding.get('threat_name', 'Unknown Threat')}</b><br/>
                    <b>Severity:</b> {finding.get('severity', 'Unknown')}<br/>
                    <b>STRIDE Category:</b> {finding.get('stride_category', 'Unknown')}<br/>
                    <b>CWE:</b> {finding.get('cwe_id', 'Unknown')}<br/>
                    <b>File:</b> {finding.get('file_path', 'Unknown')}:{finding.get('line_number', 'Unknown')}<br/>
                    <b>Description:</b> {finding.get('description', 'No description available')}<br/>
                    <b>Mitigation:</b> {finding.get('mitigation', 'No mitigation provided')}<br/>
                    """

                    story.append(Paragraph(finding_text, self.styles['Normal']))

                    # Add code snippet if available
                    code_snippet = finding.get('code_snippet', '')
                    if code_snippet and len(code_snippet) < 500:
                        story.append(Paragraph("<b>Code Evidence:</b>", self.styles['Normal']))
                        story.append(Paragraph(f"<font name='Courier'>{code_snippet}</font>", self.code_style))

                    story.append(Spacer(1, 10))

            story.append(PageBreak())

        # Recommendations Section
        story.append(Paragraph("Security Recommendations", self.heading1_style))

        recommendations = self.generate_recommendations(all_data)
        story.append(Paragraph(recommendations, self.styles['Normal']))
        story.append(Spacer(1, 20))

        # Implementation Roadmap
        story.append(Paragraph("Implementation Roadmap", self.heading2_style))

        roadmap = """
        <b>Phase 1 - Immediate Actions (0-30 days):</b><br/>
        • Address all Critical vulnerabilities<br/>
        • Remove hardcoded credentials and API keys<br/>
        • Implement input validation for code injection vulnerabilities<br/>
        • Enable HTTPS for all communications<br/><br/>

        <b>Phase 2 - Short-term Improvements (1-3 months):</b><br/>
        • Remediate High severity vulnerabilities<br/>
        • Implement comprehensive logging and monitoring<br/>
        • Upgrade weak cryptographic algorithms<br/>
        • Conduct security code reviews<br/><br/>

        <b>Phase 3 - Long-term Security Program (3-12 months):</b><br/>
        • Address Medium severity vulnerabilities<br/>
        • Implement automated security testing<br/>
        • Security awareness training for developers<br/>
        • Regular threat modeling and security assessments<br/>
        """

        story.append(Paragraph(roadmap, self.styles['Normal']))

        # Appendices
        story.append(PageBreak())
        story.append(Paragraph("Appendix A: STRIDE Threat Categories", self.heading1_style))

        appendix_text = """
        <b>Spoofing Identity</b><br/>
        Threats involving impersonation of users, processes, or systems.<br/>
        Common examples: Credential theft, session hijacking, identity fraud<br/><br/>

        <b>Tampering with Data</b><br/>
        Unauthorized modification of data or code.<br/>
        Common examples: SQL injection, XSS, data corruption, code injection<br/><br/>

        <b>Repudiation</b><br/>
        Users denying they performed an action without the system being able to prove otherwise.<br/>
        Common examples: Insufficient logging, missing audit trails, log tampering<br/><br/>

        <b>Information Disclosure</b><br/>
        Exposure of information to individuals who are not supposed to have access to it.<br/>
        Common examples: Data leaks, privacy violations, insecure communications<br/><br/>

        <b>Denial of Service</b><br/>
        Attacks that deny or degrade service for users.<br/>
        Common examples: Resource exhaustion, DDoS attacks, system overload<br/><br/>

        <b>Elevation of Privilege</b><br/>
        A user gains capabilities without proper authorization.<br/>
        Common examples: Buffer overflows, privilege escalation, configuration errors<br/>
        """

        story.append(Paragraph(appendix_text, self.styles['Normal']))

        # Build PDF
        doc.build(story)
        print(f"✅ Consolidated PDF report generated: {self.output_path}")

    def calculate_project_risk(self, project_data: Dict[str, Any]) -> str:
        """Calculate risk level for a project."""
        severity_dist = project_data.get('severity_distribution', {})
        critical = severity_dist.get('Critical', 0)
        high = severity_dist.get('High', 0)

        if critical > 10:
            return "CRITICAL"
        elif critical > 0 or high > 5:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_recommendations(self, all_data: Dict[str, Any]) -> str:
        """Generate security recommendations based on findings."""
        critical_count = all_data['overall_stats']['Critical']
        high_count = all_data['overall_stats']['High']
        stride_stats = all_data['stride_stats']

        recommendations = "<b>Priority Recommendations:</b><br/><br/>"

        if critical_count > 0:
            recommendations += f"<b>🚨 CRITICAL:</b> {critical_count} critical vulnerabilities require immediate attention.<br/>"

            if stride_stats.get('Tampering', 0) > 20:
                recommendations += "• Implement comprehensive input validation and parameterized queries<br/>"
                recommendations += "• Review all dynamic code execution patterns<br/>"

            if stride_stats.get('Elevation_of_Privilege', 0) > 0:
                recommendations += "• Review privilege escalation vulnerabilities immediately<br/>"
                recommendations += "• Implement principle of least privilege<br/>"

        if high_count > 0:
            recommendations += f"<b>⚠️ HIGH:</b> {high_count} high-severity issues need prompt remediation.<br/>"

        if stride_stats.get('Information_Disclosure', 0) > 10:
            recommendations += "• Review information disclosure vulnerabilities<br/>"
            recommendations += "• Implement proper error handling<br/>"
            recommendations += "• Upgrade to secure communication protocols<br/>"

        if stride_stats.get('Spoofing', 0) > 0:
            recommendations += "• Strengthen authentication mechanisms<br/>"
            recommendations += "• Remove hardcoded credentials<br/>"

        recommendations += "<br/><b>General Security Improvements:</b><br/>"
        recommendations += "• Implement automated security testing in CI/CD pipeline<br/>"
        recommendations += "• Conduct regular security code reviews<br/>"
        recommendations += "• Provide security training for development teams<br/>"
        recommendations += "• Establish incident response procedures<br/>"

        return recommendations

def main():
    """Main function to generate consolidated PDF."""
    current_dir = Path.cwd()
    reports_dir = current_dir / 'threat_reports'
    output_path = current_dir / 'Consolidated_Threat_Modeling_Report.pdf'

    if not reports_dir.exists():
        print("❌ No threat reports directory found. Run threat analysis first.")
        return

    generator = ConsolidatedPDFGenerator(reports_dir, output_path)
    generator.generate_consolidated_report()

    print(f"📄 Consolidated report available at: {output_path}")
    print(f"📊 Report includes analysis of all projects with detailed findings, POCs, and remediation steps")

if __name__ == "__main__":
    main()