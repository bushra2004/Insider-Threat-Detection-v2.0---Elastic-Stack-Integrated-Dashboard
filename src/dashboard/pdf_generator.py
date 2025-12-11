from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import matplotlib.pyplot as plt
import io
import pandas as pd
import numpy as np
from typing import Dict, List
import os
import asyncio

class PDFGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        
        # Custom styles
        self.styles.add(ParagraphStyle(
            name='Title',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#1E3A8A'),
            spaceAfter=30
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor('#374151'),
            spaceAfter=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='AlertCritical',
            parent=self.styles['Normal'],
            backColor=colors.HexColor('#FEE2E2'),
            borderColor=colors.HexColor('#DC2626'),
            borderWidth=1,
            borderPadding=5,
            leftIndent=10
        ))
    
    async def generate_threat_report(self, threat_data: Dict) -> str:
        """Generate detailed threat report PDF"""
        filename = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        story = []
        
        # Title
        story.append(Paragraph("Insider Threat Detection Report", self.styles['Title']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                              self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        story.append(Paragraph(
            f"This report details {threat_data.get('total_threats', 0)} threat events detected "
            f"with {threat_data.get('critical_count', 0)} critical alerts requiring immediate attention.",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 15))
        
        # Threat Summary Table
        summary_data = [
            ['Severity', 'Count', 'Percentage'],
            ['Critical', str(threat_data.get('critical_count', 0)), 
             f"{threat_data.get('critical_percentage', 0):.1f}%"],
            ['High', str(threat_data.get('high_count', 0)), 
             f"{threat_data.get('high_percentage', 0):.1f}%"],
            ['Medium', str(threat_data.get('medium_count', 0)), 
             f"{threat_data.get('medium_percentage', 0):.1f}%"],
            ['Low', str(threat_data.get('low_count', 0)), 
             f"{threat_data.get('low_percentage', 0):.1f}%"],
            ['Total', str(threat_data.get('total_threats', 0)), '100%']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FEE2E2')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#FFEDD5')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#FEF3C7')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#D1FAE5')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('PADDING', (0, 1), (-1, -1), 6),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Critical Alerts Section
        if 'critical_alerts' in threat_data:
            story.append(Paragraph("Critical Alerts", self.styles['Heading1']))
            
            for alert in threat_data['critical_alerts'][:5]:  # Limit to 5
                alert_text = f"""
                <b>Alert ID:</b> {alert.get('id', 'N/A')}<br/>
                <b>User:</b> {alert.get('user', 'Unknown')}<br/>
                <b>Time:</b> {alert.get('timestamp', 'N/A')}<br/>
                <b>Type:</b> {alert.get('type', 'Unknown')}<br/>
                <b>Description:</b> {alert.get('description', 'No description')}
                """
                story.append(Paragraph(alert_text, self.styles['AlertCritical']))
                story.append(Spacer(1, 10))
        
        # Generate and add charts
        story.append(Paragraph("Threat Analysis Charts", self.styles['Heading1']))
        
        # Create severity distribution chart
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        # Pie chart
        labels = ['Critical', 'High', 'Medium', 'Low']
        sizes = [
            threat_data.get('critical_count', 0),
            threat_data.get('high_count', 0),
            threat_data.get('medium_count', 0),
            threat_data.get('low_count', 0)
        ]
        colors_pie = ['#DC2626', '#EA580C', '#D97706', '#059669']
        
        ax1.pie(sizes, labels=labels, colors=colors_pie, autopct='%1.1f%%')
        ax1.set_title('Threat Severity Distribution')
        
        # Bar chart
        threats_over_time = threat_data.get('threats_over_time', {})
        times = list(threats_over_time.keys())[-10:]  # Last 10 time periods
        counts = [threats_over_time.get(t, 0) for t in times]
        
        ax2.bar(times, counts, color='#3B82F6')
        ax2.set_title('Threats Over Time')
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Count')
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        
        # Save chart to buffer
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150)
        plt.close()
        
        # Add image to PDF
        img_buffer.seek(0)
        chart_img = Image(img_buffer, width=6*inch, height=3*inch)
        story.append(chart_img)
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", self.styles['Heading1']))
        
        findings_data = [
            ['Finding', 'Risk Level', 'Affected Users', 'Recommendation'],
            ['Data exfiltration attempts', 'High', '3', 'Implement DLP controls'],
            ['Unauthorized access attempts', 'Medium', '5', 'Review access permissions'],
            ['Unusual login times', 'Low', '12', 'Monitor for patterns'],
            ['Privilege escalation attempts', 'Critical', '1', 'Immediate investigation']
        ]
        
        findings_table = Table(findings_data, colWidths=[2*inch, 1*inch, 1.5*inch, 2.5*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F9FAFB')]),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(findings_table)
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['Heading1']))
        recommendations = [
            "1. Immediately investigate critical alerts",
            "2. Review and tighten access controls for affected users",
            "3. Implement Data Loss Prevention (DLP) solutions",
            "4. Conduct security awareness training",
            "5. Review and update incident response procedures"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
            story.append(Spacer(1, 5))
        
        # Footer with disclaimer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "Confidential - For authorized personnel only. "
            "This report contains sensitive security information.",
            ParagraphStyle(
                name='Disclaimer',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.grey
            )
        ))
        
        # Build PDF
        doc.build(story)
        
        return filepath
    
    async def generate_daily_report(self, report_data: Dict) -> str:
        """Generate daily summary report"""
        filename = f"daily_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        # Similar structure as threat report but with daily summary
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Add daily summary content
        story.append(Paragraph(f"Daily Threat Report - {datetime.now().strftime('%Y-%m-%d')}", 
                              self.styles['Title']))
        
        # Add daily metrics, top threats, trends, etc.
        # ... (similar to generate_threat_report but focused on daily data)
        
        doc.build(story)
        return filepath