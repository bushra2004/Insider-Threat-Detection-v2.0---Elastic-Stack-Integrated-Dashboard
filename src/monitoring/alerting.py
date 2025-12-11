import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
import logging
from jinja2 import Template
import os

logger = logging.getLogger(__name__)

class EmailNotifier:
    def __init__(self):
        self.smtp_host = os.getenv('SMTP_HOST', 'mailhog')
        self.smtp_port = int(os.getenv('SMTP_PORT', 1025))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_pass = os.getenv('SMTP_PASS', '')
        self.sender = os.getenv('EMAIL_SENDER', 'alerts@threatdetection.com')
        
        # Load email templates
        self.templates = self.load_templates()
    
    def load_templates(self) -> dict:
        """Load email templates from config"""
        templates = {
            'critical_alert': """
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; }
                    .alert-critical { 
                        background-color: #fee; 
                        border-left: 5px solid #d00;
                        padding: 20px;
                        margin: 10px 0;
                    }
                    .alert-high { 
                        background-color: #ffeaa7; 
                        border-left: 5px solid #f39c12;
                        padding: 20px;
                        margin: 10px 0;
                    }
                    .button { 
                        background-color: #d00; 
                        color: white; 
                        padding: 10px 20px; 
                        text-decoration: none; 
                        border-radius: 5px;
                    }
                </style>
            </head>
            <body>
                <h2>🚨 CRITICAL THREAT ALERT</h2>
                <div class="alert-critical">
                    <h3>{{ title }}</h3>
                    <p><strong>Severity:</strong> {{ severity }}</p>
                    <p><strong>User:</strong> {{ user }}</p>
                    <p><strong>Time:</strong> {{ timestamp }}</p>
                    <p><strong>Threat Score:</strong> {{ score }}</p>
                    <p>{{ description }}</p>
                    <p>
                        <a href="{{ dashboard_url }}" class="button">View in Dashboard</a>
                    </p>
                </div>
                <p>This alert requires immediate attention.</p>
            </body>
            </html>
            """,
            'daily_report': """
            <!DOCTYPE html>
            <html>
            <body>
                <h2>📊 Daily Threat Report</h2>
                <p>Date: {{ date }}</p>
                <h3>Summary:</h3>
                <ul>
                    <li>Total Threats: {{ total_threats }}</li>
                    <li>Critical: {{ critical_count }}</li>
                    <li>High: {{ high_count }}</li>
                    <li>Medium: {{ medium_count }}</li>
                    <li>Low: {{ low_count }}</li>
                </ul>
                <p>Detailed report is attached as PDF.</p>
            </body>
            </html>
            """
        }
        return templates
    
    async def send_alert_email(self, alert_data: dict, recipients: list):
        """Send alert email"""
        try:
            # Prepare message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert_data['severity'].upper()}] {alert_data['title']}"
            msg['From'] = self.sender
            msg['To'] = ', '.join(recipients)
            
            # Create HTML content
            template = Template(self.templates['critical_alert'])
            html_content = template.render(
                title=alert_data['title'],
                severity=alert_data['severity'],
                user=alert_data['user'],
                timestamp=alert_data['timestamp'],
                score=alert_data.get('score', 'N/A'),
                description=alert_data.get('description', ''),
                dashboard_url="http://localhost:8501"
            )
            
            # Attach HTML
            msg.attach(MIMEText(html_content, 'html'))
            
            # Attach PDF report if available
            if 'report_path' in alert_data:
                with open(alert_data['report_path'], 'rb') as f:
                    report = MIMEApplication(f.read(), _subtype='pdf')
                    report.add_header('Content-Disposition', 'attachment', 
                                    filename=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
                    msg.attach(report)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            
            logger.info(f"Alert email sent to {recipients}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
            return False
    
    async def send_daily_report(self, report_data: dict, recipients: list):
        """Send daily report email with PDF attachment"""
        try:
            # Generate PDF report
            from src.reporting.pdf_generator import PDFGenerator
            pdf_gen = PDFGenerator()
            pdf_path = await pdf_gen.generate_daily_report(report_data)
            
            # Prepare message
            msg = MIMEMultipart()
            msg['Subject'] = f"Daily Threat Report - {datetime.now().strftime('%Y-%m-%d')}"
            msg['From'] = self.sender
            msg['To'] = ', '.join(recipients)
            
            # HTML content
            template = Template(self.templates['daily_report'])
            html_content = template.render(
                date=datetime.now().strftime('%Y-%m-%d'),
                total_threats=report_data.get('total_threats', 0),
                critical_count=report_data.get('critical_count', 0),
                high_count=report_data.get('high_count', 0),
                medium_count=report_data.get('medium_count', 0),
                low_count=report_data.get('low_count', 0)
            )
            
            msg.attach(MIMEText(html_content, 'html'))
            
            # Attach PDF
            with open(pdf_path, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                pdf_attachment.add_header('Content-Disposition', 'attachment',
                                        filename=f"daily_report_{datetime.now().strftime('%Y%m%d')}.pdf")
                msg.attach(pdf_attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            
            logger.info(f"Daily report sent to {recipients}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send daily report: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check SMTP connection"""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=5) as server:
                return True
        except:
            return False