"""
Alert Manager for Unified File Monitoring System
=================================================
Handles email notifications for security events.
Supports Gmail SMTP with throttling and failed login tracking.
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional
from collections import defaultdict
import threading
import os

# Configure logger
logger = logging.getLogger('alert_manager')


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of security alerts."""
    BLOCKED_TRANSFER = "Blocked File Transfer"
    UNREGISTERED_DEVICE = "Unregistered Device Detected"
    LOGIN_FAILED = "Failed Login Attempt"
    LOGIN_FAILED_MULTIPLE = "Multiple Failed Login Attempts"
    DEVICE_REGISTERED = "New Device Registered"
    DEVICE_UNREGISTERED = "Device Unregistered"
    PERMISSION_GRANTED = "Permission Granted"
    PERMISSION_REVOKED = "Permission Revoked"
    SENSITIVE_DATA = "Sensitive Data Detected"
    SYSTEM_ERROR = "System Error"


class AlertManager:
    """
    Manages security alerts and email notifications.
    
    Features:
    - Email alerts via Gmail SMTP
    - Alert throttling to prevent spam
    - Failed login attempt tracking
    - Async email sending (non-blocking)
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the Alert Manager.
        
        Args:
            config: Configuration dictionary with email and alert settings
        """
        self.config = config
        self.enabled = config.get('ALERT_CONFIG', {}).get('enabled', True)
        
        # Email settings
        self.mail_server = config.get('MAIL_SERVER', 'smtp.gmail.com')
        self.mail_port = config.get('MAIL_PORT', 587)
        self.mail_use_tls = config.get('MAIL_USE_TLS', True)
        self.mail_username = config.get('MAIL_USERNAME', '')
        self.mail_password = config.get('MAIL_PASSWORD', '')
        self.mail_sender = config.get('MAIL_DEFAULT_SENDER', ('Unified Monitoring', self.mail_username))
        self.recipients = config.get('ALERT_RECIPIENTS', [])
        
        # Alert config
        alert_config = config.get('ALERT_CONFIG', {})
        self.email_enabled = alert_config.get('email_enabled', True)
        self.min_interval = alert_config.get('min_interval_seconds', 60)
        self.max_alerts_per_hour = alert_config.get('max_alerts_per_hour', 50)
        self.failed_login_threshold = alert_config.get('failed_login_threshold', 3)
        self.failed_login_window = alert_config.get('failed_login_window_minutes', 5)
        
        # Throttling state
        self._last_alert_time: Dict[str, datetime] = {}
        self._alert_count_this_hour = 0
        self._hour_start = datetime.now()
        
        # Failed login tracking
        self._failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        
        # App info
        app_info = config.get('APP_INFO', {})
        self.app_name = app_info.get('name', 'Unified Monitoring System')
        self.dashboard_url = app_info.get('dashboard_url', 'http://localhost:5000')
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        logger.info(f"Alert Manager initialized (Email: {'enabled' if self.email_enabled else 'disabled'})")
        
        if self.email_enabled and not self.mail_password:
            logger.warning("[WARNING] Email alerts enabled but MAIL_PASSWORD not set. Emails will not be sent.")
    
    def send_alert(self, alert_type: AlertType, level: AlertLevel, details: Dict) -> bool:
        """
        Send an alert notification.
        
        Args:
            alert_type: Type of alert
            level: Severity level
            details: Dictionary with alert details
            
        Returns:
            bool: True if alert was sent, False otherwise
        """
        if not self.enabled:
            logger.debug("Alerts disabled, skipping")
            return False
        
        # Check throttling
        if not self._should_send_alert(alert_type):
            logger.debug(f"Alert throttled: {alert_type.value}")
            return False
        
        # Add timestamp if not present
        if 'timestamp' not in details:
            details['timestamp'] = datetime.now().isoformat()
        
        # Log the alert
        log_message = f"[ALERT] {level.value.upper()} - {alert_type.value}: {details}"
        if level == AlertLevel.CRITICAL:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # Send email if enabled
        if self.email_enabled and self.mail_password:
            # Send asynchronously to not block the request
            thread = threading.Thread(
                target=self._send_email_alert,
                args=(alert_type, level, details)
            )
            thread.daemon = True
            thread.start()
            return True
        
        return False
    
    def _should_send_alert(self, alert_type: AlertType) -> bool:
        """Check if alert should be sent based on throttling rules."""
        with self._lock:
            now = datetime.now()
            
            # Reset hourly counter if needed
            if (now - self._hour_start).total_seconds() >= 3600:
                self._alert_count_this_hour = 0
                self._hour_start = now
            
            # Check max alerts per hour
            if self._alert_count_this_hour >= self.max_alerts_per_hour:
                return False
            
            # Check minimum interval for same alert type
            alert_key = alert_type.value
            if alert_key in self._last_alert_time:
                elapsed = (now - self._last_alert_time[alert_key]).total_seconds()
                if elapsed < self.min_interval:
                    return False
            
            # Update tracking
            self._last_alert_time[alert_key] = now
            self._alert_count_this_hour += 1
            
            return True
    
    def track_failed_login(self, username: str, client_info: str = "") -> Optional[bool]:
        """
        Track failed login attempts and send alert if threshold reached.
        
        Args:
            username: The username that failed to login
            client_info: Additional client info (MAC address, IP, etc.)
            
        Returns:
            True if alert was sent, False if not yet at threshold, None if error
        """
        with self._lock:
            now = datetime.now()
            window_start = now - timedelta(minutes=self.failed_login_window)
            
            # Clean old entries
            self._failed_logins[username] = [
                t for t in self._failed_logins[username] 
                if t > window_start
            ]
            
            # Add new attempt
            self._failed_logins[username].append(now)
            
            # Check threshold
            attempts = len(self._failed_logins[username])
            
            if attempts >= self.failed_login_threshold:
                # Reset counter and send alert
                self._failed_logins[username] = []
                
                self.send_alert(
                    AlertType.LOGIN_FAILED_MULTIPLE,
                    AlertLevel.WARNING,
                    {
                        'username': username,
                        'attempts': attempts,
                        'window_minutes': self.failed_login_window,
                        'client_info': client_info,
                        'message': f"User '{username}' failed {attempts} login attempts in {self.failed_login_window} minutes"
                    }
                )
                return True
            
            return False
    
    def _send_email_alert(self, alert_type: AlertType, level: AlertLevel, details: Dict):
        """Send email alert (runs in separate thread)."""
        try:
            subject = self._build_subject(alert_type, level)
            html_body = self._build_html_body(alert_type, level, details)
            text_body = self._build_text_body(alert_type, level, details)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.mail_sender[0]} <{self.mail_sender[1]}>" if isinstance(self.mail_sender, tuple) else self.mail_sender
            msg['To'] = ', '.join(self.recipients)
            
            # Add plain text and HTML versions
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send via SMTP
            with smtplib.SMTP(self.mail_server, self.mail_port) as server:
                if self.mail_use_tls:
                    server.starttls()
                server.login(self.mail_username, self.mail_password)
                server.sendmail(self.mail_username, self.recipients, msg.as_string())
            
            logger.info(f"[EMAIL] Alert sent: {alert_type.value} to {len(self.recipients)} recipient(s)")
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"[ERROR] Email authentication failed. Check your Gmail App Password. Error: {e}")
        except Exception as e:
            logger.error(f"[ERROR] Failed to send email alert: {e}")
    
    def _build_subject(self, alert_type: AlertType, level: AlertLevel) -> str:
        """Build email subject line."""
        emoji = "🚨" if level == AlertLevel.CRITICAL else "⚠️" if level == AlertLevel.WARNING else "ℹ️"
        return f"{emoji} [{level.value.upper()}] {alert_type.value} - {self.app_name}"
    
    def _build_text_body(self, alert_type: AlertType, level: AlertLevel, details: Dict) -> str:
        """Build plain text email body."""
        lines = [
            f"{'=' * 50}",
            f"SECURITY ALERT - {self.app_name}",
            f"{'=' * 50}",
            "",
            f"Alert Type: {alert_type.value}",
            f"Severity: {level.value.upper()}",
            f"Timestamp: {details.get('timestamp', 'N/A')}",
            "",
            "DETAILS:",
            "-" * 30,
        ]
        
        # Add all details
        for key, value in details.items():
            if key != 'timestamp':
                lines.append(f"  • {key.replace('_', ' ').title()}: {value}")
        
        lines.extend([
            "",
            f"{'=' * 50}",
            f"Please review this incident in the dashboard:",
            f"{self.dashboard_url}/local/dashboard",
            f"{'=' * 50}",
        ])
        
        return "\n".join(lines)
    
    def _build_html_body(self, alert_type: AlertType, level: AlertLevel, details: Dict) -> str:
        """Build HTML email body with styling."""
        
        # Color based on severity
        colors = {
            AlertLevel.CRITICAL: {'bg': '#fee2e2', 'border': '#ef4444', 'text': '#991b1b'},
            AlertLevel.WARNING: {'bg': '#fef3c7', 'border': '#f59e0b', 'text': '#92400e'},
            AlertLevel.INFO: {'bg': '#dbeafe', 'border': '#3b82f6', 'text': '#1e40af'},
        }
        color = colors.get(level, colors[AlertLevel.INFO])
        
        # Build details rows
        detail_rows = ""
        for key, value in details.items():
            if key != 'timestamp':
                detail_rows += f"""
                <tr>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e5e7eb; color: #6b7280; font-weight: 500;">
                        {key.replace('_', ' ').title()}
                    </td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e5e7eb; color: #111827;">
                        {value}
                    </td>
                </tr>
                """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%); padding: 24px; border-radius: 12px 12px 0 0; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">
                        🛡️ {self.app_name}
                    </h1>
                    <p style="margin: 8px 0 0 0; color: #94a3b8; font-size: 14px;">
                        Security Alert Notification
                    </p>
                </div>
                
                <!-- Alert Banner -->
                <div style="background-color: {color['bg']}; border-left: 4px solid {color['border']}; padding: 16px 20px; margin-top: 2px;">
                    <div style="display: flex; align-items: center;">
                        <span style="font-size: 24px; margin-right: 12px;">
                            {"🚨" if level == AlertLevel.CRITICAL else "⚠️" if level == AlertLevel.WARNING else "ℹ️"}
                        </span>
                        <div>
                            <h2 style="margin: 0; color: {color['text']}; font-size: 18px; font-weight: 600;">
                                {alert_type.value}
                            </h2>
                            <p style="margin: 4px 0 0 0; color: {color['text']}; font-size: 14px; opacity: 0.8;">
                                Severity: {level.value.upper()}
                            </p>
                        </div>
                    </div>
                </div>
                
                <!-- Content -->
                <div style="background-color: #ffffff; padding: 24px; border: 1px solid #e5e7eb; border-top: none;">
                    <!-- Timestamp -->
                    <p style="margin: 0 0 20px 0; color: #6b7280; font-size: 14px;">
                        📅 <strong>Timestamp:</strong> {details.get('timestamp', 'N/A')}
                    </p>
                    
                    <!-- Details Table -->
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th colspan="2" style="padding: 12px; background-color: #f9fafb; text-align: left; color: #374151; font-size: 14px; font-weight: 600; border-bottom: 2px solid #e5e7eb;">
                                    Alert Details
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {detail_rows}
                        </tbody>
                    </table>
                    
                    <!-- Action Button -->
                    <div style="text-align: center; margin-top: 24px;">
                        <a href="{self.dashboard_url}/local/dashboard" 
                           style="display: inline-block; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); 
                                  color: #ffffff; text-decoration: none; padding: 12px 32px; border-radius: 8px; 
                                  font-weight: 600; font-size: 14px; box-shadow: 0 2px 4px rgba(59, 130, 246, 0.3);">
                            📊 View Dashboard
                        </a>
                    </div>
                </div>
                
                <!-- Footer -->
                <div style="background-color: #f9fafb; padding: 16px 24px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 12px 12px; text-align: center;">
                    <p style="margin: 0; color: #6b7280; font-size: 12px;">
                        This is an automated message from {self.app_name}.<br>
                        Please do not reply to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def test_email(self) -> Dict:
        """
        Send a test email to verify configuration.
        
        Returns:
            Dict with success status and message
        """
        if not self.mail_password:
            return {
                'success': False,
                'error': 'MAIL_PASSWORD not configured. Please set the environment variable.'
            }
        
        try:
            self.send_alert(
                AlertType.SYSTEM_ERROR,  # Using SYSTEM_ERROR for test
                AlertLevel.INFO,
                {
                    'message': 'This is a test email from the Unified Monitoring System.',
                    'test': True,
                    'configuration': 'Email alerts are working correctly!'
                }
            )
            return {
                'success': True,
                'message': f'Test email sent to {", ".join(self.recipients)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_status(self) -> Dict:
        """Get current alert manager status."""
        return {
            'enabled': self.enabled,
            'email_enabled': self.email_enabled,
            'email_configured': bool(self.mail_password),
            'recipients': self.recipients,
            'alerts_this_hour': self._alert_count_this_hour,
            'max_alerts_per_hour': self.max_alerts_per_hour,
            'mail_server': self.mail_server,
            'mail_username': self.mail_username,
        }


# Convenience function for creating alert manager from config module
def create_alert_manager():
    """Create AlertManager instance from config module."""
    try:
        import config
        config_dict = {
            'MAIL_SERVER': config.MAIL_SERVER,
            'MAIL_PORT': config.MAIL_PORT,
            'MAIL_USE_TLS': config.MAIL_USE_TLS,
            'MAIL_USERNAME': config.MAIL_USERNAME,
            'MAIL_PASSWORD': config.MAIL_PASSWORD,
            'MAIL_DEFAULT_SENDER': config.MAIL_DEFAULT_SENDER,
            'ALERT_RECIPIENTS': config.ALERT_RECIPIENTS,
            'ALERT_CONFIG': config.ALERT_CONFIG,
            'APP_INFO': config.APP_INFO,
        }
        return AlertManager(config_dict)
    except ImportError:
        logger.warning("Config module not found, using defaults")
        return AlertManager({})
