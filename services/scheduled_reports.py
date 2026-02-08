"""Scheduled Reports & Email Alerts service.

Manages report schedules stored in SQLite and sends email alerts.
Uses a background thread to check schedules periodically.
"""

import os
import json
import sqlite3
import smtplib
import threading
import time
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import current_app


DB_PATH = os.environ.get('AUDIT_DB_PATH', '/app/data/audit.db')

_scheduler_thread = None
_scheduler_running = False


def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_scheduled_reports_db():
    """Create the scheduled_reports table if it doesn't exist."""
    db = _get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            report_type TEXT NOT NULL,
            schedule TEXT NOT NULL,
            recipients TEXT NOT NULL,
            parameters TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            last_status TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            recipients TEXT NOT NULL,
            parameters TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    db.commit()
    db.close()


def get_all_schedules():
    """Get all scheduled reports."""
    try:
        db = _get_db()
        rows = db.execute('SELECT * FROM scheduled_reports ORDER BY id DESC').fetchall()
        db.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_schedule(schedule_id):
    """Get a single scheduled report."""
    try:
        db = _get_db()
        row = db.execute('SELECT * FROM scheduled_reports WHERE id = ?', (schedule_id,)).fetchone()
        db.close()
        return dict(row) if row else None
    except Exception:
        return None


def create_schedule(name, report_type, schedule, recipients, parameters, created_by):
    """Create a new scheduled report."""
    try:
        db = _get_db()
        db.execute(
            '''INSERT INTO scheduled_reports
               (name, report_type, schedule, recipients, parameters, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (name, report_type, schedule, recipients,
             json.dumps(parameters), created_by,
             datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
        db.close()
        return True, 'Schedule created successfully.'
    except Exception as e:
        return False, str(e)


def update_schedule(schedule_id, **kwargs):
    """Update a scheduled report."""
    try:
        db = _get_db()
        for key, value in kwargs.items():
            if key == 'parameters':
                value = json.dumps(value)
            db.execute(f'UPDATE scheduled_reports SET {key} = ? WHERE id = ?', (value, schedule_id))
        db.commit()
        db.close()
        return True, 'Schedule updated.'
    except Exception as e:
        return False, str(e)


def delete_schedule(schedule_id):
    """Delete a scheduled report."""
    try:
        db = _get_db()
        db.execute('DELETE FROM scheduled_reports WHERE id = ?', (schedule_id,))
        db.commit()
        db.close()
        return True, 'Schedule deleted.'
    except Exception as e:
        return False, str(e)


def toggle_schedule(schedule_id):
    """Toggle a schedule on/off."""
    try:
        db = _get_db()
        row = db.execute('SELECT enabled FROM scheduled_reports WHERE id = ?', (schedule_id,)).fetchone()
        if not row:
            db.close()
            return False, 'Schedule not found.'
        new_state = 0 if row['enabled'] else 1
        db.execute('UPDATE scheduled_reports SET enabled = ? WHERE id = ?', (new_state, schedule_id))
        db.commit()
        db.close()
        return True, 'Enabled' if new_state else 'Disabled'
    except Exception as e:
        return False, str(e)


# Alert rules
def get_all_alerts():
    """Get all alert rules."""
    try:
        db = _get_db()
        rows = db.execute('SELECT * FROM alert_rules ORDER BY id DESC').fetchall()
        db.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def create_alert(name, alert_type, recipients, parameters, created_by):
    """Create a new alert rule."""
    try:
        db = _get_db()
        db.execute(
            '''INSERT INTO alert_rules
               (name, alert_type, recipients, parameters, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (name, alert_type, recipients, json.dumps(parameters), created_by,
             datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
        db.close()
        return True, 'Alert rule created.'
    except Exception as e:
        return False, str(e)


def delete_alert(alert_id):
    """Delete an alert rule."""
    try:
        db = _get_db()
        db.execute('DELETE FROM alert_rules WHERE id = ?', (alert_id,))
        db.commit()
        db.close()
        return True, 'Alert rule deleted.'
    except Exception as e:
        return False, str(e)


def toggle_alert(alert_id):
    """Toggle an alert rule on/off."""
    try:
        db = _get_db()
        row = db.execute('SELECT enabled FROM alert_rules WHERE id = ?', (alert_id,)).fetchone()
        if not row:
            db.close()
            return False, 'Alert not found.'
        new_state = 0 if row['enabled'] else 1
        db.execute('UPDATE alert_rules SET enabled = ? WHERE id = ?', (new_state, alert_id))
        db.commit()
        db.close()
        return True, 'Enabled' if new_state else 'Disabled'
    except Exception as e:
        return False, str(e)


def send_email(recipients, subject, html_body):
    """Send an email using SMTP configuration from environment."""
    smtp_host = os.environ.get('SMTP_HOST', '')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_password = os.environ.get('SMTP_PASSWORD', '')
    smtp_from = os.environ.get('SMTP_FROM', smtp_user)
    smtp_tls = os.environ.get('SMTP_TLS', 'true').lower() == 'true'

    if not smtp_host:
        return False, 'SMTP not configured. Set SMTP_HOST environment variable.'

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = smtp_from
        msg['To'] = recipients

        msg.attach(MIMEText(html_body, 'html'))

        if smtp_tls:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)

        if smtp_user:
            server.login(smtp_user, smtp_password)

        server.sendmail(smtp_from, recipients.split(','), msg.as_string())
        server.quit()
        return True, 'Email sent successfully.'
    except Exception as e:
        return False, str(e)


def send_test_email(recipients):
    """Send a test email to verify SMTP configuration."""
    return send_email(
        recipients,
        'AD Tools - Test Email',
        '<h2>AD Tools Email Test</h2><p>This is a test email from AD Tools. '
        'If you received this, your SMTP configuration is working correctly.</p>'
    )


# Report type definitions
REPORT_TYPES = {
    'password_expiry': {
        'name': 'Password Expiry Report',
        'description': 'Users with passwords expiring within N days',
        'default_params': {'days': 30},
    },
    'stale_users': {
        'name': 'Stale Users Report',
        'description': 'Users who haven\'t logged in for N days',
        'default_params': {'days': 90},
    },
    'stale_computers': {
        'name': 'Stale Computers Report',
        'description': 'Computers that haven\'t logged in for N days',
        'default_params': {'days': 90},
    },
    'locked_accounts': {
        'name': 'Locked Accounts Summary',
        'description': 'Currently locked user accounts',
        'default_params': {},
    },
    'privileged_accounts': {
        'name': 'Privileged Accounts Report',
        'description': 'Accounts with elevated privileges',
        'default_params': {},
    },
}

ALERT_TYPES = {
    'account_locked': {
        'name': 'Account Locked',
        'description': 'Alert when any account gets locked out',
    },
    'privileged_change': {
        'name': 'Privileged Group Change',
        'description': 'Alert when privileged group membership changes',
    },
    'admin_login': {
        'name': 'Admin Login',
        'description': 'Alert when an admin logs into AD Tools',
    },
}

SCHEDULE_OPTIONS = {
    'daily_8am': 'Daily at 8:00 AM',
    'daily_6pm': 'Daily at 6:00 PM',
    'weekly_monday': 'Weekly on Monday',
    'weekly_friday': 'Weekly on Friday',
    'monthly_1st': 'Monthly on the 1st',
}
