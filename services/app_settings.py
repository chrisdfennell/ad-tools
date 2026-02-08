"""App Settings service - persist runtime settings in SQLite.

Settings override environment variables at runtime without container rebuild.
"""

import sqlite3
import os
import json
from flask import current_app

DB_PATH = os.environ.get('AUDIT_DB_PATH', '/app/data/audit.db')


def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_settings_db():
    """Create the settings table if it doesn't exist."""
    db = _get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT
        )
    ''')
    db.commit()
    db.close()


def get_setting(key, default=''):
    """Get a single setting value."""
    try:
        db = _get_db()
        row = db.execute('SELECT value FROM app_settings WHERE key = ?', (key,)).fetchone()
        db.close()
        return row['value'] if row else default
    except Exception:
        return default


def get_all_settings():
    """Get all settings as a dict."""
    try:
        db = _get_db()
        rows = db.execute('SELECT key, value FROM app_settings').fetchall()
        db.close()
        return {r['key']: r['value'] for r in rows}
    except Exception:
        return {}


def save_setting(key, value):
    """Save a setting (insert or update)."""
    try:
        from datetime import datetime
        db = _get_db()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        db.execute(
            'INSERT OR REPLACE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)',
            (key, value, now)
        )
        db.commit()
        db.close()
        return True
    except Exception:
        return False


def save_settings(settings_dict):
    """Save multiple settings at once."""
    try:
        from datetime import datetime
        db = _get_db()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        for key, value in settings_dict.items():
            db.execute(
                'INSERT OR REPLACE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)',
                (key, str(value), now)
            )
        db.commit()
        db.close()
        return True, 'Settings saved.'
    except Exception as e:
        return False, str(e)


# Setting definitions with metadata
SETTING_GROUPS = {
    'Branding': [
        {'key': 'APP_NAME', 'label': 'Application Name', 'type': 'text', 'default': 'AD Tools'},
        {'key': 'DOMAIN_DISPLAY', 'label': 'Domain Display Name', 'type': 'text', 'default': ''},
    ],
    'Session': [
        {'key': 'SESSION_TIMEOUT_MINUTES', 'label': 'Session Timeout (minutes)', 'type': 'number', 'default': '60'},
    ],
    'RBAC Groups': [
        {'key': 'HELPDESK_GROUP', 'label': 'Helpdesk AD Group', 'type': 'text', 'default': ''},
        {'key': 'VIEWER_GROUP', 'label': 'Viewer AD Group', 'type': 'text', 'default': ''},
    ],
    'Default OUs': [
        {'key': 'USER_OU', 'label': 'Default User OU', 'type': 'text', 'default': ''},
        {'key': 'GROUPS_OU', 'label': 'Default Groups OU', 'type': 'text', 'default': ''},
        {'key': 'COMPUTERS_OU', 'label': 'Default Computers OU', 'type': 'text', 'default': ''},
    ],
    'SMTP (Email)': [
        {'key': 'SMTP_SERVER', 'label': 'SMTP Server', 'type': 'text', 'default': ''},
        {'key': 'SMTP_PORT', 'label': 'SMTP Port', 'type': 'number', 'default': '587'},
        {'key': 'SMTP_FROM', 'label': 'From Address', 'type': 'text', 'default': ''},
        {'key': 'SMTP_USERNAME', 'label': 'SMTP Username', 'type': 'text', 'default': ''},
    ],
    'Reports': [
        {'key': 'DEFAULT_PASSWORD_MAX_AGE', 'label': 'Assumed Max Password Age (days)', 'type': 'number', 'default': '90'},
        {'key': 'STALE_THRESHOLD_DAYS', 'label': 'Default Stale Threshold (days)', 'type': 'number', 'default': '90'},
    ],
}
