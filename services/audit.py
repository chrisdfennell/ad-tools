import sqlite3
import os
from datetime import datetime
from flask import session


DB_PATH = os.environ.get('AUDIT_DB_PATH', '/app/data/audit.db')


def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = _get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            details TEXT,
            result TEXT NOT NULL
        )
    ''')
    db.commit()
    db.close()


def log_action(action, target, details='', result='success'):
    user = session.get('username', 'system')
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    try:
        db = _get_db()
        db.execute(
            'INSERT INTO audit_log (timestamp, user, action, target, details, result) VALUES (?, ?, ?, ?, ?, ?)',
            (timestamp, user, action, target, details, result)
        )
        db.commit()
        db.close()
    except Exception:
        pass  # Don't let audit failures break the app


def get_target_history(target, limit=50):
    """Get audit log entries for a specific target (e.g. a user's sAMAccountName)."""
    try:
        db = _get_db()
        rows = db.execute(
            'SELECT * FROM audit_log WHERE target LIKE ? ORDER BY id DESC LIMIT ?',
            (f'%{target}%', limit)
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_audit_log(limit=200, offset=0, action_filter='', user_filter=''):
    try:
        db = _get_db()
        query = 'SELECT * FROM audit_log WHERE 1=1'
        params = []
        if action_filter:
            query += ' AND action LIKE ?'
            params.append(f'%{action_filter}%')
        if user_filter:
            query += ' AND user LIKE ?'
            params.append(f'%{user_filter}%')
        query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        rows = db.execute(query, params).fetchall()
        total = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
        db.close()
        return [dict(r) for r in rows], total
    except Exception:
        return [], 0
