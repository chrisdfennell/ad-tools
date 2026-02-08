"""Dynamic Group Viewer - virtual groups based on LDAP filters.

Groups are saved in SQLite and evaluated on-the-fly against AD.
"""

import sqlite3
import os
from datetime import datetime

from ldap3 import SUBTREE
from flask import current_app, session

from .ad_connection import get_connection


DB_PATH = os.environ.get('AUDIT_DB_PATH', '/app/data/audit.db')


def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_dynamic_groups_db():
    """Create the dynamic_groups table if it doesn't exist."""
    db = _get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS dynamic_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            ldap_filter TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT
        )
    ''')
    db.commit()
    db.close()


def list_dynamic_groups():
    """Get all saved dynamic groups."""
    try:
        db = _get_db()
        rows = db.execute('SELECT * FROM dynamic_groups ORDER BY name').fetchall()
        db.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_dynamic_group(group_id):
    """Get a single dynamic group by ID."""
    try:
        db = _get_db()
        row = db.execute('SELECT * FROM dynamic_groups WHERE id = ?', (group_id,)).fetchone()
        db.close()
        return dict(row) if row else None
    except Exception:
        return None


def create_dynamic_group(name, description, ldap_filter):
    """Create a new dynamic group."""
    try:
        db = _get_db()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        user = session.get('username', 'system')
        db.execute(
            'INSERT INTO dynamic_groups (name, description, ldap_filter, created_by, created_at) VALUES (?, ?, ?, ?, ?)',
            (name, description, ldap_filter, user, now)
        )
        db.commit()
        db.close()
        return True, 'Dynamic group created.'
    except Exception as e:
        return False, str(e)


def update_dynamic_group(group_id, name, description, ldap_filter):
    """Update an existing dynamic group."""
    try:
        db = _get_db()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        db.execute(
            'UPDATE dynamic_groups SET name=?, description=?, ldap_filter=?, updated_at=? WHERE id=?',
            (name, description, ldap_filter, now, group_id)
        )
        db.commit()
        db.close()
        return True, 'Dynamic group updated.'
    except Exception as e:
        return False, str(e)


def delete_dynamic_group(group_id):
    """Delete a dynamic group."""
    try:
        db = _get_db()
        db.execute('DELETE FROM dynamic_groups WHERE id = ?', (group_id,))
        db.commit()
        db.close()
        return True, 'Dynamic group deleted.'
    except Exception as e:
        return False, str(e)


def evaluate_dynamic_group(ldap_filter, limit=500):
    """Run the LDAP filter against AD and return matching objects."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(
            cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'distinguishedName',
                        'objectClass', 'userAccountControl'],
            size_limit=limit,
        )
        results = []
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            obj_classes = _safe('objectClass') or []
            if isinstance(obj_classes, str):
                obj_classes = [obj_classes]

            obj_type = 'user'
            if 'computer' in obj_classes:
                obj_type = 'computer'
            elif 'group' in obj_classes:
                obj_type = 'group'

            uac = int(_safe('userAccountControl') or 512)
            status = 'disabled' if uac & 0x2 else 'enabled'

            results.append({
                'cn': str(_safe('cn') or ''),
                'sam': str(_safe('sAMAccountName') or ''),
                'dn': str(entry.entry_dn),
                'type': obj_type,
                'status': status,
            })
        return True, results
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
