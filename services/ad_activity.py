"""Real-Time Activity service - poll AD for recent lockouts, password changes, new accounts."""

from datetime import datetime, timedelta, timezone

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def get_locked_accounts():
    """Get all currently locked-out accounts."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        # lockoutTime > 0 means locked
        locked_filter = f'(&{USER_FILTER}(lockoutTime>=1))'
        conn.search(
            cfg['BASE_DN'], locked_filter, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'displayName', 'lockoutTime',
                         'distinguishedName'],
        )

        locked = []
        for entry in conn.entries:
            lockout_time = ''
            try:
                lt = entry.lockoutTime.value
                if lt and str(lt) not in ('0', '1601-01-01 00:00:00+00:00'):
                    lockout_time = str(lt)
                else:
                    continue  # Not actually locked
            except Exception:
                continue

            locked.append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'lockout_time': lockout_time,
                'dn': str(entry.entry_dn),
            })

        return True, locked
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_recent_password_changes(hours=24):
    """Get users whose password was changed in the last N hours."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        filetime = int((cutoff - epoch).total_seconds() * 10_000_000)

        pwd_filter = f'(&{USER_FILTER}(pwdLastSet>={filetime}))'
        conn.search(
            cfg['BASE_DN'], pwd_filter, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'displayName', 'pwdLastSet',
                         'distinguishedName'],
        )

        users = []
        for entry in conn.entries:
            pwd_time = ''
            try:
                pt = entry.pwdLastSet.value
                if pt and hasattr(pt, 'strftime'):
                    pwd_time = pt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                pass

            users.append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'pwd_changed': pwd_time,
                'dn': str(entry.entry_dn),
            })

        users.sort(key=lambda u: u['pwd_changed'], reverse=True)
        return True, users
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_recently_created_accounts(hours=72):
    """Get accounts created in the last N hours."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        # whenCreated uses generalized time format: YYYYMMDDHHmmss.0Z
        cutoff_str = cutoff.strftime('%Y%m%d%H%M%S.0Z')

        created_filter = f'(&{USER_FILTER}(whenCreated>={cutoff_str}))'
        conn.search(
            cfg['BASE_DN'], created_filter, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'displayName', 'whenCreated',
                         'userAccountControl', 'distinguishedName'],
        )

        users = []
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
            status = 'disabled' if uac & 2 else 'enabled'
            users.append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'created': str(entry.whenCreated) if entry.whenCreated.value else '',
                'status': status,
                'dn': str(entry.entry_dn),
            })

        users.sort(key=lambda u: u['created'], reverse=True)
        return True, users
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_recently_modified_accounts(hours=24):
    """Get accounts modified in the last N hours."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_str = cutoff.strftime('%Y%m%d%H%M%S.0Z')

        modified_filter = f'(&{USER_FILTER}(whenChanged>={cutoff_str}))'
        conn.search(
            cfg['BASE_DN'], modified_filter, search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName', 'displayName', 'whenChanged',
                         'distinguishedName'],
        )

        users = []
        for entry in conn.entries:
            users.append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'modified': str(entry.whenChanged) if entry.whenChanged.value else '',
                'dn': str(entry.entry_dn),
            })

        users.sort(key=lambda u: u['modified'], reverse=True)
        return True, users
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
