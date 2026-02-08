from datetime import datetime, timezone

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection


# Windows FILETIME epoch
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def _filetime_to_datetime(ft_val):
    """Convert Windows FILETIME (100-ns since 1601) to datetime or None."""
    if not ft_val or str(ft_val) in ('0', '1601-01-01 00:00:00+00:00'):
        return None
    try:
        val = int(ft_val)
        if val <= 0:
            return None
        seconds = val / 10_000_000
        return _FILETIME_EPOCH + __import__('datetime').timedelta(seconds=seconds)
    except (ValueError, OverflowError, OSError):
        # ldap3 may already return a datetime
        if isinstance(ft_val, datetime):
            return ft_val
        return None


def get_lockout_details(sam_account_name):
    """Get detailed lockout info for a specific user."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        attrs = [
            'cn', 'sAMAccountName', 'distinguishedName', 'displayName',
            'lockoutTime', 'badPwdCount', 'badPasswordTime',
            'pwdLastSet', 'userAccountControl', 'lockoutDuration',
            'lastLogon', 'lastLogonTimestamp', 'logonCount',
        ]
        conn.search(
            cfg['BASE_DN'],
            f'(&{USER_FILTER}(sAMAccountName={sam_account_name}))',
            search_scope=SUBTREE,
            attributes=attrs,
        )
        if not conn.entries:
            return False, 'User not found'

        entry = conn.entries[0]

        def _safe(attr):
            try:
                return entry[attr].value
            except Exception:
                return None

        lockout_time = _filetime_to_datetime(_safe('lockoutTime'))
        bad_pwd_time = _filetime_to_datetime(_safe('badPasswordTime'))
        last_logon = _filetime_to_datetime(_safe('lastLogon'))
        last_logon_ts = _filetime_to_datetime(_safe('lastLogonTimestamp'))

        uac = int(_safe('userAccountControl') or 512)
        is_locked = lockout_time is not None
        is_disabled = bool(uac & 0x2)

        user = {
            'cn': str(_safe('cn') or ''),
            'sam': str(_safe('sAMAccountName') or ''),
            'dn': str(entry.entry_dn),
            'display_name': str(_safe('displayName') or _safe('cn') or ''),
            'is_locked': is_locked,
            'is_disabled': is_disabled,
            'lockout_time': str(lockout_time) if lockout_time else 'Not locked',
            'bad_pwd_count': int(_safe('badPwdCount') or 0),
            'bad_pwd_time': str(bad_pwd_time) if bad_pwd_time else 'Never',
            'pwd_last_set': str(_filetime_to_datetime(_safe('pwdLastSet')) or 'Never'),
            'last_logon': str(last_logon) if last_logon else 'Never',
            'last_logon_replicated': str(last_logon_ts) if last_logon_ts else 'Never',
            'logon_count': int(_safe('logonCount') or 0),
            'uac': uac,
        }
        return True, user
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_all_locked_users():
    """Get all currently locked out users with lockout details."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        attrs = [
            'cn', 'sAMAccountName', 'distinguishedName', 'displayName',
            'lockoutTime', 'badPwdCount', 'badPasswordTime',
            'userAccountControl',
        ]
        conn.search(
            cfg['BASE_DN'],
            f'(&{USER_FILTER}(lockoutTime>=1))',
            search_scope=SUBTREE,
            attributes=attrs,
        )
        locked = []
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            lt = _filetime_to_datetime(_safe('lockoutTime'))
            if not lt:
                continue

            locked.append({
                'cn': str(_safe('cn') or ''),
                'sam': str(_safe('sAMAccountName') or ''),
                'dn': str(entry.entry_dn),
                'display_name': str(_safe('displayName') or _safe('cn') or ''),
                'lockout_time': str(lt),
                'bad_pwd_count': int(_safe('badPwdCount') or 0),
                'bad_pwd_time': str(_filetime_to_datetime(_safe('badPasswordTime')) or 'N/A'),
            })

        return True, locked
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_lockout_policy():
    """Get the domain lockout policy from the Default Domain Policy."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(
            cfg['BASE_DN'],
            '(objectClass=domain)',
            search_scope='BASE',
            attributes=[
                'lockoutThreshold', 'lockoutDuration',
                'lockOutObservationWindow',
            ],
        )
        if not conn.entries:
            return False, 'Cannot read domain policy'

        entry = conn.entries[0]

        def _safe(attr):
            try:
                return entry[attr].value
            except Exception:
                return None

        def _duration_to_minutes(val):
            """Convert AD duration (negative 100-ns intervals) to minutes."""
            if not val:
                return 0
            try:
                v = abs(int(val))
                return v // 600_000_000
            except (ValueError, TypeError):
                return 0

        policy = {
            'threshold': int(_safe('lockoutThreshold') or 0),
            'duration_minutes': _duration_to_minutes(_safe('lockoutDuration')),
            'observation_minutes': _duration_to_minutes(_safe('lockOutObservationWindow')),
        }
        return True, policy
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
