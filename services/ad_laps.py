"""LAPS (Local Administrator Password Solution) service.

Reads LAPS passwords from computer objects.
- Legacy LAPS: ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
- Windows LAPS: msLAPS-Password, msLAPS-PasswordExpirationTime, msLAPS-EncryptedPassword
"""

import json
from datetime import datetime, timezone, timedelta

from ldap3 import SUBTREE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection

LAPS_ATTRIBUTES = [
    'cn', 'sAMAccountName', 'distinguishedName', 'operatingSystem',
    'dNSHostName', 'userAccountControl',
    # Legacy LAPS
    'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime',
    # Windows LAPS
    'msLAPS-Password', 'msLAPS-PasswordExpirationTime',
    'msLAPS-EncryptedPassword',
]


def _filetime_to_datetime(filetime):
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    try:
        ft = int(filetime)
        if ft <= 0:
            return None
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return epoch + timedelta(microseconds=ft // 10)
    except (ValueError, TypeError, OverflowError):
        return None


def search_laps(query=''):
    """Search for computers with LAPS passwords."""
    cfg = current_app.config
    search_base = cfg.get('COMPUTERS_OU') or cfg['BASE_DN']

    # Build filter for computers that have at least one LAPS attribute
    if query:
        name_filter = f'(cn=*{escape_rdn(query)}*)'
    else:
        name_filter = ''

    laps_filter = (
        f'(&(objectClass=computer){name_filter}'
        f'(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))'
    )

    conn = None
    try:
        conn = get_connection()
        conn.search(search_base, laps_filter, search_scope=SUBTREE,
                     attributes=LAPS_ATTRIBUTES, paged_size=500)

        results = []
        for entry in conn.entries:
            results.append(_format_laps_entry(entry))

        results.sort(key=lambda x: x['cn'].lower())
        return True, results
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_laps_password(cn):
    """Get LAPS password for a specific computer."""
    cfg = current_app.config
    ldap_filter = f'(&(objectClass=computer)(cn={escape_rdn(cn)}))'

    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=LAPS_ATTRIBUTES)
        if not conn.entries:
            return False, 'Computer not found'

        entry = conn.entries[0]
        result = _format_laps_entry(entry)
        if not result['has_laps']:
            return False, 'No LAPS password found for this computer'
        return True, result
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _format_laps_entry(entry):
    """Format a computer entry with LAPS data."""
    uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 4096
    status = 'disabled' if uac & 2 else 'enabled'

    result = {
        'cn': str(entry.cn) if entry.cn else '',
        'dn': str(entry.entry_dn),
        'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
        'dns_name': str(entry.dNSHostName) if entry.dNSHostName else '',
        'os': str(entry.operatingSystem) if entry.operatingSystem else '',
        'status': status,
        'has_laps': False,
        'laps_type': None,
        'password': None,
        'account': None,
        'expiry': None,
        'expiry_dt': None,
        'encrypted': False,
    }

    # Check Legacy LAPS first
    legacy_pwd = getattr(entry, 'ms-Mcs-AdmPwd', None)
    if legacy_pwd and legacy_pwd.value:
        result['has_laps'] = True
        result['laps_type'] = 'Legacy LAPS'
        result['password'] = str(legacy_pwd.value)
        result['account'] = 'Administrator'

        legacy_exp = getattr(entry, 'ms-Mcs-AdmPwdExpirationTime', None)
        if legacy_exp and legacy_exp.value:
            exp_dt = _filetime_to_datetime(legacy_exp.value)
            if exp_dt:
                result['expiry_dt'] = exp_dt
                result['expiry'] = exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        return result

    # Check Windows LAPS (cleartext JSON)
    win_pwd = getattr(entry, 'msLAPS-Password', None)
    if win_pwd and win_pwd.value:
        result['has_laps'] = True
        result['laps_type'] = 'Windows LAPS'
        try:
            pwd_data = json.loads(str(win_pwd.value))
            result['password'] = pwd_data.get('p', '')
            result['account'] = pwd_data.get('n', 'Administrator')
        except (json.JSONDecodeError, TypeError):
            result['password'] = str(win_pwd.value)
            result['account'] = 'Administrator'

        win_exp = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
        if win_exp and win_exp.value:
            exp_dt = _filetime_to_datetime(win_exp.value)
            if exp_dt:
                result['expiry_dt'] = exp_dt
                result['expiry'] = exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        return result

    # Check Windows LAPS (encrypted)
    enc_pwd = getattr(entry, 'msLAPS-EncryptedPassword', None)
    if enc_pwd and enc_pwd.value:
        result['has_laps'] = True
        result['laps_type'] = 'Windows LAPS (Encrypted)'
        result['encrypted'] = True
        result['password'] = '(Encrypted - cannot be displayed via LDAP)'
        result['account'] = 'Administrator'

        win_exp = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
        if win_exp and win_exp.value:
            exp_dt = _filetime_to_datetime(win_exp.value)
            if exp_dt:
                result['expiry_dt'] = exp_dt
                result['expiry'] = exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')

    return result
