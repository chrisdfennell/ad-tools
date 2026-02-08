import csv
import io
from datetime import datetime, timedelta, timezone

from ldap3 import MODIFY_REPLACE, SUBTREE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection

EXTENSION_ATTRS = [f'extensionAttribute{i}' for i in range(1, 16)]

USER_ATTRIBUTES = [
    'cn', 'sAMAccountName', 'userPrincipalName', 'givenName', 'sn',
    'displayName', 'mail', 'telephoneNumber', 'mobile', 'title',
    'department', 'company', 'description', 'manager', 'memberOf',
    'userAccountControl', 'lockoutTime', 'pwdLastSet', 'lastLogon',
    'whenCreated', 'whenChanged', 'distinguishedName', 'accountExpires',
]

# Full attribute list including extension attrs (used only in get_user detail)
USER_DETAIL_ATTRIBUTES = USER_ATTRIBUTES + EXTENSION_ATTRS

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'

# Windows FILETIME epoch (Jan 1 1601)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_NEVER_EXPIRES_VALUES = {0, 9223372036854775807}  # 0 and 0x7FFFFFFFFFFFFFFF


def _filetime_to_date(filetime_val):
    """Convert Windows FILETIME (100-ns intervals since 1601) to date string."""
    try:
        val = int(filetime_val)
        if val in _NEVER_EXPIRES_VALUES:
            return 'Never'
        dt = _FILETIME_EPOCH + timedelta(microseconds=val // 10)
        return dt.strftime('%Y-%m-%d')
    except (ValueError, TypeError, OverflowError):
        return 'Never'


def _date_to_filetime(date_str):
    """Convert YYYY-MM-DD date string to Windows FILETIME integer."""
    if not date_str or date_str.lower() == 'never':
        return 9223372036854775807  # Never expires
    dt = datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    delta = dt - _FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def _user_status(entry):
    """Derive status string from userAccountControl and lockoutTime."""
    uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
    lockout = entry.lockoutTime.value if hasattr(entry, 'lockoutTime') and entry.lockoutTime.value else None

    if lockout and str(lockout) not in ('0', '1601-01-01 00:00:00+00:00'):
        return 'locked'
    if uac & 2:
        return 'disabled'
    return 'enabled'


def search_users(query='*', ou=None):
    cfg = current_app.config
    search_base = ou or cfg['BASE_DN']
    if query and query != '*':
        ldap_filter = f'(&{USER_FILTER}(|(cn=*{escape_rdn(query)}*)(sAMAccountName=*{escape_rdn(query)}*)(mail=*{escape_rdn(query)}*)))'
    else:
        ldap_filter = USER_FILTER

    conn = None
    try:
        conn = get_connection()
        conn.search(search_base, ldap_filter, search_scope=SUBTREE,
                     attributes=USER_ATTRIBUTES, paged_size=1000)
        users = []
        for entry in conn.entries:
            users.append({
                'dn': str(entry.entry_dn),
                'cn': str(entry.cn) if entry.cn else '',
                'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'upn': str(entry.userPrincipalName) if entry.userPrincipalName else '',
                'first_name': str(entry.givenName) if entry.givenName else '',
                'last_name': str(entry.sn) if entry.sn else '',
                'display_name': str(entry.displayName) if entry.displayName else '',
                'email': str(entry.mail) if entry.mail else '',
                'phone': str(entry.telephoneNumber) if entry.telephoneNumber else '',
                'department': str(entry.department) if entry.department else '',
                'title': str(entry.title) if entry.title else '',
                'status': _user_status(entry),
                'last_logon': str(entry.lastLogon) if entry.lastLogon.value else 'Never',
                'when_created': str(entry.whenCreated) if entry.whenCreated else '',
            })
        return True, users
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_user(sam_account_name):
    cfg = current_app.config
    ldap_filter = f'(&{USER_FILTER}(sAMAccountName={escape_rdn(sam_account_name)}))'
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=USER_ATTRIBUTES)
        if not conn.entries:
            return False, 'User not found'
        entry = conn.entries[0]

        def _safe(attr):
            """Safely get a string attribute value."""
            try:
                val = getattr(entry, attr, None)
                if val is None:
                    return ''
                if hasattr(val, 'value'):
                    return str(val) if val.value else ''
                return str(val) if val else ''
            except Exception:
                return ''

        user = {
            'dn': str(entry.entry_dn),
            'cn': _safe('cn'),
            'sam': _safe('sAMAccountName'),
            'upn': _safe('userPrincipalName'),
            'first_name': _safe('givenName'),
            'last_name': _safe('sn'),
            'display_name': _safe('displayName'),
            'email': _safe('mail'),
            'phone': _safe('telephoneNumber'),
            'mobile': _safe('mobile'),
            'title': _safe('title'),
            'department': _safe('department'),
            'company': _safe('company'),
            'description': _safe('description'),
            'manager': _safe('manager'),
            'member_of': [str(g) for g in entry.memberOf] if hasattr(entry, 'memberOf') and entry.memberOf else [],
            'status': _user_status(entry),
            'uac': int(entry.userAccountControl.value) if entry.userAccountControl.value else 512,
            'last_logon': str(entry.lastLogon) if hasattr(entry, 'lastLogon') and entry.lastLogon.value else 'Never',
            'pwd_last_set': _safe('pwdLastSet'),
            'when_created': _safe('whenCreated'),
            'when_changed': _safe('whenChanged'),
            'account_expires': _filetime_to_date(_safe('accountExpires') or 0),
            'account_expires_raw': _safe('accountExpires'),
        }
        # Extension attributes (skip if schema doesn't support them)
        for attr in EXTENSION_ATTRS:
            user[attr] = _safe(attr)
        return True, user
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def create_user(fname, lname, username, password, email='', phone='', mobile='',
                title='', department='', company='', description='',
                target_ou=None):
    cfg = current_app.config
    ou = target_ou or cfg['USER_OU']
    cn = f"{fname} {lname}"
    user_dn = f"CN={escape_rdn(cn)},{ou}"

    attributes = {
        'givenName': fname,
        'sn': lname,
        'sAMAccountName': username,
        'userPrincipalName': f"{username}@{cfg['AD_DOMAIN']}.{cfg['AD_SUFFIX']}",
        'displayName': cn,
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
    }
    if email:
        attributes['mail'] = email
    if phone:
        attributes['telephoneNumber'] = phone
    if mobile:
        attributes['mobile'] = mobile
    if title:
        attributes['title'] = title
    if department:
        attributes['department'] = department
    if company:
        attributes['company'] = company
    if description:
        attributes['description'] = description

    conn = None
    try:
        conn = get_connection()
        if not conn.add(user_dn, attributes=attributes):
            return False, conn.result.get('description', 'Failed to create user')

        # Set password (AD requires quoted UTF-16-LE)
        encoded_pw = ('"%s"' % password).encode('utf-16-le')
        conn.extend.microsoft.modify_password(user_dn, encoded_pw)

        # Enable account (512 = NORMAL_ACCOUNT)
        conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, 512)]})

        return True, f"User '{username}' created successfully."
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def modify_user(user_dn, changes):
    """Modify user attributes. changes is a dict of {attr_name: new_value}."""
    conn = None
    try:
        conn = get_connection()
        modifications = {}
        for attr, value in changes.items():
            # Skip empty extension attributes to avoid schema errors
            if attr.startswith('extensionAttribute') and not value:
                continue
            # Handle accountExpires specially (needs FILETIME conversion)
            if attr == 'accountExpires':
                ft = _date_to_filetime(value)
                modifications[attr] = [(MODIFY_REPLACE, [ft])]
                continue
            if value:
                modifications[attr] = [(MODIFY_REPLACE, [value])]
            else:
                modifications[attr] = [(MODIFY_REPLACE, [])]

        if not conn.modify(user_dn, modifications):
            return False, conn.result.get('description', 'Modification failed')
        return True, 'User updated successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def delete_user(user_dn):
    conn = None
    try:
        conn = get_connection()
        if not conn.delete(user_dn):
            return False, conn.result.get('description', 'Delete failed')
        return True, 'User deleted successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def disable_user(user_dn):
    conn = None
    try:
        conn = get_connection()
        conn.search(current_app.config['BASE_DN'],
                     f'(distinguishedName={user_dn})',
                     attributes=['userAccountControl'])
        if not conn.entries:
            return False, 'User not found'
        current_uac = int(conn.entries[0].userAccountControl.value)
        new_uac = current_uac | 2  # Set disabled bit
        if not conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}):
            return False, conn.result.get('description', 'Failed to disable')
        return True, 'User disabled.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def enable_user(user_dn):
    conn = None
    try:
        conn = get_connection()
        conn.search(current_app.config['BASE_DN'],
                     f'(distinguishedName={user_dn})',
                     attributes=['userAccountControl'])
        if not conn.entries:
            return False, 'User not found'
        current_uac = int(conn.entries[0].userAccountControl.value)
        new_uac = current_uac & ~2  # Clear disabled bit
        if not conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}):
            return False, conn.result.get('description', 'Failed to enable')
        return True, 'User enabled.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def unlock_user(user_dn):
    conn = None
    try:
        conn = get_connection()
        if not conn.modify(user_dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]}):
            return False, conn.result.get('description', 'Failed to unlock')
        return True, 'User unlocked.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def reset_password(user_dn, new_password, must_change=False):
    conn = None
    try:
        conn = get_connection()
        encoded_pw = ('"%s"' % new_password).encode('utf-16-le')
        conn.extend.microsoft.modify_password(user_dn, encoded_pw)
        if must_change:
            conn.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
        return True, 'Password reset successfully.' + (' User must change at next logon.' if must_change else '')
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_user_groups(user_dn):
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], f'(member={user_dn})',
                     search_scope=SUBTREE, attributes=['cn', 'distinguishedName'])
        groups = [{'cn': str(e.cn), 'dn': str(e.entry_dn)} for e in conn.entries]
        return True, groups
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def bulk_import(csv_content):
    """Import users from CSV. Expected columns: fname,lname,username,password,email,department,title"""
    reader = csv.DictReader(io.StringIO(csv_content))
    results = []
    for row in reader:
        fname = row.get('fname', '').strip()
        lname = row.get('lname', '').strip()
        username = row.get('username', '').strip()
        password = row.get('password', '').strip()
        if not all([fname, lname, username, password]):
            results.append({'username': username or '(empty)', 'success': False, 'message': 'Missing required fields'})
            continue
        success, msg = create_user(
            fname, lname, username, password,
            email=row.get('email', '').strip(),
            department=row.get('department', '').strip(),
            title=row.get('title', '').strip(),
        )
        results.append({'username': username, 'success': success, 'message': msg})
    return results


def export_users(ou=None):
    """Export all users as CSV string."""
    success, users = search_users('*', ou)
    if not success:
        return False, users

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'sam', 'first_name', 'last_name', 'display_name', 'email',
        'phone', 'department', 'title', 'status', 'when_created',
    ])
    writer.writeheader()
    for u in users:
        writer.writerow({k: u.get(k, '') for k in writer.fieldnames})
    return True, output.getvalue()
