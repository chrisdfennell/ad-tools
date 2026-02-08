from datetime import datetime, timedelta, timezone

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def get_password_expiry_report(days_threshold=30):
    """Get users whose passwords will expire within the given number of days."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Get domain password policy (maxPwdAge from domain root)
        conn.search(cfg['BASE_DN'], '(objectClass=domain)',
                     attributes=['maxPwdAge'])
        if not conn.entries:
            return False, 'Cannot read domain password policy'

        max_pwd_age = conn.entries[0].maxPwdAge.value
        if not max_pwd_age:
            return True, []  # No password expiry policy

        # maxPwdAge is a negative timedelta
        max_pwd_days = abs(max_pwd_age.days)
        if max_pwd_days == 0:
            return True, []  # Passwords never expire

        # Get all users with pwdLastSet
        conn.search(cfg['BASE_DN'], USER_FILTER, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'pwdLastSet',
                                 'userAccountControl', 'distinguishedName'])

        now = datetime.now(timezone.utc)
        users = []
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
            # Skip disabled accounts
            if uac & 2:
                continue
            # Skip "password never expires" accounts (bit 16 = 0x10000)
            if uac & 65536:
                continue

            pwd_last_set = entry.pwdLastSet.value
            if not pwd_last_set or str(pwd_last_set) in ('0', '1601-01-01 00:00:00+00:00'):
                users.append({
                    'cn': str(entry.cn),
                    'sam': str(entry.sAMAccountName),
                    'dn': str(entry.entry_dn),
                    'pwd_last_set': 'Never',
                    'expires': 'Must change',
                    'days_remaining': -1,
                })
                continue

            if hasattr(pwd_last_set, 'replace'):
                pwd_set_dt = pwd_last_set if pwd_last_set.tzinfo else pwd_last_set.replace(tzinfo=timezone.utc)
            else:
                continue

            expiry_date = pwd_set_dt + timedelta(days=max_pwd_days)
            days_remaining = (expiry_date - now).days

            if days_remaining <= days_threshold:
                users.append({
                    'cn': str(entry.cn),
                    'sam': str(entry.sAMAccountName),
                    'dn': str(entry.entry_dn),
                    'pwd_last_set': pwd_set_dt.strftime('%Y-%m-%d %H:%M'),
                    'expires': expiry_date.strftime('%Y-%m-%d'),
                    'days_remaining': days_remaining,
                })

        users.sort(key=lambda x: x['days_remaining'])
        return True, users
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_privileged_accounts():
    """Get accounts with elevated privileges (adminCount=1, Domain Admins, etc.)."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        privileged = []
        seen_dns = set()

        # 1. Find all users with adminCount=1
        admin_filter = f'(&{USER_FILTER}(adminCount=1))'
        conn.search(cfg['BASE_DN'], admin_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'displayName', 'memberOf',
                                 'userAccountControl', 'distinguishedName'])
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            if dn in seen_dns:
                continue
            seen_dns.add(dn)
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
            status = 'disabled' if uac & 2 else 'enabled'
            groups = [str(g) for g in entry.memberOf.values] if entry.memberOf.value else []
            privileged.append({
                'cn': str(entry.cn),
                'sam': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'status': status,
                'dn': dn,
                'groups': groups,
                'source': 'adminCount=1',
            })

        # 2. Find members of well-known privileged groups using nested membership
        priv_groups = [
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Account Operators', 'Server Operators',
            'Backup Operators', 'Print Operators',
        ]
        for group_name in priv_groups:
            group_filter = f'(&(objectClass=group)(cn={group_name}))'
            conn.search(cfg['BASE_DN'], group_filter, search_scope=SUBTREE,
                         attributes=['distinguishedName'])
            if not conn.entries:
                continue
            group_dn = str(conn.entries[0].entry_dn)

            # Use LDAP_MATCHING_RULE_IN_CHAIN for nested membership
            member_filter = (
                f'(&{USER_FILTER}'
                f'(memberOf:1.2.840.113556.1.4.1941:={group_dn}))'
            )
            conn.search(cfg['BASE_DN'], member_filter, search_scope=SUBTREE,
                         attributes=['cn', 'sAMAccountName', 'displayName',
                                     'userAccountControl', 'distinguishedName'])
            for entry in conn.entries:
                dn = str(entry.entry_dn)
                if dn in seen_dns:
                    for p in privileged:
                        if p['dn'] == dn and group_name not in p['source']:
                            p['source'] += f', {group_name}'
                    continue
                seen_dns.add(dn)
                uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
                status = 'disabled' if uac & 2 else 'enabled'
                privileged.append({
                    'cn': str(entry.cn),
                    'sam': str(entry.sAMAccountName),
                    'display_name': str(entry.displayName) if entry.displayName.value else '',
                    'status': status,
                    'dn': dn,
                    'groups': [],
                    'source': group_name,
                })

        return True, privileged
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_stale_objects(days_inactive=90, object_type='users'):
    """Get users or computers that haven't logged in for X days."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        cutoff = datetime.now(timezone.utc) - timedelta(days=days_inactive)
        # Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        filetime = int((cutoff - epoch).total_seconds() * 10_000_000)

        if object_type == 'computers':
            ldap_filter = f'(&(objectClass=computer)(lastLogonTimestamp<={filetime}))'
            attrs = ['cn', 'sAMAccountName', 'lastLogonTimestamp', 'whenCreated',
                     'userAccountControl', 'operatingSystem', 'distinguishedName']
        else:
            ldap_filter = f'(&{USER_FILTER}(lastLogonTimestamp<={filetime}))'
            attrs = ['cn', 'sAMAccountName', 'lastLogonTimestamp', 'whenCreated',
                     'userAccountControl', 'distinguishedName']

        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=attrs, paged_size=1000)

        objects = []
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512
            status = 'disabled' if uac & 2 else 'enabled'
            last_logon = str(entry.lastLogonTimestamp) if entry.lastLogonTimestamp.value else 'Never'

            obj = {
                'cn': str(entry.cn) if entry.cn else '',
                'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'dn': str(entry.entry_dn),
                'last_logon': last_logon,
                'when_created': str(entry.whenCreated) if entry.whenCreated else '',
                'status': status,
            }
            if object_type == 'computers':
                obj['os'] = str(entry.operatingSystem) if entry.operatingSystem else ''
            objects.append(obj)

        return True, objects
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
