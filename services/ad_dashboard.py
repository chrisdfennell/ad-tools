from datetime import datetime, timedelta, timezone

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def get_dashboard_stats():
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
    except Exception as e:
        return False, f'Cannot connect to AD: {e}'
    try:
        stats = {}

        # Total users
        conn.search(cfg['BASE_DN'], USER_FILTER, search_scope=SUBTREE, attributes=['cn'])
        stats['total_users'] = len(conn.entries)

        # Disabled users (bit 1 = ACCOUNTDISABLE)
        conn.search(cfg['BASE_DN'],
                     f'(&{USER_FILTER}(userAccountControl:1.2.840.113556.1.4.803:=2))',
                     search_scope=SUBTREE, attributes=['cn'])
        stats['disabled_users'] = len(conn.entries)

        # Active users
        stats['active_users'] = stats['total_users'] - stats['disabled_users']

        # Locked out users
        conn.search(cfg['BASE_DN'],
                     f'(&{USER_FILTER}(lockoutTime>=1))',
                     search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'lockoutTime', 'distinguishedName'])
        locked = []
        for e in conn.entries:
            lt = e.lockoutTime.value
            if lt and str(lt) not in ('0', '1601-01-01 00:00:00+00:00'):
                locked.append({
                    'cn': str(e.cn),
                    'sam': str(e.sAMAccountName),
                    'dn': str(e.entry_dn),
                    'lockout_time': str(lt),
                })
        stats['locked_users'] = len(locked)
        stats['locked_user_list'] = locked

        # Total groups
        conn.search(cfg['BASE_DN'], '(objectClass=group)', search_scope=SUBTREE, attributes=['cn'])
        stats['total_groups'] = len(conn.entries)

        # Total computers
        conn.search(cfg['BASE_DN'], '(objectClass=computer)', search_scope=SUBTREE, attributes=['cn'])
        stats['total_computers'] = len(conn.entries)

        # Recently created users (last 7 days)
        seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y%m%d%H%M%S.0Z')
        conn.search(cfg['BASE_DN'],
                     f'(&{USER_FILTER}(whenCreated>={seven_days_ago}))',
                     search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'whenCreated'])
        stats['recent_users'] = [
            {
                'cn': str(e.cn),
                'sam': str(e.sAMAccountName),
                'when_created': str(e.whenCreated),
            }
            for e in conn.entries
        ]

        # Recently modified objects (last 7 days)
        conn.search(cfg['BASE_DN'],
                     f'(&{USER_FILTER}(whenChanged>={seven_days_ago}))',
                     search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'whenChanged'])
        stats['recent_modified'] = [
            {
                'cn': str(e.cn),
                'sam': str(e.sAMAccountName),
                'when_changed': str(e.whenChanged),
            }
            for e in conn.entries
        ][:10]

        # Top 10 groups by member count (for chart)
        conn.search(cfg['BASE_DN'],
                     '(objectClass=group)',
                     search_scope=SUBTREE,
                     attributes=['cn', 'member'])
        top_groups = []
        for e in conn.entries:
            members = e['member'].values if hasattr(e['member'], 'values') else []
            if members:
                top_groups.append({
                    'cn': str(e.cn),
                    'count': len(members),
                })
        top_groups.sort(key=lambda g: g['count'], reverse=True)
        stats['top_groups'] = top_groups[:10]

        # Password expiry buckets (for chart)
        # Query users with pwdLastSet set, calculate rough buckets
        conn.search(cfg['BASE_DN'],
                     f'(&{USER_FILTER}(!(userAccountControl:1.2.840.113556.1.4.803:=65536))(pwdLastSet>=1))',
                     search_scope=SUBTREE,
                     attributes=['pwdLastSet'])
        now = datetime.now(timezone.utc)
        expiry_buckets = {'Expired': 0, '0-7 days': 0, '8-30 days': 0, '31-90 days': 0, '90+ days': 0}
        for e in conn.entries:
            try:
                pwd_set = e['pwdLastSet'].value
                if not pwd_set or str(pwd_set) == '0':
                    continue
                if isinstance(pwd_set, datetime):
                    age_days = (now - pwd_set.replace(tzinfo=timezone.utc if pwd_set.tzinfo is None else pwd_set.tzinfo)).days
                else:
                    continue
                # Assume 90-day max password age (common default)
                days_left = 90 - age_days
                if days_left < 0:
                    expiry_buckets['Expired'] += 1
                elif days_left <= 7:
                    expiry_buckets['0-7 days'] += 1
                elif days_left <= 30:
                    expiry_buckets['8-30 days'] += 1
                elif days_left <= 90:
                    expiry_buckets['31-90 days'] += 1
                else:
                    expiry_buckets['90+ days'] += 1
            except Exception:
                continue
        stats['expiry_buckets'] = expiry_buckets

        return True, stats
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
