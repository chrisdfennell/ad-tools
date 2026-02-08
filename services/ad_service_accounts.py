"""Service Account Manager - find and report on service accounts."""

from datetime import datetime, timedelta, timezone

from ldap3 import SUBTREE
from flask import current_app

from .ad_connection import get_connection

USER_FILTER = '(&(objectClass=user)(objectCategory=person))'


def get_service_accounts():
    """Find service accounts: password never expires, non-interactive flags, SPN set, etc."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Get all user accounts with relevant attributes
        conn.search(
            cfg['BASE_DN'], USER_FILTER, search_scope=SUBTREE,
            attributes=[
                'cn', 'sAMAccountName', 'displayName', 'userAccountControl',
                'servicePrincipalName', 'pwdLastSet', 'lastLogon',
                'description', 'memberOf', 'whenCreated',
                'distinguishedName',
            ],
            paged_size=1000,
        )

        now = datetime.now(timezone.utc)
        accounts = []

        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 512

            # Flags
            pwd_never_expires = bool(uac & 0x10000)     # DONT_EXPIRE_PASSWORD
            not_delegated = bool(uac & 0x100000)         # NOT_DELEGATED
            trusted_for_deleg = bool(uac & 0x80000)      # TRUSTED_FOR_DELEGATION
            constrained_deleg = bool(uac & 0x1000000)    # TRUSTED_TO_AUTH_FOR_DELEGATION
            disabled = bool(uac & 0x2)
            cant_change_pwd = bool(uac & 0x40)           # PASSWD_CANT_CHANGE

            # Get SPNs
            spns = []
            try:
                if entry.servicePrincipalName.value:
                    spns = [str(v) for v in entry.servicePrincipalName.values]
            except Exception:
                pass

            has_spn = len(spns) > 0

            # Determine if this looks like a service account
            sam = str(entry.sAMAccountName)
            description = ''
            try:
                description = str(entry.description) if entry.description.value else ''
            except Exception:
                pass

            is_service = (
                pwd_never_expires or
                has_spn or
                sam.startswith('svc') or sam.startswith('SVC') or
                sam.startswith('svc_') or sam.startswith('svc-') or
                'service' in description.lower() or
                'service' in sam.lower()
            )

            if not is_service:
                continue

            # Password age
            pwd_age_days = None
            try:
                pwd_last_set = entry.pwdLastSet.value
                if pwd_last_set and str(pwd_last_set) not in ('0', '1601-01-01 00:00:00+00:00'):
                    if hasattr(pwd_last_set, 'replace'):
                        pdt = pwd_last_set if pwd_last_set.tzinfo else pwd_last_set.replace(tzinfo=timezone.utc)
                        pwd_age_days = (now - pdt).days
            except Exception:
                pass

            # Risk assessment
            risks = []
            if has_spn and not disabled:
                risks.append('Kerberoastable')
            if pwd_never_expires:
                risks.append('Password Never Expires')
            if pwd_age_days and pwd_age_days > 365:
                risks.append(f'Password {pwd_age_days}d old')
            if trusted_for_deleg:
                risks.append('Unconstrained Delegation')
            if constrained_deleg:
                risks.append('Constrained Delegation')

            groups = []
            try:
                if entry.memberOf.value:
                    groups = [str(g) for g in entry.memberOf.values]
            except Exception:
                pass

            accounts.append({
                'cn': str(entry.cn),
                'sam': sam,
                'display_name': str(entry.displayName) if entry.displayName.value else '',
                'description': description,
                'dn': str(entry.entry_dn),
                'status': 'disabled' if disabled else 'enabled',
                'pwd_never_expires': pwd_never_expires,
                'has_spn': has_spn,
                'spns': spns,
                'pwd_age_days': pwd_age_days,
                'trusted_for_delegation': trusted_for_deleg,
                'constrained_delegation': constrained_deleg,
                'risks': risks,
                'risk_level': 'high' if len(risks) >= 3 else 'medium' if len(risks) >= 1 else 'low',
                'group_count': len(groups),
                'created': str(entry.whenCreated) if entry.whenCreated.value else '',
            })

        accounts.sort(key=lambda a: len(a['risks']), reverse=True)
        return True, accounts
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
