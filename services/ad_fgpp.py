"""Fine-Grained Password Policy (FGPP) service.

Manages Password Settings Objects (PSOs) stored in
CN=Password Settings Container,CN=System,<BASE_DN>.
"""

from datetime import timedelta

from ldap3 import SUBTREE, BASE, MODIFY_REPLACE
from flask import current_app

from .ad_connection import get_connection

PSO_ATTRIBUTES = [
    'cn', 'distinguishedName', 'msDS-PasswordSettingsPrecedence',
    'msDS-PasswordReversibleEncryptionEnabled',
    'msDS-PasswordHistoryLength', 'msDS-PasswordComplexityEnabled',
    'msDS-MinimumPasswordLength', 'msDS-MinimumPasswordAge',
    'msDS-MaximumPasswordAge', 'msDS-LockoutThreshold',
    'msDS-LockoutObservationWindow', 'msDS-LockoutDuration',
    'msDS-PSOAppliesTo', 'description', 'whenCreated', 'whenChanged',
]


def _timedelta_to_display(td):
    """Convert a timedelta to a human-readable string."""
    if td is None:
        return 'Not set'
    total_seconds = abs(int(td.total_seconds()))
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    parts = []
    if days:
        parts.append(f'{days}d')
    if hours:
        parts.append(f'{hours}h')
    if minutes:
        parts.append(f'{minutes}m')
    return ' '.join(parts) if parts else '0m'


def _format_pso(entry):
    """Format a PSO entry into a dict."""

    def _safe_int(attr_name, default=0):
        val = getattr(entry, attr_name, None)
        if val and val.value is not None:
            try:
                return int(val.value)
            except (ValueError, TypeError):
                return default
        return default

    def _safe_bool(attr_name, default=False):
        val = getattr(entry, attr_name, None)
        if val and val.value is not None:
            return str(val.value).upper() in ('TRUE', '1')
        return default

    def _safe_timedelta(attr_name):
        val = getattr(entry, attr_name, None)
        if val and val.value is not None:
            if isinstance(val.value, timedelta):
                return val.value
        return None

    def _safe_str(attr_name):
        val = getattr(entry, attr_name, None)
        if val and val.value:
            return str(val.value)
        return ''

    applies_to_attr = getattr(entry, 'msDS-PSOAppliesTo', None)
    applies_to = []
    if applies_to_attr and applies_to_attr.values:
        applies_to = [str(v) for v in applies_to_attr.values]

    min_age = _safe_timedelta('msDS-MinimumPasswordAge')
    max_age = _safe_timedelta('msDS-MaximumPasswordAge')
    lockout_window = _safe_timedelta('msDS-LockoutObservationWindow')
    lockout_duration = _safe_timedelta('msDS-LockoutDuration')

    return {
        'cn': str(entry.cn) if entry.cn else '',
        'dn': str(entry.entry_dn),
        'description': _safe_str('description'),
        'precedence': _safe_int('msDS-PasswordSettingsPrecedence', 0),
        'min_length': _safe_int('msDS-MinimumPasswordLength', 0),
        'history_length': _safe_int('msDS-PasswordHistoryLength', 0),
        'complexity_enabled': _safe_bool('msDS-PasswordComplexityEnabled'),
        'reversible_encryption': _safe_bool('msDS-PasswordReversibleEncryptionEnabled'),
        'min_age': min_age,
        'min_age_display': _timedelta_to_display(min_age),
        'max_age': max_age,
        'max_age_display': _timedelta_to_display(max_age),
        'lockout_threshold': _safe_int('msDS-LockoutThreshold', 0),
        'lockout_window': lockout_window,
        'lockout_window_display': _timedelta_to_display(lockout_window),
        'lockout_duration': lockout_duration,
        'lockout_duration_display': _timedelta_to_display(lockout_duration),
        'applies_to': applies_to,
        'applies_to_count': len(applies_to),
        'when_created': _safe_str('whenCreated'),
        'when_changed': _safe_str('whenChanged'),
    }


def get_all_fgpp():
    """Get all Fine-Grained Password Policies (PSOs)."""
    cfg = current_app.config
    pso_container = f"CN=Password Settings Container,CN=System,{cfg['BASE_DN']}"
    conn = None
    try:
        conn = get_connection()
        conn.search(pso_container,
                     '(objectClass=msDS-PasswordSettings)',
                     search_scope=SUBTREE, attributes=PSO_ATTRIBUTES)
        psos = [_format_pso(e) for e in conn.entries]
        psos.sort(key=lambda x: x['precedence'])
        return True, psos
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_fgpp_detail(pso_dn):
    """Get detailed info for a single PSO."""
    conn = None
    try:
        conn = get_connection()
        conn.search(pso_dn,
                     '(objectClass=msDS-PasswordSettings)',
                     search_scope=BASE, attributes=PSO_ATTRIBUTES)
        if not conn.entries:
            return False, 'PSO not found'

        pso = _format_pso(conn.entries[0])

        # Resolve applies-to DNs to friendly names
        resolved = []
        for target_dn in pso['applies_to']:
            conn.search(target_dn, '(objectClass=*)', search_scope=BASE,
                         attributes=['cn', 'objectClass', 'sAMAccountName'])
            if conn.entries:
                obj_classes = [str(c) for c in conn.entries[0].objectClass]
                obj_type = 'group' if 'group' in obj_classes else 'user'
                resolved.append({
                    'dn': target_dn,
                    'cn': str(conn.entries[0].cn) if conn.entries[0].cn else '',
                    'sam': str(conn.entries[0].sAMAccountName) if conn.entries[0].sAMAccountName else '',
                    'type': obj_type,
                })
            else:
                resolved.append({'dn': target_dn, 'cn': target_dn, 'sam': '', 'type': 'unknown'})

        pso['applies_to_resolved'] = resolved
        return True, pso
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_domain_password_policy():
    """Get the default domain password policy for comparison."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], '(objectClass=domain)',
                     attributes=[
                         'minPwdLength', 'pwdHistoryLength', 'pwdProperties',
                         'minPwdAge', 'maxPwdAge', 'lockoutThreshold',
                         'lockoutDuration', 'lockOutObservationWindow',
                     ])
        if not conn.entries:
            return False, 'Cannot read domain policy'

        entry = conn.entries[0]

        def _safe_int(attr, default=0):
            val = getattr(entry, attr, None)
            if val and val.value is not None:
                try:
                    return int(val.value)
                except (ValueError, TypeError):
                    return default
            return default

        def _safe_td(attr):
            val = getattr(entry, attr, None)
            if val and val.value is not None and isinstance(val.value, timedelta):
                return val.value
            return None

        pwd_props = _safe_int('pwdProperties', 0)

        return True, {
            'min_length': _safe_int('minPwdLength'),
            'history_length': _safe_int('pwdHistoryLength'),
            'complexity_enabled': bool(pwd_props & 1),
            'min_age_display': _timedelta_to_display(_safe_td('minPwdAge')),
            'max_age_display': _timedelta_to_display(_safe_td('maxPwdAge')),
            'lockout_threshold': _safe_int('lockoutThreshold'),
            'lockout_duration_display': _timedelta_to_display(_safe_td('lockoutDuration')),
            'lockout_window_display': _timedelta_to_display(_safe_td('lockOutObservationWindow')),
        }
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_effective_policy(sam_account_name):
    """Get the effective password policy for a specific user."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Find the user
        user_filter = (
            f'(&(objectClass=user)(objectCategory=person)'
            f'(sAMAccountName={sam_account_name}))'
        )
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['distinguishedName', 'msDS-ResultantPSO'])

        if not conn.entries:
            return False, 'User not found'

        resultant_pso = getattr(conn.entries[0], 'msDS-ResultantPSO', None)
        if resultant_pso and resultant_pso.value:
            pso_dn = str(resultant_pso.value)
            return get_fgpp_detail(pso_dn)
        else:
            # User uses default domain policy
            success, policy = get_domain_password_policy()
            if success:
                policy['cn'] = 'Default Domain Policy'
                policy['dn'] = cfg['BASE_DN']
                policy['is_default'] = True
                return True, policy
            return success, policy
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
