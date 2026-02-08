"""Kerberos token size estimator.

Estimates the size of a user's Kerberos ticket based on group memberships.
Based on Microsoft's documentation for token size calculation.
"""

from ldap3 import SUBTREE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection

# Token size constants (bytes)
TOKEN_BASE_SIZE = 1200  # Base ticket overhead
SID_SIZE = 40  # Approximate size per SID in the PAC
DOMAIN_LOCAL_EXTRA = 40  # Extra for domain-local group SIDs (resource groups)

# Warning thresholds
TOKEN_WARNING = 12000   # HTTP default MaxTokenSize issues start here
TOKEN_CRITICAL = 48000  # Kerberos MaxTokenSize default (Windows 2012+)
TOKEN_MAX_LEGACY = 12000  # Older Windows default MaxTokenSize


def estimate_token_size(sam_account_name):
    """Estimate Kerberos token size for a user."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Find the user
        user_filter = (
            f'(&(objectClass=user)(objectCategory=person)'
            f'(sAMAccountName={escape_rdn(sam_account_name)}))'
        )
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'distinguishedName', 'memberOf'])
        if not conn.entries:
            return False, 'User not found'

        user_entry = conn.entries[0]
        user_dn = str(user_entry.entry_dn)

        # Get direct group memberships
        direct_groups = []
        if user_entry.memberOf and user_entry.memberOf.values:
            direct_groups = [str(g) for g in user_entry.memberOf.values]

        # Get nested (transitive) group memberships
        nested_filter = (
            f'(&(objectClass=group)'
            f'(member:1.2.840.113556.1.4.1941:={user_dn}))'
        )
        conn.search(cfg['BASE_DN'], nested_filter, search_scope=SUBTREE,
                     attributes=['cn', 'sAMAccountName', 'groupType', 'distinguishedName'])

        all_groups = []
        domain_local_count = 0
        global_count = 0
        universal_count = 0

        for entry in conn.entries:
            gt = int(entry.groupType.value) if entry.groupType.value else 0
            group_info = {
                'dn': str(entry.entry_dn),
                'cn': str(entry.cn) if entry.cn else '',
                'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'group_type': gt,
                'direct': str(entry.entry_dn) in direct_groups,
            }

            # Classify group type
            if gt in (-2147483644, 4):  # Domain local
                group_info['type_label'] = 'Domain Local'
                domain_local_count += 1
            elif gt in (-2147483646, 2):  # Global
                group_info['type_label'] = 'Global'
                global_count += 1
            elif gt in (-2147483640, 8):  # Universal
                group_info['type_label'] = 'Universal'
                universal_count += 1
            else:
                group_info['type_label'] = 'Unknown'

            all_groups.append(group_info)

        # Calculate estimated token size
        total_groups = len(all_groups)
        estimated_size = TOKEN_BASE_SIZE + (total_groups * SID_SIZE) + (domain_local_count * DOMAIN_LOCAL_EXTRA)

        # Determine severity
        if estimated_size >= TOKEN_CRITICAL:
            severity = 'critical'
        elif estimated_size >= TOKEN_WARNING:
            severity = 'warning'
        else:
            severity = 'ok'

        return True, {
            'user': {
                'cn': str(user_entry.cn) if user_entry.cn else '',
                'sam': sam_account_name,
                'dn': user_dn,
            },
            'groups': all_groups,
            'stats': {
                'total_groups': total_groups,
                'direct_groups': len(direct_groups),
                'nested_groups': total_groups - len(direct_groups),
                'global_count': global_count,
                'universal_count': universal_count,
                'domain_local_count': domain_local_count,
            },
            'token': {
                'estimated_size': estimated_size,
                'severity': severity,
                'warning_threshold': TOKEN_WARNING,
                'critical_threshold': TOKEN_CRITICAL,
            },
        }
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
