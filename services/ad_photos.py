"""User Photo Management service.

Handles reading and writing thumbnailPhoto on AD user objects.
Photos are stored as JPEG binary data and propagate to Outlook/Teams/SharePoint.
"""

import base64

from ldap3 import SUBTREE, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection


def get_user_photo(sam_account_name):
    """Get the thumbnailPhoto for a user as base64-encoded data."""
    cfg = current_app.config
    user_filter = (
        f'(&(objectClass=user)(objectCategory=person)'
        f'(sAMAccountName={escape_rdn(sam_account_name)}))'
    )
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['thumbnailPhoto', 'cn', 'distinguishedName'])
        if not conn.entries:
            return False, 'User not found'

        entry = conn.entries[0]
        photo_data = entry.thumbnailPhoto.value if entry.thumbnailPhoto.value else None

        if photo_data:
            b64 = base64.b64encode(photo_data).decode('ascii')
            return True, {
                'cn': str(entry.cn),
                'dn': str(entry.entry_dn),
                'has_photo': True,
                'photo_b64': b64,
                'photo_size': len(photo_data),
            }
        else:
            return True, {
                'cn': str(entry.cn),
                'dn': str(entry.entry_dn),
                'has_photo': False,
                'photo_b64': None,
                'photo_size': 0,
            }
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def set_user_photo(sam_account_name, photo_bytes):
    """Set the thumbnailPhoto for a user.

    Args:
        sam_account_name: The user's sAMAccountName
        photo_bytes: Raw JPEG/PNG image bytes (will be stored as-is)
    """
    cfg = current_app.config
    user_filter = (
        f'(&(objectClass=user)(objectCategory=person)'
        f'(sAMAccountName={escape_rdn(sam_account_name)}))'
    )
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['distinguishedName'])
        if not conn.entries:
            return False, 'User not found'

        user_dn = str(conn.entries[0].entry_dn)

        if not conn.modify(user_dn, {
            'thumbnailPhoto': [(MODIFY_REPLACE, [photo_bytes])]
        }):
            return False, conn.result.get('description', 'Failed to set photo')

        return True, 'Photo updated successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def delete_user_photo(sam_account_name):
    """Remove the thumbnailPhoto from a user."""
    cfg = current_app.config
    user_filter = (
        f'(&(objectClass=user)(objectCategory=person)'
        f'(sAMAccountName={escape_rdn(sam_account_name)}))'
    )
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], user_filter, search_scope=SUBTREE,
                     attributes=['distinguishedName'])
        if not conn.entries:
            return False, 'User not found'

        user_dn = str(conn.entries[0].entry_dn)

        if not conn.modify(user_dn, {
            'thumbnailPhoto': [(MODIFY_REPLACE, [])]
        }):
            return False, conn.result.get('description', 'Failed to remove photo')

        return True, 'Photo removed successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
