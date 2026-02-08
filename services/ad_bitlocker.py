"""BitLocker Recovery Key service.

BitLocker recovery information is stored as child objects (msFVE-RecoveryInformation)
under computer objects in Active Directory.
"""

from ldap3 import SUBTREE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection


def search_recovery_keys(query=''):
    """Search for BitLocker recovery keys by computer name or recovery key ID."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        if query:
            # First try: search by computer name
            comp_filter = f'(&(objectClass=computer)(cn=*{escape_rdn(query)}*))'
            conn.search(cfg['BASE_DN'], comp_filter, search_scope=SUBTREE,
                         attributes=['cn', 'distinguishedName'])
            computer_dns = [(str(e.cn), str(e.entry_dn)) for e in conn.entries]

            # Also try searching recovery keys directly by ID
            key_filter = (
                f'(&(objectClass=msFVE-RecoveryInformation)'
                f'(|(cn=*{escape_rdn(query)}*)(msFVE-RecoveryPassword=*{escape_rdn(query)}*)))'
            )
            conn.search(cfg['BASE_DN'], key_filter, search_scope=SUBTREE,
                         attributes=['cn', 'distinguishedName', 'msFVE-RecoveryPassword',
                                     'msFVE-RecoveryGuid', 'msFVE-VolumeGuid', 'whenCreated'])
            direct_keys = [_format_recovery_key(e) for e in conn.entries]
        else:
            computer_dns = []
            direct_keys = []

        # For each computer found, look for recovery keys
        results = list(direct_keys)
        seen_dns = {k['dn'] for k in direct_keys}

        for comp_name, comp_dn in computer_dns:
            key_filter = '(objectClass=msFVE-RecoveryInformation)'
            conn.search(comp_dn, key_filter, search_scope=SUBTREE,
                         attributes=['cn', 'distinguishedName', 'msFVE-RecoveryPassword',
                                     'msFVE-RecoveryGuid', 'msFVE-VolumeGuid', 'whenCreated'])
            for entry in conn.entries:
                dn = str(entry.entry_dn)
                if dn not in seen_dns:
                    seen_dns.add(dn)
                    results.append(_format_recovery_key(entry))

        results.sort(key=lambda x: x['computer_name'].lower())
        return True, results
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_computer_recovery_keys(cn):
    """Get all BitLocker recovery keys for a specific computer."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Find the computer
        comp_filter = f'(&(objectClass=computer)(cn={escape_rdn(cn)}))'
        conn.search(cfg['BASE_DN'], comp_filter, search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'operatingSystem', 'dNSHostName'])
        if not conn.entries:
            return False, 'Computer not found'

        computer = {
            'cn': str(conn.entries[0].cn),
            'dn': str(conn.entries[0].entry_dn),
            'os': str(conn.entries[0].operatingSystem) if conn.entries[0].operatingSystem else '',
            'dns_name': str(conn.entries[0].dNSHostName) if conn.entries[0].dNSHostName else '',
        }

        # Search for recovery keys under this computer
        key_filter = '(objectClass=msFVE-RecoveryInformation)'
        conn.search(computer['dn'], key_filter, search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'msFVE-RecoveryPassword',
                                 'msFVE-RecoveryGuid', 'msFVE-VolumeGuid', 'whenCreated'])

        keys = [_format_recovery_key(e) for e in conn.entries]
        keys.sort(key=lambda x: x['created'], reverse=True)

        return True, {'computer': computer, 'keys': keys}
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _format_recovery_key(entry):
    """Format a recovery key entry."""
    dn = str(entry.entry_dn)
    # Extract computer name from DN (parent of the recovery key object)
    parts = dn.split(',')
    computer_name = ''
    for part in parts[1:]:
        if part.strip().upper().startswith('CN='):
            computer_name = part.strip()[3:]
            break

    recovery_pwd = ''
    pwd_attr = getattr(entry, 'msFVE-RecoveryPassword', None)
    if pwd_attr and pwd_attr.value:
        recovery_pwd = str(pwd_attr.value)

    recovery_guid = ''
    guid_attr = getattr(entry, 'msFVE-RecoveryGuid', None)
    if guid_attr and guid_attr.value:
        raw = guid_attr.value
        if isinstance(raw, bytes):
            # Format GUID from bytes
            recovery_guid = _format_guid_bytes(raw)
        else:
            recovery_guid = str(raw)

    volume_guid = ''
    vol_attr = getattr(entry, 'msFVE-VolumeGuid', None)
    if vol_attr and vol_attr.value:
        raw = vol_attr.value
        if isinstance(raw, bytes):
            recovery_guid_vol = _format_guid_bytes(raw)
            volume_guid = recovery_guid_vol
        else:
            volume_guid = str(raw)

    # The CN of recovery info often contains the date
    key_cn = str(entry.cn) if entry.cn else ''

    return {
        'dn': dn,
        'cn': key_cn,
        'computer_name': computer_name,
        'recovery_password': recovery_pwd,
        'recovery_guid': recovery_guid,
        'volume_guid': volume_guid,
        'created': str(entry.whenCreated) if entry.whenCreated else '',
    }


def _format_guid_bytes(raw_bytes):
    """Format raw GUID bytes into standard GUID string."""
    try:
        if len(raw_bytes) == 16:
            import struct
            parts = struct.unpack('<IHH', raw_bytes[:8])
            return '{%08x-%04x-%04x-%s-%s}' % (
                parts[0], parts[1], parts[2],
                raw_bytes[8:10].hex(),
                raw_bytes[10:16].hex(),
            )
        return raw_bytes.hex()
    except Exception:
        return str(raw_bytes)
