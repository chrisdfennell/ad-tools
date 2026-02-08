"""AD Object ACL/Permissions viewer.

Reads the nTSecurityDescriptor attribute and decodes ACEs into
human-readable form. Uses ldap3's built-in security descriptor parsing.
"""

from ldap3 import SUBTREE, ALL_ATTRIBUTES
from ldap3.protocol.microsoft import security_descriptor_control
from flask import current_app

from .ad_connection import get_connection


# Well-known SID mappings
WELL_KNOWN_SIDS = {
    'S-1-0-0': 'Nobody',
    'S-1-1-0': 'Everyone',
    'S-1-2-0': 'Local',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-5-7': 'Anonymous Logon',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-18': 'SYSTEM',
    'S-1-5-19': 'Local Service',
    'S-1-5-20': 'Network Service',
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-32-548': 'BUILTIN\\Account Operators',
    'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-550': 'BUILTIN\\Print Operators',
    'S-1-5-32-551': 'BUILTIN\\Backup Operators',
    'S-1-5-32-552': 'BUILTIN\\Replicator',
}

# Access mask bit meanings for AD
ACCESS_RIGHTS = {
    0x00000001: 'Create Child',
    0x00000002: 'Delete Child',
    0x00000004: 'List Contents',
    0x00000008: 'Self Write',
    0x00000010: 'Read Property',
    0x00000020: 'Write Property',
    0x00000040: 'Delete Tree',
    0x00000080: 'List Object',
    0x00000100: 'Extended Right',
    0x00010000: 'Delete',
    0x00020000: 'Read Control',
    0x00040000: 'Write DACL',
    0x00080000: 'Write Owner',
    0x10000000: 'Generic All',
    0x20000000: 'Generic Execute',
    0x40000000: 'Generic Write',
    0x80000000: 'Generic Read',
}

# Well-known extended right / property set GUIDs
KNOWN_GUIDS = {
    '00299570-246d-11d0-a768-00aa006e0529': 'Reset Password',
    'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send As',
    'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive As',
    '00000000-0000-0000-0000-000000000000': 'All Properties',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'memberOf',
    'bf967a86-0de6-11d0-a285-00aa003049e2': 'unicodePwd',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire Password',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'User Account Restrictions',
    '5f202010-79a5-11d0-9020-00c04fc2d4cf': 'User Logon Information',
    '59ba2f42-79a2-11d0-9020-00c04fc2d4cf': 'General Information',
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf': 'Group Membership',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'Public Information',
    '77b5b886-944a-11d1-aebd-0000f80367c1': 'Personal Information',
    'e45795b2-9455-11d1-aebd-0000f80367c1': 'Email Information',
    'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open Address List',
}

ACE_TYPE_NAMES = {
    0: 'Allow',
    1: 'Deny',
    5: 'Allow (Object)',
    6: 'Deny (Object)',
}


def _decode_access_mask(mask):
    """Decode an access mask integer into human-readable rights."""
    rights = []
    for bit, name in ACCESS_RIGHTS.items():
        if mask & bit:
            rights.append(name)
    if not rights:
        rights.append(f'0x{mask:08x}')
    return rights


def _resolve_sid(conn, sid_str, base_dn, cache):
    """Resolve a SID to a display name. Uses cache to avoid repeated lookups."""
    if sid_str in cache:
        return cache[sid_str]

    if sid_str in WELL_KNOWN_SIDS:
        cache[sid_str] = WELL_KNOWN_SIDS[sid_str]
        return cache[sid_str]

    try:
        conn.search(
            base_dn,
            f'(objectSid={sid_str})',
            search_scope=SUBTREE,
            attributes=['cn', 'sAMAccountName'],
        )
        if conn.entries:
            name = str(conn.entries[0]['sAMAccountName'].value or conn.entries[0]['cn'].value)
            cache[sid_str] = name
            return name
    except Exception:
        pass

    cache[sid_str] = sid_str
    return sid_str


def get_object_acl(object_dn):
    """Read and decode the ACL (DACL) for an AD object."""
    conn = None
    try:
        conn = get_connection()
        cfg = current_app.config

        # Request nTSecurityDescriptor with the SD control
        conn.search(
            object_dn,
            '(objectClass=*)',
            search_scope='BASE',
            attributes=['nTSecurityDescriptor', 'cn', 'objectClass'],
            controls=[security_descriptor_control(sdflags=0x04)],
        )
        if not conn.entries:
            return False, 'Object not found'

        entry = conn.entries[0]
        obj_name = str(entry['cn'].value or '')

        # Parse the raw security descriptor
        try:
            sd_bytes = entry['nTSecurityDescriptor'].raw_values[0]
        except (IndexError, AttributeError):
            return False, 'Cannot read security descriptor'

        aces = _parse_security_descriptor(sd_bytes)

        # Resolve SIDs to names
        sid_cache = dict(WELL_KNOWN_SIDS)
        for ace in aces:
            ace['trustee_name'] = _resolve_sid(conn, ace['trustee_sid'], cfg['BASE_DN'], sid_cache)
            ace['rights_list'] = _decode_access_mask(ace['access_mask'])
            ace['type_name'] = ACE_TYPE_NAMES.get(ace['ace_type'], f"Type {ace['ace_type']}")
            guid = ace.get('object_guid', '')
            ace['guid_name'] = KNOWN_GUIDS.get(guid, guid) if guid else ''

        return True, {'dn': object_dn, 'name': obj_name, 'aces': aces}
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _parse_security_descriptor(sd_bytes):
    """Parse a raw NT Security Descriptor to extract DACL ACEs."""
    aces = []
    try:
        import struct

        # SD header: revision(1), sbz1(1), control(2), offset_owner(4), offset_group(4),
        #            offset_sacl(4), offset_dacl(4)
        if len(sd_bytes) < 20:
            return aces

        revision, _, control, off_owner, off_group, off_sacl, off_dacl = struct.unpack_from('<BBHIIII', sd_bytes, 0)

        if off_dacl == 0:
            return aces

        # DACL header: revision(1), sbz1(1), size(2), ace_count(2), sbz2(2)
        dacl_rev, _, dacl_size, ace_count, _ = struct.unpack_from('<BBHHH', sd_bytes, off_dacl)

        offset = off_dacl + 8  # past DACL header
        for _ in range(ace_count):
            if offset + 4 > len(sd_bytes):
                break

            ace_type, ace_flags, ace_size = struct.unpack_from('<BBH', sd_bytes, offset)

            ace_data = {
                'ace_type': ace_type,
                'ace_flags': ace_flags,
                'inherited': bool(ace_flags & 0x10),
            }

            if ace_type in (0, 1):  # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE
                if offset + 8 + 8 <= len(sd_bytes):
                    access_mask = struct.unpack_from('<I', sd_bytes, offset + 4)[0]
                    sid = _parse_sid(sd_bytes, offset + 8)
                    ace_data['access_mask'] = access_mask
                    ace_data['trustee_sid'] = sid
                    ace_data['object_guid'] = ''
                    aces.append(ace_data)

            elif ace_type in (5, 6):  # ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE
                if offset + 12 <= len(sd_bytes):
                    access_mask = struct.unpack_from('<I', sd_bytes, offset + 4)[0]
                    obj_flags = struct.unpack_from('<I', sd_bytes, offset + 8)[0]

                    guid_offset = offset + 12
                    obj_guid = ''
                    if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                        if guid_offset + 16 <= len(sd_bytes):
                            obj_guid = _parse_guid(sd_bytes[guid_offset:guid_offset + 16])
                            guid_offset += 16
                    if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                        guid_offset += 16

                    sid = _parse_sid(sd_bytes, guid_offset)
                    ace_data['access_mask'] = access_mask
                    ace_data['trustee_sid'] = sid
                    ace_data['object_guid'] = obj_guid
                    aces.append(ace_data)

            offset += ace_size

    except Exception:
        pass

    return aces


def _parse_sid(data, offset):
    """Parse a SID from binary data."""
    import struct
    try:
        if offset + 8 > len(data):
            return 'S-1-0-0'

        revision = data[offset]
        sub_count = data[offset + 1]
        authority = struct.unpack_from('>Q', b'\x00\x00' + data[offset + 2:offset + 8], 0)[0]

        subs = []
        for i in range(sub_count):
            sub_offset = offset + 8 + (i * 4)
            if sub_offset + 4 > len(data):
                break
            subs.append(struct.unpack_from('<I', data, sub_offset)[0])

        return f"S-{revision}-{authority}" + ''.join(f'-{s}' for s in subs)
    except Exception:
        return 'S-1-0-0'


def _parse_guid(data):
    """Parse a 16-byte GUID into string form."""
    import struct
    try:
        p1, p2, p3 = struct.unpack_from('<IHH', data, 0)
        p4 = data[8:10]
        p5 = data[10:16]
        return f'{p1:08x}-{p2:04x}-{p3:04x}-{p4.hex()}-{p5.hex()}'
    except Exception:
        return ''
