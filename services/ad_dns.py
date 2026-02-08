"""DNS Record Browser - query AD-integrated DNS zones and records."""

import struct

from ldap3 import SUBTREE, BASE, MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
from flask import current_app

from .ad_connection import get_connection


def get_dns_zones():
    """Get all AD-integrated DNS zones."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        zones = []

        # Search in DomainDnsZones partition
        dns_bases = [
            f"CN=MicrosoftDNS,DC=DomainDnsZones,{cfg['BASE_DN']}",
            f"CN=MicrosoftDNS,DC=ForestDnsZones,{cfg['BASE_DN']}",
            f"CN=MicrosoftDNS,CN=System,{cfg['BASE_DN']}",
        ]

        for dns_base in dns_bases:
            try:
                conn.search(
                    dns_base,
                    '(objectClass=dnsZone)',
                    search_scope=SUBTREE,
                    attributes=['dc', 'name', 'distinguishedName', 'whenCreated'],
                )
                for entry in conn.entries:
                    zone_name = str(entry.dc) if entry.dc.value else str(entry.name) if entry.name.value else ''
                    if zone_name and zone_name not in ('RootDNSServers', '..TrustAnchors'):
                        zones.append({
                            'name': zone_name,
                            'dn': str(entry.entry_dn),
                            'created': str(entry.whenCreated) if entry.whenCreated.value else '',
                            'partition': dns_base.split(',')[1],  # DC=DomainDnsZones, etc.
                        })
            except Exception:
                continue

        # Deduplicate by name
        seen = set()
        unique = []
        for z in zones:
            if z['name'] not in seen:
                seen.add(z['name'])
                unique.append(z)

        unique.sort(key=lambda z: z['name'].lower())
        return True, unique
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_dns_records(zone_dn):
    """Get all DNS records in a zone."""
    conn = None
    try:
        conn = get_connection()

        conn.search(
            zone_dn,
            '(objectClass=dnsNode)',
            search_scope=SUBTREE,
            attributes=['dc', 'dnsRecord', 'distinguishedName', 'dNSTombstoned'],
        )

        records = []
        for entry in conn.entries:
            hostname = str(entry.dc) if entry.dc.value else '@'
            tombstoned = False
            try:
                tombstoned = entry.dNSTombstoned.value == True
            except Exception:
                pass

            if tombstoned:
                continue

            # Parse dnsRecord binary blobs
            try:
                raw_records = entry['dnsRecord'].raw_values
                for raw in raw_records:
                    parsed = _parse_dns_record(raw)
                    if parsed:
                        parsed['hostname'] = hostname
                        parsed['dn'] = str(entry.entry_dn)
                        records.append(parsed)
            except Exception:
                records.append({
                    'hostname': hostname,
                    'type': 'Unknown',
                    'data': '(unable to parse)',
                    'ttl': '',
                    'dn': str(entry.entry_dn),
                })

        records.sort(key=lambda r: (r['hostname'].lower(), r['type']))
        return True, records
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _parse_dns_record(data):
    """Parse a single AD dnsRecord binary blob."""
    if len(data) < 24:
        return None

    # DNS_RPC_RECORD structure
    data_length = struct.unpack_from('<H', data, 0)[0]
    record_type = struct.unpack_from('<H', data, 2)[0]
    version = data[4]
    rank = data[5]
    flags = struct.unpack_from('<H', data, 6)[0]
    serial = struct.unpack_from('<I', data, 8)[0]
    ttl_raw = struct.unpack_from('>I', data, 12)[0]  # TTL is big-endian
    # timestamp at offset 20, 4 bytes

    record_data = data[24:]

    type_map = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
        15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 0: 'ZERO',
    }
    type_name = type_map.get(record_type, f'Type{record_type}')

    parsed_data = ''
    try:
        if record_type == 1 and len(record_data) >= 4:
            # A record: 4 bytes IPv4
            parsed_data = '.'.join(str(b) for b in record_data[:4])

        elif record_type == 28 and len(record_data) >= 16:
            # AAAA record: 16 bytes IPv6
            parts = []
            for i in range(0, 16, 2):
                parts.append(f'{record_data[i]:02x}{record_data[i+1]:02x}')
            parsed_data = ':'.join(parts)

        elif record_type in (2, 5, 12):
            # NS, CNAME, PTR: DNS name
            parsed_data = _parse_dns_name(record_data)

        elif record_type == 15 and len(record_data) >= 4:
            # MX: priority(2) + name
            priority = struct.unpack_from('<H', record_data, 0)[0]
            name = _parse_dns_name(record_data[2:])
            parsed_data = f'{priority} {name}'

        elif record_type == 33 and len(record_data) >= 8:
            # SRV: priority(2) + weight(2) + port(2) + name
            priority = struct.unpack_from('<H', record_data, 0)[0]
            weight = struct.unpack_from('<H', record_data, 2)[0]
            port = struct.unpack_from('<H', record_data, 4)[0]
            name = _parse_dns_name(record_data[6:])
            parsed_data = f'{priority} {weight} {port} {name}'

        elif record_type == 16:
            # TXT
            parsed_data = record_data.decode('utf-8', errors='replace')

        elif record_type == 6 and len(record_data) >= 20:
            # SOA
            parsed_data = '(SOA record)'

        else:
            parsed_data = record_data.hex() if record_data else ''
    except Exception:
        parsed_data = record_data.hex() if record_data else ''

    if record_type == 0:
        return None  # Skip ZERO/tombstone records

    return {
        'type': type_name,
        'data': parsed_data,
        'ttl': ttl_raw,
    }


def _parse_dns_name(data):
    """Parse a DNS name from AD record format (length-prefixed labels)."""
    parts = []
    pos = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            break
        pos += 1
        if pos + length > len(data):
            break
        parts.append(data[pos:pos + length].decode('utf-8', errors='replace'))
        pos += length
    return '.'.join(parts) if parts else '.'
