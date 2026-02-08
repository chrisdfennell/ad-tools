"""AD Replication Status Monitor.

Queries replication metadata from NTDS Settings objects and
msDS-ReplConnectionFailures to show inter-DC replication health.
"""

from ldap3 import SUBTREE, BASE
from flask import current_app

from .ad_connection import get_connection


def _get_config_dn(conn):
    try:
        info = conn.server.info
        return str(info.other.get('configurationNamingContext', [None])[0])
    except Exception:
        base = current_app.config['BASE_DN']
        return f"CN=Configuration,{base}"


def get_replication_status():
    """Get replication partner information and status for all DCs."""
    conn = None
    try:
        conn = get_connection()
        cfg = current_app.config
        config_dn = _get_config_dn(conn)

        # Find all NTDS Settings objects (one per DC)
        conn.search(
            f"CN=Sites,{config_dn}",
            '(objectClass=nTDSDSA)',
            search_scope=SUBTREE,
            attributes=['cn', 'distinguishedName'],
        )
        ntds_entries = [str(e.entry_dn) for e in conn.entries]

        # Get replication connections
        connections = []
        for ntds_dn in ntds_entries:
            # The server DN is the parent of the NTDS Settings DN
            server_dn = ','.join(ntds_dn.split(',')[1:])

            # Get server name
            conn.search(server_dn, '(objectClass=server)', search_scope=BASE,
                        attributes=['cn', 'dNSHostName'])
            server_name = ''
            server_dns = ''
            if conn.entries:
                server_name = str(conn.entries[0]['cn'].value or '')
                server_dns = str(conn.entries[0]['dNSHostName'].value or '') if hasattr(conn.entries[0], 'dNSHostName') else ''

            # Get replication connections under this NTDS Settings
            conn.search(ntds_dn, '(objectClass=nTDSConnection)', search_scope=SUBTREE,
                        attributes=['cn', 'fromServer', 'enabledConnection', 'whenCreated',
                                    'schedule', 'options', 'transportType'])
            for entry in conn.entries:
                def _safe(attr, e=entry):
                    try:
                        return e[attr].value
                    except Exception:
                        return None

                from_server = str(_safe('fromServer') or '')
                # Extract source server name from the fromServer DN
                from_name = ''
                if from_server:
                    parts = from_server.split(',')
                    for p in parts:
                        if p.startswith('CN=') and p != 'CN=NTDS Settings':
                            from_name = p.replace('CN=', '')
                            break

                enabled = _safe('enabledConnection')
                options = int(_safe('options') or 0)
                auto_generated = bool(options & 1)

                connections.append({
                    'to_server': server_name,
                    'to_dns': server_dns,
                    'from_server': from_name,
                    'from_dn': from_server,
                    'enabled': enabled if enabled is not None else True,
                    'auto_generated': auto_generated,
                    'when_created': str(_safe('whenCreated') or ''),
                    'name': str(_safe('cn') or ''),
                })

        # Query replication metadata from RootDSE
        # msDS-ReplAllInboundNeighbors gives replication partner status
        repl_partners = []
        try:
            conn.search(
                '', '(objectClass=*)', search_scope=BASE,
                attributes=['msDS-ReplAllInboundNeighbors'],
            )
            if conn.entries:
                raw = conn.entries[0]['msDS-ReplAllInboundNeighbors'].values
                if raw:
                    for item in raw:
                        # Each item is an XML-formatted replication neighbor descriptor
                        repl_partners.append(str(item))
        except Exception:
            pass

        # Get DCs list
        dcs = []
        conn.search(
            cfg['BASE_DN'],
            '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            search_scope=SUBTREE,
            attributes=['cn', 'dNSHostName', 'operatingSystem', 'whenCreated'],
        )
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None
            dcs.append({
                'cn': str(_safe('cn') or ''),
                'dns_host': str(_safe('dNSHostName') or ''),
                'os': str(_safe('operatingSystem') or ''),
                'when_created': str(_safe('whenCreated') or ''),
            })

        return True, {
            'connections': connections,
            'dcs': dcs,
            'repl_partners_raw': repl_partners,
        }
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
