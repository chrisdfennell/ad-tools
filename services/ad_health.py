"""AD Health Dashboard service.

Provides infrastructure health information:
- FSMO role holders
- Domain/forest functional levels
- Domain controllers and replication
- Sites and subnets
"""

from ldap3 import SUBTREE, BASE, ALL
from flask import current_app

from .ad_connection import get_connection


def get_fsmo_roles():
    """Get FSMO role holders for the domain and forest."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        roles = {}

        # Domain-level roles (from domain root)
        conn.search(cfg['BASE_DN'], '(objectClass=*)', search_scope=BASE,
                     attributes=['fSMORoleOwner'])
        if conn.entries and conn.entries[0].fSMORoleOwner.value:
            roles['PDC Emulator'] = _ntds_to_dc(str(conn.entries[0].fSMORoleOwner.value))

        # RID Master (from RID Manager)
        rid_dn = f"CN=RID Manager$,CN=System,{cfg['BASE_DN']}"
        conn.search(rid_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['fSMORoleOwner'])
        if conn.entries and conn.entries[0].fSMORoleOwner.value:
            roles['RID Master'] = _ntds_to_dc(str(conn.entries[0].fSMORoleOwner.value))

        # Infrastructure Master
        infra_dn = f"CN=Infrastructure,{cfg['BASE_DN']}"
        conn.search(infra_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['fSMORoleOwner'])
        if conn.entries and conn.entries[0].fSMORoleOwner.value:
            roles['Infrastructure Master'] = _ntds_to_dc(str(conn.entries[0].fSMORoleOwner.value))

        # Schema Master (forest-level)
        # Schema naming context
        schema_dn = conn.server.info.other.get('schemaNamingContext', [''])[0] if conn.server.info and conn.server.info.other else ''
        if schema_dn:
            conn.search(schema_dn, '(objectClass=*)', search_scope=BASE,
                         attributes=['fSMORoleOwner'])
            if conn.entries and conn.entries[0].fSMORoleOwner.value:
                roles['Schema Master'] = _ntds_to_dc(str(conn.entries[0].fSMORoleOwner.value))

        # Domain Naming Master (forest-level)
        config_dn = conn.server.info.other.get('configurationNamingContext', [''])[0] if conn.server.info and conn.server.info.other else ''
        if config_dn:
            partitions_dn = f"CN=Partitions,{config_dn}"
            conn.search(partitions_dn, '(objectClass=*)', search_scope=BASE,
                         attributes=['fSMORoleOwner'])
            if conn.entries and conn.entries[0].fSMORoleOwner.value:
                roles['Domain Naming Master'] = _ntds_to_dc(str(conn.entries[0].fSMORoleOwner.value))

        return True, roles
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _ntds_to_dc(ntds_dn):
    """Convert NTDS Settings DN to the DC server name.

    Input:  CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,...
    Output: DC1
    """
    parts = ntds_dn.split(',')
    for part in parts:
        stripped = part.strip()
        if stripped.upper().startswith('CN=') and stripped[3:].upper() != 'NTDS SETTINGS':
            return stripped[3:]
    return ntds_dn


def get_functional_levels():
    """Get domain and forest functional levels."""
    conn = None
    try:
        conn = get_connection()

        levels = {}

        if conn.server.info:
            other = conn.server.info.other or {}

            domain_level = other.get('domainFunctionality', [''])[0]
            forest_level = other.get('forestFunctionality', [''])[0]
            dc_level = other.get('domainControllerFunctionality', [''])[0]

            level_map = {
                '0': 'Windows 2000',
                '1': 'Windows 2003 Interim',
                '2': 'Windows Server 2003',
                '3': 'Windows Server 2008',
                '4': 'Windows Server 2008 R2',
                '5': 'Windows Server 2012',
                '6': 'Windows Server 2012 R2',
                '7': 'Windows Server 2016',
                '8': 'Windows Server 2019',
                '9': 'Windows Server 2022',
                '10': 'Windows Server 2025',
            }

            levels['domain'] = level_map.get(str(domain_level), f'Unknown ({domain_level})')
            levels['forest'] = level_map.get(str(forest_level), f'Unknown ({forest_level})')
            levels['dc'] = level_map.get(str(dc_level), f'Unknown ({dc_level})')

        return True, levels
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_domain_controllers():
    """Get all domain controllers and basic info."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        dc_filter = '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        conn.search(cfg['BASE_DN'], dc_filter, search_scope=SUBTREE,
                     attributes=[
                         'cn', 'dNSHostName', 'operatingSystem',
                         'operatingSystemVersion', 'lastLogonTimestamp',
                         'whenCreated', 'distinguishedName',
                         'userAccountControl',
                     ])

        dcs = []
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 8192
            dcs.append({
                'cn': str(entry.cn) if entry.cn else '',
                'dns_name': str(entry.dNSHostName) if entry.dNSHostName else '',
                'os': str(entry.operatingSystem) if entry.operatingSystem else '',
                'os_version': str(entry.operatingSystemVersion) if entry.operatingSystemVersion else '',
                'last_logon': str(entry.lastLogonTimestamp) if entry.lastLogonTimestamp.value else 'Unknown',
                'created': str(entry.whenCreated) if entry.whenCreated else '',
                'dn': str(entry.entry_dn),
                'enabled': not bool(uac & 2),
            })

        return True, dcs
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_sites_and_subnets():
    """Get AD sites and their associated subnets."""
    conn = None
    try:
        conn = get_connection()

        config_dn = ''
        if conn.server.info and conn.server.info.other:
            config_dn = conn.server.info.other.get('configurationNamingContext', [''])[0]
        if not config_dn:
            return False, 'Cannot determine configuration naming context'

        sites_dn = f"CN=Sites,{config_dn}"

        # Get all sites
        conn.search(sites_dn, '(objectClass=site)', search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'description', 'whenCreated'])

        sites = {}
        for entry in conn.entries:
            site_cn = str(entry.cn) if entry.cn else ''
            sites[str(entry.entry_dn).lower()] = {
                'cn': site_cn,
                'dn': str(entry.entry_dn),
                'description': str(entry.description) if entry.description else '',
                'created': str(entry.whenCreated) if entry.whenCreated else '',
                'subnets': [],
                'servers': [],
            }

        # Get all subnets
        subnets_dn = f"CN=Subnets,CN=Sites,{config_dn}"
        conn.search(subnets_dn, '(objectClass=subnet)', search_scope=SUBTREE,
                     attributes=['cn', 'siteObject', 'description'])

        for entry in conn.entries:
            subnet_cn = str(entry.cn) if entry.cn else ''
            site_dn = str(entry.siteObject).lower() if entry.siteObject.value else ''
            subnet_info = {
                'name': subnet_cn,
                'description': str(entry.description) if entry.description else '',
            }
            if site_dn in sites:
                sites[site_dn]['subnets'].append(subnet_info)

        # Get servers in each site
        conn.search(sites_dn, '(objectClass=server)', search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'dNSHostName'])

        for entry in conn.entries:
            server_dn = str(entry.entry_dn)
            # Find which site this server belongs to
            for site_dn_lower, site in sites.items():
                if site_dn_lower in server_dn.lower():
                    site['servers'].append({
                        'cn': str(entry.cn) if entry.cn else '',
                        'dns_name': str(entry.dNSHostName) if entry.dNSHostName else '',
                    })
                    break

        result = sorted(sites.values(), key=lambda s: s['cn'].lower())
        return True, result
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_replication_status():
    """Get replication partner info for domain controllers."""
    conn = None
    try:
        conn = get_connection()

        config_dn = ''
        if conn.server.info and conn.server.info.other:
            config_dn = conn.server.info.other.get('configurationNamingContext', [''])[0]
        if not config_dn:
            return False, 'Cannot determine configuration naming context'

        # Find NTDS Connection objects (replication agreements)
        conn.search(config_dn,
                     '(objectClass=nTDSConnection)',
                     search_scope=SUBTREE,
                     attributes=[
                         'cn', 'distinguishedName', 'fromServer',
                         'enabledConnection', 'options', 'whenCreated',
                         'schedule',
                     ])

        connections = []
        for entry in conn.entries:
            dn = str(entry.entry_dn)
            from_server = str(entry.fromServer) if entry.fromServer.value else ''

            # Extract destination server from DN
            # DN: CN=<guid>,CN=NTDS Settings,CN=DC2,CN=Servers,...
            to_server = _ntds_to_dc(dn)
            from_dc = _ntds_to_dc(from_server)

            enabled = str(entry.enabledConnection).upper() == 'TRUE' if entry.enabledConnection.value else True

            connections.append({
                'from': from_dc,
                'to': to_server,
                'enabled': enabled,
                'auto_generated': 'automatically generated' in str(entry.cn).lower() if entry.cn else False,
                'created': str(entry.whenCreated) if entry.whenCreated else '',
            })

        return True, connections
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_tombstone_lifetime():
    """Get the tombstone lifetime and AD recycle bin status."""
    conn = None
    try:
        conn = get_connection()

        config_dn = ''
        if conn.server.info and conn.server.info.other:
            config_dn = conn.server.info.other.get('configurationNamingContext', [''])[0]
        if not config_dn:
            return False, 'Cannot determine configuration naming context'

        # Get tombstone lifetime
        ds_service_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}"
        conn.search(ds_service_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['tombstoneLifetime', 'msDS-DeletedObjectLifetime'])

        result = {'tombstone_lifetime': 180, 'deleted_object_lifetime': 180, 'recycle_bin': False}

        if conn.entries:
            entry = conn.entries[0]
            if entry.tombstoneLifetime.value:
                result['tombstone_lifetime'] = int(entry.tombstoneLifetime.value)
            deleted_lt = getattr(entry, 'msDS-DeletedObjectLifetime', None)
            if deleted_lt and deleted_lt.value:
                result['deleted_object_lifetime'] = int(deleted_lt.value)

        # Check if AD Recycle Bin is enabled
        conn.search(config_dn,
                     '(&(objectClass=msDS-OptionalFeature)(cn=Recycle Bin Feature))',
                     search_scope=SUBTREE,
                     attributes=['msDS-EnabledFeatureBL'])
        if conn.entries:
            enabled_bl = getattr(conn.entries[0], 'msDS-EnabledFeatureBL', None)
            if enabled_bl and enabled_bl.values:
                result['recycle_bin'] = True

        return True, result
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
