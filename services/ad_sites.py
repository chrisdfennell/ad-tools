from ldap3 import SUBTREE, BASE
from flask import current_app

from .ad_connection import get_connection


def _get_config_dn(conn):
    """Get the Configuration naming context from RootDSE."""
    try:
        info = conn.server.info
        return str(info.other.get('configurationNamingContext', [None])[0])
    except Exception:
        # Fallback: derive from BASE_DN
        base = current_app.config['BASE_DN']
        return f"CN=Configuration,{base}"


def get_sites():
    """Get all AD sites with their subnets and servers."""
    conn = None
    try:
        conn = get_connection()
        config_dn = _get_config_dn(conn)
        sites_dn = f"CN=Sites,{config_dn}"

        # Get all sites
        conn.search(
            sites_dn,
            '(objectClass=site)',
            search_scope=SUBTREE,
            attributes=['cn', 'description', 'location', 'whenCreated', 'whenChanged'],
        )
        sites = []
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            sites.append({
                'cn': str(_safe('cn') or ''),
                'dn': str(entry.entry_dn),
                'description': str(_safe('description') or ''),
                'location': str(_safe('location') or ''),
                'when_created': str(_safe('whenCreated') or ''),
                'subnets': [],
                'servers': [],
            })

        # Get all subnets
        subnets_dn = f"CN=Subnets,CN=Sites,{config_dn}"
        conn.search(
            subnets_dn,
            '(objectClass=subnet)',
            search_scope=SUBTREE,
            attributes=['cn', 'description', 'siteObject', 'location'],
        )
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            site_obj = str(_safe('siteObject') or '')
            subnet = {
                'cn': str(_safe('cn') or ''),
                'description': str(_safe('description') or ''),
                'location': str(_safe('location') or ''),
                'site_dn': site_obj,
            }
            # Associate subnet with its site
            for site in sites:
                if site['dn'].lower() == site_obj.lower():
                    site['subnets'].append(subnet)
                    break

        # Get servers in each site
        for site in sites:
            servers_dn = f"CN=Servers,{site['dn']}"
            try:
                conn.search(
                    servers_dn,
                    '(objectClass=server)',
                    search_scope=SUBTREE,
                    attributes=['cn', 'dNSHostName'],
                )
                for entry in conn.entries:
                    def _safe(attr, e=entry):
                        try:
                            return e[attr].value
                        except Exception:
                            return None
                    site['servers'].append({
                        'cn': str(_safe('cn') or ''),
                        'dns_host': str(_safe('dNSHostName') or ''),
                    })
            except Exception:
                pass

        return True, sites
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_site_links():
    """Get all AD site links."""
    conn = None
    try:
        conn = get_connection()
        config_dn = _get_config_dn(conn)
        links_dn = f"CN=IP,CN=Inter-Site Transports,CN=Sites,{config_dn}"

        conn.search(
            links_dn,
            '(objectClass=siteLink)',
            search_scope=SUBTREE,
            attributes=['cn', 'cost', 'replInterval', 'siteList', 'description', 'options'],
        )
        links = []
        for entry in conn.entries:
            def _safe(attr, e=entry):
                try:
                    return e[attr].value
                except Exception:
                    return None

            def _safe_list(attr, e=entry):
                try:
                    val = e[attr].value
                    if isinstance(val, list):
                        return val
                    return [val] if val else []
                except Exception:
                    return []

            site_list = _safe_list('siteList')
            # Extract site names from DNs
            site_names = []
            for s in site_list:
                parts = str(s).split(',')
                if parts:
                    name = parts[0].replace('CN=', '')
                    site_names.append(name)

            links.append({
                'cn': str(_safe('cn') or ''),
                'cost': int(_safe('cost') or 100),
                'repl_interval': int(_safe('replInterval') or 180),
                'description': str(_safe('description') or ''),
                'sites': site_names,
                'site_count': len(site_names),
            })

        return True, links
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
