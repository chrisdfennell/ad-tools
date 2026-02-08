"""GPO Viewer service - browse Group Policy Objects and their links."""

from ldap3 import SUBTREE, BASE
from flask import current_app

from .ad_connection import get_connection


def get_all_gpos():
    """Get all Group Policy Objects in the domain."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # GPOs are stored under CN=Policies,CN=System,<BASE_DN>
        gpo_container = f"CN=Policies,CN=System,{cfg['BASE_DN']}"
        conn.search(
            gpo_container,
            '(objectClass=groupPolicyContainer)',
            search_scope=SUBTREE,
            attributes=[
                'displayName', 'cn', 'gPCFileSysPath',
                'gPCFunctionalityVersion', 'flags',
                'whenCreated', 'whenChanged', 'distinguishedName',
                'versionNumber',
            ],
        )

        gpos = []
        for entry in conn.entries:
            flags = int(entry.flags.value) if entry.flags.value else 0
            # flags: 0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled
            if flags == 0:
                status = 'Enabled'
            elif flags == 1:
                status = 'User Config Disabled'
            elif flags == 2:
                status = 'Computer Config Disabled'
            else:
                status = 'All Settings Disabled'

            version = int(entry.versionNumber.value) if entry.versionNumber.value else 0
            # Version: upper 16 bits = user version, lower 16 bits = computer version
            user_ver = version >> 16
            comp_ver = version & 0xFFFF

            gpos.append({
                'name': str(entry.displayName) if entry.displayName.value else '',
                'guid': str(entry.cn) if entry.cn.value else '',
                'dn': str(entry.entry_dn),
                'sysvol_path': str(entry.gPCFileSysPath) if entry.gPCFileSysPath.value else '',
                'status': status,
                'flags': flags,
                'user_version': user_ver,
                'computer_version': comp_ver,
                'created': str(entry.whenCreated) if entry.whenCreated.value else '',
                'modified': str(entry.whenChanged) if entry.whenChanged.value else '',
                'links': [],
            })

        # Now find GPO links on OUs and domain
        _find_gpo_links(conn, cfg['BASE_DN'], gpos)

        gpos.sort(key=lambda g: g['name'].lower())
        return True, gpos
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _find_gpo_links(conn, base_dn, gpos):
    """Find where each GPO is linked (OUs, domain, sites)."""
    gpo_by_dn = {g['dn'].lower(): g for g in gpos}

    # Search OUs and the domain root for gPLink attribute
    conn.search(
        base_dn,
        '(gPLink=*)',
        search_scope=SUBTREE,
        attributes=['distinguishedName', 'gPLink', 'ou', 'cn'],
    )

    for entry in conn.entries:
        gp_link = str(entry.gPLink) if entry.gPLink.value else ''
        container_dn = str(entry.entry_dn)
        container_name = ''
        try:
            container_name = str(entry.ou) if entry.ou.value else str(entry.cn) if entry.cn.value else container_dn
        except Exception:
            container_name = container_dn

        # gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;flags]
        # Can have multiple entries
        import re
        links = re.findall(r'\[LDAP://([^;]+);(\d+)\]', gp_link, re.IGNORECASE)
        for link_dn, link_flags in links:
            link_dn_lower = link_dn.lower()
            for gpo in gpos:
                if gpo['dn'].lower() == link_dn_lower:
                    enforced = int(link_flags) & 2
                    disabled = int(link_flags) & 1
                    gpo['links'].append({
                        'container': container_name,
                        'container_dn': container_dn,
                        'enforced': bool(enforced),
                        'link_disabled': bool(disabled),
                    })
                    break


def link_gpo(gpo_dn, container_dn, enforced=False):
    """Link a GPO to an OU or domain root."""
    import re
    conn = None
    try:
        conn = get_connection()
        from ldap3 import MODIFY_REPLACE

        conn.search(container_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['gPLink'])
        if not conn.entries:
            return False, 'Container not found'

        current_gplink = ''
        if conn.entries[0].gPLink.value:
            current_gplink = str(conn.entries[0].gPLink.value)

        if gpo_dn.lower() in current_gplink.lower():
            return False, 'GPO is already linked to this container'

        flags = 2 if enforced else 0
        new_link = f'[LDAP://{gpo_dn};{flags}]'
        new_gplink = new_link + current_gplink

        if not conn.modify(container_dn, {'gPLink': [(MODIFY_REPLACE, [new_gplink])]}):
            return False, conn.result.get('description', 'Failed to link GPO')
        return True, 'GPO linked successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def unlink_gpo(gpo_dn, container_dn):
    """Remove a GPO link from an OU or domain root."""
    import re
    conn = None
    try:
        conn = get_connection()
        from ldap3 import MODIFY_REPLACE

        conn.search(container_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['gPLink'])
        if not conn.entries:
            return False, 'Container not found'

        current_gplink = str(conn.entries[0].gPLink.value) if conn.entries[0].gPLink.value else ''
        if not current_gplink:
            return False, 'No GPO links on this container'

        pattern = re.compile(r'\[LDAP://' + re.escape(gpo_dn) + r';\d+\]', re.IGNORECASE)
        new_gplink = pattern.sub('', current_gplink)

        if new_gplink == current_gplink:
            return False, 'GPO link not found on this container'

        if new_gplink.strip():
            if not conn.modify(container_dn, {'gPLink': [(MODIFY_REPLACE, [new_gplink])]}):
                return False, conn.result.get('description', 'Failed to unlink GPO')
        else:
            if not conn.modify(container_dn, {'gPLink': [(MODIFY_REPLACE, [])]}):
                return False, conn.result.get('description', 'Failed to unlink GPO')

        return True, 'GPO unlinked successfully.'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def set_gpo_link_enforced(gpo_dn, container_dn, enforced=True):
    """Set or clear the enforced flag on a GPO link."""
    import re
    conn = None
    try:
        conn = get_connection()
        from ldap3 import MODIFY_REPLACE

        conn.search(container_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['gPLink'])
        if not conn.entries or not conn.entries[0].gPLink.value:
            return False, 'No GPO links on this container'

        current_gplink = str(conn.entries[0].gPLink.value)
        pattern = re.compile(
            r'\[LDAP://(' + re.escape(gpo_dn) + r');(\d+)\]', re.IGNORECASE
        )
        match = pattern.search(current_gplink)
        if not match:
            return False, 'GPO link not found'

        old_flags = int(match.group(2))
        new_flags = (old_flags | 2) if enforced else (old_flags & ~2)
        new_gplink = pattern.sub(f'[LDAP://{match.group(1)};{new_flags}]', current_gplink)

        if not conn.modify(container_dn, {'gPLink': [(MODIFY_REPLACE, [new_gplink])]}):
            return False, conn.result.get('description', 'Failed to update link')
        return True, 'Enforced' if enforced else 'Not enforced'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def toggle_gpo_link(gpo_dn, container_dn):
    """Enable/disable a GPO link."""
    import re
    conn = None
    try:
        conn = get_connection()
        from ldap3 import MODIFY_REPLACE

        conn.search(container_dn, '(objectClass=*)', search_scope=BASE,
                     attributes=['gPLink'])
        if not conn.entries or not conn.entries[0].gPLink.value:
            return False, 'No GPO links on this container'

        current_gplink = str(conn.entries[0].gPLink.value)
        pattern = re.compile(
            r'\[LDAP://(' + re.escape(gpo_dn) + r');(\d+)\]', re.IGNORECASE
        )
        match = pattern.search(current_gplink)
        if not match:
            return False, 'GPO link not found'

        old_flags = int(match.group(2))
        new_flags = old_flags ^ 1
        new_gplink = pattern.sub(f'[LDAP://{match.group(1)};{new_flags}]', current_gplink)

        if not conn.modify(container_dn, {'gPLink': [(MODIFY_REPLACE, [new_gplink])]}):
            return False, conn.result.get('description', 'Failed to toggle link')

        link_enabled = not (new_flags & 1)
        return True, 'Link enabled' if link_enabled else 'Link disabled'
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_linkable_containers():
    """Get all OUs and the domain root for GPO linking."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        containers = [{'dn': cfg['BASE_DN'], 'name': cfg['BASE_DN'], 'type': 'domain'}]
        conn.search(cfg['BASE_DN'], '(objectClass=organizationalUnit)',
                     search_scope=SUBTREE, attributes=['ou', 'distinguishedName'])
        for entry in conn.entries:
            containers.append({
                'dn': str(entry.entry_dn),
                'name': str(entry.ou) if entry.ou else str(entry.entry_dn),
                'type': 'ou',
            })
        containers.sort(key=lambda c: c['dn'].lower())
        return True, containers
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def get_gpo_detail(gpo_dn):
    """Get detailed info for a single GPO."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(
            gpo_dn,
            '(objectClass=groupPolicyContainer)',
            search_scope=BASE,
            attributes=['*'],
        )
        if not conn.entries:
            return False, 'GPO not found'

        entry = conn.entries[0]
        attrs = {}
        for attr_name in entry.entry_attributes:
            raw_val = getattr(entry, attr_name)
            if raw_val and raw_val.values:
                if len(raw_val.values) == 1:
                    attrs[attr_name] = str(raw_val.value)
                else:
                    attrs[attr_name] = [str(v) for v in raw_val.values]
            else:
                attrs[attr_name] = ''

        # Find links for this GPO
        links = []
        conn.search(cfg['BASE_DN'], '(gPLink=*)', search_scope=SUBTREE,
                     attributes=['distinguishedName', 'gPLink', 'ou', 'cn'])
        import re
        for link_entry in conn.entries:
            gp_link = str(link_entry.gPLink) if link_entry.gPLink.value else ''
            if gpo_dn.lower() in gp_link.lower():
                container_name = ''
                try:
                    container_name = str(link_entry.ou) if link_entry.ou.value else str(link_entry.cn)
                except Exception:
                    container_name = str(link_entry.entry_dn)
                found = re.findall(r'\[LDAP://([^;]+);(\d+)\]', gp_link, re.IGNORECASE)
                for link_dn, link_flags in found:
                    if link_dn.lower() == gpo_dn.lower():
                        links.append({
                            'container': container_name,
                            'container_dn': str(link_entry.entry_dn),
                            'enforced': bool(int(link_flags) & 2),
                            'link_disabled': bool(int(link_flags) & 1),
                        })

        return True, {'dn': gpo_dn, 'attributes': attrs, 'links': links}
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()
