"""Group Nesting Visualizer service.

Builds a tree of group memberships to visualize nesting depth,
detect circular references, and show effective vs direct members.
"""

from ldap3 import SUBTREE
from ldap3.utils.dn import escape_rdn
from flask import current_app

from .ad_connection import get_connection


def get_group_nesting_tree(group_cn):
    """Build a tree showing all nested group memberships for a group.

    Returns a tree structure showing:
    - Direct members (users and groups)
    - For each member group, its own members recursively
    - Circular reference detection
    """
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        # Find the group
        ldap_filter = f'(&(objectClass=group)(cn={escape_rdn(group_cn)}))'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'member', 'description'])
        if not conn.entries:
            return False, 'Group not found'

        root_dn = str(conn.entries[0].entry_dn)
        root_cn = str(conn.entries[0].cn)
        root_desc = str(conn.entries[0].description) if conn.entries[0].description else ''

        visited = set()
        tree = _build_member_tree(conn, cfg, root_dn, root_cn, visited)
        tree['description'] = root_desc

        # Count effective members
        effective_users = set()
        _count_effective_users(tree, effective_users)
        tree['effective_user_count'] = len(effective_users)

        return True, tree
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _build_member_tree(conn, cfg, group_dn, group_cn, visited):
    """Recursively build member tree for a group."""
    node = {
        'cn': group_cn,
        'dn': group_dn,
        'type': 'group',
        'children': [],
        'circular': False,
        'direct_users': 0,
        'direct_groups': 0,
    }

    if group_dn.lower() in visited:
        node['circular'] = True
        return node

    visited.add(group_dn.lower())

    # Get direct members
    ldap_filter = f'(memberOf={group_dn})'
    conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                 attributes=['cn', 'sAMAccountName', 'objectClass',
                             'distinguishedName', 'member'])

    for entry in conn.entries:
        obj_classes = [str(c).lower() for c in entry.objectClass]
        member_dn = str(entry.entry_dn)
        member_cn = str(entry.cn) if entry.cn else ''

        if 'group' in obj_classes:
            node['direct_groups'] += 1
            child = _build_member_tree(conn, cfg, member_dn, member_cn, visited.copy())
            node['children'].append(child)
        else:
            node['direct_users'] += 1
            node['children'].append({
                'cn': member_cn,
                'dn': member_dn,
                'sam': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'type': 'user' if 'user' in obj_classes else 'computer' if 'computer' in obj_classes else 'other',
                'children': [],
            })

    return node


def _count_effective_users(node, users):
    """Count unique effective users across the entire tree."""
    for child in node.get('children', []):
        if child['type'] in ('user', 'computer', 'other'):
            users.add(child['dn'].lower())
        elif child['type'] == 'group' and not child.get('circular'):
            _count_effective_users(child, users)


def get_member_of_tree(group_cn):
    """Build a tree showing what groups this group is a member of (upward nesting)."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()

        ldap_filter = f'(&(objectClass=group)(cn={escape_rdn(group_cn)}))'
        conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'memberOf'])
        if not conn.entries:
            return False, 'Group not found'

        root_dn = str(conn.entries[0].entry_dn)
        root_cn = str(conn.entries[0].cn)

        visited = set()
        tree = _build_parent_tree(conn, cfg, root_dn, root_cn, visited)
        return True, tree
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _build_parent_tree(conn, cfg, group_dn, group_cn, visited):
    """Recursively build parent group tree."""
    node = {
        'cn': group_cn,
        'dn': group_dn,
        'type': 'group',
        'parents': [],
        'circular': False,
    }

    if group_dn.lower() in visited:
        node['circular'] = True
        return node

    visited.add(group_dn.lower())

    # Find groups that this group is a member of
    ldap_filter = f'(member={group_dn})'
    conn.search(cfg['BASE_DN'], ldap_filter, search_scope=SUBTREE,
                 attributes=['cn', 'distinguishedName', 'objectClass'])

    for entry in conn.entries:
        obj_classes = [str(c).lower() for c in entry.objectClass]
        if 'group' in obj_classes:
            parent_dn = str(entry.entry_dn)
            parent_cn = str(entry.cn) if entry.cn else ''
            parent = _build_parent_tree(conn, cfg, parent_dn, parent_cn, visited.copy())
            node['parents'].append(parent)

    return node


def find_circular_nesting():
    """Scan all groups for circular nesting references."""
    cfg = current_app.config
    conn = None
    try:
        conn = get_connection()
        conn.search(cfg['BASE_DN'], '(objectClass=group)', search_scope=SUBTREE,
                     attributes=['cn', 'distinguishedName', 'member'],
                     paged_size=1000)

        # Build adjacency map
        group_members = {}
        group_names = {}
        for entry in conn.entries:
            dn = str(entry.entry_dn).lower()
            group_names[dn] = str(entry.cn) if entry.cn else ''
            members = [str(m).lower() for m in entry.member] if entry.member else []
            group_members[dn] = [m for m in members if m in group_names or m in group_members]

        # Re-scan to get all group DNs for membership check
        all_group_dns = set(group_names.keys())
        for dn in group_members:
            group_members[dn] = [m for m in group_members[dn] if m in all_group_dns]

        # Detect cycles using DFS
        circular = []
        for start_dn in all_group_dns:
            path = []
            visited = set()
            _find_cycles(start_dn, group_members, visited, path, circular, group_names)

        # Deduplicate
        seen = set()
        unique_circular = []
        for cycle in circular:
            key = tuple(sorted(cycle))
            if key not in seen:
                seen.add(key)
                unique_circular.append(cycle)

        return True, unique_circular
    except Exception as e:
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def _find_cycles(node, adj, visited, path, cycles, names):
    """DFS cycle detection."""
    if node in visited:
        # Found a cycle - extract it
        if node in path:
            cycle_start = path.index(node)
            cycle = [names.get(n, n) for n in path[cycle_start:]]
            cycles.append(cycle)
        return

    visited.add(node)
    path.append(node)

    for neighbor in adj.get(node, []):
        _find_cycles(neighbor, adj, visited, path, cycles, names)

    path.pop()
