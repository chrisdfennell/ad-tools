from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify

from services.ad_groups import (
    search_groups, get_group, create_group, delete_group,
    add_member, remove_member, get_group_members, modify_group,
    GROUP_TYPES, GROUP_TYPE_LABELS,
)
from services.ad_users import search_users
from services.ad_ous import get_ou_tree
from services.audit import log_action

groups_bp = Blueprint('groups', __name__, url_prefix='/groups')


@groups_bp.route('/')
def list_groups():
    query = request.args.get('q', '*')
    success, groups = search_groups(query)
    if not success:
        flash(f'Search failed: {groups}', 'danger')
        groups = []
    return render_template('groups/list.html', groups=groups, query=query if query != '*' else '')


@groups_bp.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        name = request.form['name']
        ou_dn = request.form['ou_dn']
        group_type = request.form.get('group_type', 'global_security')
        description = request.form.get('description', '')
        success, msg = create_group(name, ou_dn, group_type, description)
        flash(msg, 'success' if success else 'danger')
        if success:
            return redirect(url_for('groups.list_groups'))

    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('groups/create.html', ous=ous, group_types=GROUP_TYPES)


@groups_bp.route('/<cn>/detail')
def detail(cn):
    success, group = get_group(cn)
    if not success:
        flash(f'Group not found: {group}', 'danger')
        return redirect(url_for('groups.list_groups'))
    mem_success, members = get_group_members(group['dn'])
    if not mem_success:
        members = []
    return render_template('groups/detail.html', group=group, members=members)


@groups_bp.route('/<cn>/edit', methods=['GET', 'POST'])
def edit(cn):
    success, group = get_group(cn)
    if not success:
        flash(f'Group not found: {group}', 'danger')
        return redirect(url_for('groups.list_groups'))

    if request.method == 'POST':
        changes = {
            'description': request.form.get('description', ''),
            'managedBy': request.form.get('managedBy', ''),
        }
        mod_success, msg = modify_group(group['dn'], changes)
        flash(msg, 'success' if mod_success else 'danger')
        log_action('modify_group', cn, msg, 'success' if mod_success else 'failure')
        if mod_success:
            return redirect(url_for('groups.detail', cn=cn))

    return render_template('groups/edit.html', group=group, group_type_labels=GROUP_TYPE_LABELS)


@groups_bp.route('/<cn>/add-member', methods=['POST'])
def add_member_route(cn):
    success, group = get_group(cn)
    if not success:
        flash(f'Group not found: {group}', 'danger')
        return redirect(url_for('groups.list_groups'))
    member_dn = request.form['member_dn']
    add_success, msg = add_member(group['dn'], member_dn)
    flash(msg, 'success' if add_success else 'danger')
    return redirect(url_for('groups.detail', cn=cn))


@groups_bp.route('/<cn>/remove-member', methods=['POST'])
def remove_member_route(cn):
    success, group = get_group(cn)
    if not success:
        flash(f'Group not found: {group}', 'danger')
        return redirect(url_for('groups.list_groups'))
    member_dn = request.form['member_dn']
    rm_success, msg = remove_member(group['dn'], member_dn)
    flash(msg, 'success' if rm_success else 'danger')
    return redirect(url_for('groups.detail', cn=cn))


@groups_bp.route('/<cn>/delete', methods=['POST'])
def delete(cn):
    success, group = get_group(cn)
    if not success:
        flash(f'Group not found: {group}', 'danger')
        return redirect(url_for('groups.list_groups'))
    del_success, msg = delete_group(group['dn'])
    flash(msg, 'success' if del_success else 'danger')
    return redirect(url_for('groups.list_groups'))


@groups_bp.route('/search-users')
def search_users_api():
    """AJAX endpoint for member search."""
    query = request.args.get('q', '')
    if len(query) < 2:
        return jsonify([])
    success, users = search_users(query)
    if not success:
        return jsonify([])
    return jsonify([{'dn': u['dn'], 'sam': u['sam'], 'display_name': u['display_name']} for u in users[:20]])


def _flatten_ous(tree, depth=0):
    result = []
    if tree.get('dn') and tree.get('name'):
        result.append({'dn': tree['dn'], 'name': ('--- ' * depth) + tree['name']})
    for child in tree.get('children', []):
        result.extend(_flatten_ous(child, depth + 1))
    return result
