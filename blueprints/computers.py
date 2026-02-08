from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify

from services.ad_computers import (
    search_computers, get_computer, get_computer_groups,
    disable_computer, enable_computer, create_computer, delete_computer,
)
from services.ad_groups import search_groups, add_member, remove_member
from services.ad_ous import get_ou_tree, move_object
from services.audit import log_action

computers_bp = Blueprint('computers', __name__, url_prefix='/computers')


def _flatten_ous(tree, depth=0):
    result = []
    if tree.get('dn') and tree.get('name'):
        result.append({'dn': tree['dn'], 'name': ('--- ' * depth) + tree['name']})
    for child in tree.get('children', []):
        result.extend(_flatten_ous(child, depth + 1))
    return result


@computers_bp.route('/')
def list_computers():
    query = request.args.get('q', '*')
    success, computers = search_computers(query)
    if not success:
        flash(f'Search failed: {computers}', 'danger')
        computers = []
    return render_template('computers/list.html', computers=computers, query=query if query != '*' else '')


@computers_bp.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        name = request.form['name'].strip()
        ou_dn = request.form['ou_dn']
        description = request.form.get('description', '')
        if not name or not ou_dn:
            flash('Computer name and OU are required.', 'danger')
        else:
            success, msg = create_computer(name, ou_dn, description)
            flash(msg, 'success' if success else 'danger')
            log_action('create_computer', name, msg, 'success' if success else 'failure')
            if success:
                return redirect(url_for('computers.list_computers'))

    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('computers/create.html', ous=ous)


@computers_bp.route('/<cn>/detail')
def detail(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    grp_success, groups = get_computer_groups(computer['dn'])
    if not grp_success:
        groups = []
    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('computers/detail.html', computer=computer, groups=groups, ous=ous)


@computers_bp.route('/<cn>/delete', methods=['POST'])
def delete(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    del_success, msg = delete_computer(computer['dn'])
    flash(msg, 'success' if del_success else 'danger')
    log_action('delete_computer', cn, msg, 'success' if del_success else 'failure')
    return redirect(url_for('computers.list_computers'))


@computers_bp.route('/<cn>/add-to-group', methods=['POST'])
def add_to_group(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    group_dn = request.form['group_dn']
    add_success, msg = add_member(group_dn, computer['dn'])
    flash(msg, 'success' if add_success else 'danger')
    log_action('add_computer_to_group', cn, f'Group: {group_dn}', 'success' if add_success else 'failure')
    return redirect(url_for('computers.detail', cn=cn))


@computers_bp.route('/<cn>/remove-from-group', methods=['POST'])
def remove_from_group(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    group_dn = request.form['group_dn']
    rm_success, msg = remove_member(group_dn, computer['dn'])
    flash(msg, 'success' if rm_success else 'danger')
    log_action('remove_computer_from_group', cn, f'Group: {group_dn}', 'success' if rm_success else 'failure')
    return redirect(url_for('computers.detail', cn=cn))


@computers_bp.route('/<cn>/move', methods=['POST'])
def move(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    target_ou = request.form.get('target_ou', '')
    if not target_ou:
        flash('No target OU specified.', 'danger')
        return redirect(url_for('computers.detail', cn=cn))
    mv_success, msg = move_object(computer['dn'], target_ou)
    flash(msg, 'success' if mv_success else 'danger')
    log_action('move_computer', cn, f'To: {target_ou}. {msg}', 'success' if mv_success else 'failure')
    return redirect(url_for('computers.detail', cn=cn))


@computers_bp.route('/bulk-action', methods=['POST'])
def bulk_action():
    selected_dns = request.form.getlist('selected_dns')
    action = request.form.get('action', '')
    if not selected_dns:
        flash('No computers selected.', 'warning')
        return redirect(url_for('computers.list_computers'))
    results = []
    for dn in selected_dns:
        if action == 'disable':
            s, m = disable_computer(dn)
            results.append((dn, s, m))
            log_action('bulk_disable_computer', dn, m, 'success' if s else 'failure')
        elif action == 'enable':
            s, m = enable_computer(dn)
            results.append((dn, s, m))
            log_action('bulk_enable_computer', dn, m, 'success' if s else 'failure')
        elif action == 'delete':
            s, m = delete_computer(dn)
            results.append((dn, s, m))
            log_action('bulk_delete_computer', dn, m, 'success' if s else 'failure')
    success_count = sum(1 for _, s, _ in results if s)
    fail_count = len(results) - success_count
    flash(f'Bulk {action}: {success_count} succeeded, {fail_count} failed.', 'success' if fail_count == 0 else 'warning')
    return redirect(url_for('computers.list_computers'))


@computers_bp.route('/api/search-groups')
def search_groups_api():
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    success, groups = search_groups(q)
    if not success:
        return jsonify([])
    return jsonify([{'cn': g['cn'], 'dn': g['dn'], 'type_label': g['group_type_label']} for g in groups[:20]])


@computers_bp.route('/<cn>/disable', methods=['POST'])
def disable(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    dis_success, msg = disable_computer(computer['dn'])
    flash(msg, 'success' if dis_success else 'danger')
    log_action('disable_computer', cn, msg, 'success' if dis_success else 'failure')
    return redirect(url_for('computers.detail', cn=cn))


@computers_bp.route('/<cn>/enable', methods=['POST'])
def enable(cn):
    success, computer = get_computer(cn)
    if not success:
        flash(f'Computer not found: {computer}', 'danger')
        return redirect(url_for('computers.list_computers'))
    en_success, msg = enable_computer(computer['dn'])
    flash(msg, 'success' if en_success else 'danger')
    log_action('enable_computer', cn, msg, 'success' if en_success else 'failure')
    return redirect(url_for('computers.detail', cn=cn))
