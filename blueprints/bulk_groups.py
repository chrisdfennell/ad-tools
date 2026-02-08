from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify

from services.ad_groups import search_groups, get_group, add_member, remove_member
from services.ad_users import search_users
from services.audit import log_action

bulk_groups_bp = Blueprint('bulk_groups', __name__, url_prefix='/bulk-groups')


@bulk_groups_bp.route('/')
def index():
    return render_template('bulk_groups/index.html')


@bulk_groups_bp.route('/add', methods=['POST'])
def bulk_add():
    group_dn = request.form.get('group_dn', '')
    member_dns = request.form.getlist('member_dns')
    if not group_dn or not member_dns:
        flash('Group and at least one member are required.', 'danger')
        return redirect(url_for('bulk_groups.index'))

    success_count = 0
    fail_count = 0
    for member_dn in member_dns:
        s, msg = add_member(group_dn, member_dn)
        if s:
            success_count += 1
        else:
            fail_count += 1
    log_action('bulk_add_to_group', group_dn,
               f'Added {success_count}, failed {fail_count}',
               'success' if fail_count == 0 else 'partial')
    flash(f'Bulk add: {success_count} added, {fail_count} failed.', 'success' if fail_count == 0 else 'warning')
    return redirect(url_for('bulk_groups.index'))


@bulk_groups_bp.route('/remove', methods=['POST'])
def bulk_remove():
    group_dn = request.form.get('group_dn', '')
    member_dns = request.form.getlist('member_dns')
    if not group_dn or not member_dns:
        flash('Group and at least one member are required.', 'danger')
        return redirect(url_for('bulk_groups.index'))

    success_count = 0
    fail_count = 0
    for member_dn in member_dns:
        s, msg = remove_member(group_dn, member_dn)
        if s:
            success_count += 1
        else:
            fail_count += 1
    log_action('bulk_remove_from_group', group_dn,
               f'Removed {success_count}, failed {fail_count}',
               'success' if fail_count == 0 else 'partial')
    flash(f'Bulk remove: {success_count} removed, {fail_count} failed.', 'success' if fail_count == 0 else 'warning')
    return redirect(url_for('bulk_groups.index'))


@bulk_groups_bp.route('/api/search-groups')
def api_search_groups():
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    success, groups = search_groups(q)
    if not success:
        return jsonify([])
    return jsonify([{'cn': g['cn'], 'dn': g['dn'], 'type_label': g['group_type_label']} for g in groups[:20]])


@bulk_groups_bp.route('/api/search-users')
def api_search_users():
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    success, users = search_users(q)
    if not success:
        return jsonify([])
    return jsonify([{'dn': u['dn'], 'sam': u['sam'], 'display_name': u['display_name']} for u in users[:30]])
