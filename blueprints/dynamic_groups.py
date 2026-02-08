from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.dynamic_groups import (
    list_dynamic_groups, get_dynamic_group, create_dynamic_group,
    update_dynamic_group, delete_dynamic_group, evaluate_dynamic_group,
)
from services.rbac import require_permission
from services.audit import log_action

dyn_groups_bp = Blueprint('dynamic_groups', __name__, url_prefix='/dynamic-groups')


@dyn_groups_bp.route('/')
@require_permission('dynamic_groups.view')
def index():
    groups = list_dynamic_groups()
    return render_template('dynamic_groups/index.html', groups=groups)


@dyn_groups_bp.route('/create', methods=['GET', 'POST'])
@require_permission('dynamic_groups.manage')
def create():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        ldap_filter = request.form.get('ldap_filter', '').strip()

        if not name or not ldap_filter:
            flash('Name and LDAP filter are required.', 'warning')
        else:
            ok, msg = create_dynamic_group(name, description, ldap_filter)
            flash(msg, 'success' if ok else 'danger')
            log_action('create_dynamic_group', name, ldap_filter, 'success' if ok else 'failure')
            if ok:
                return redirect(url_for('dynamic_groups.index'))

    return render_template('dynamic_groups/form.html', group=None)


@dyn_groups_bp.route('/<int:group_id>/edit', methods=['GET', 'POST'])
@require_permission('dynamic_groups.manage')
def edit(group_id):
    group = get_dynamic_group(group_id)
    if not group:
        flash('Dynamic group not found.', 'danger')
        return redirect(url_for('dynamic_groups.index'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        ldap_filter = request.form.get('ldap_filter', '').strip()

        ok, msg = update_dynamic_group(group_id, name, description, ldap_filter)
        flash(msg, 'success' if ok else 'danger')
        if ok:
            return redirect(url_for('dynamic_groups.evaluate', group_id=group_id))

    return render_template('dynamic_groups/form.html', group=group)


@dyn_groups_bp.route('/<int:group_id>/delete', methods=['POST'])
@require_permission('dynamic_groups.manage')
def delete(group_id):
    group = get_dynamic_group(group_id)
    name = group['name'] if group else str(group_id)
    ok, msg = delete_dynamic_group(group_id)
    flash(msg, 'success' if ok else 'danger')
    log_action('delete_dynamic_group', name, '', 'success' if ok else 'failure')
    return redirect(url_for('dynamic_groups.index'))


@dyn_groups_bp.route('/<int:group_id>/evaluate')
@require_permission('dynamic_groups.view')
def evaluate(group_id):
    group = get_dynamic_group(group_id)
    if not group:
        flash('Dynamic group not found.', 'danger')
        return redirect(url_for('dynamic_groups.index'))

    ok, members = evaluate_dynamic_group(group['ldap_filter'])
    if not ok:
        flash(f'Failed to evaluate filter: {members}', 'danger')
        members = []

    return render_template('dynamic_groups/evaluate.html', group=group, members=members)
