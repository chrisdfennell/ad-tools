from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_gpo import (
    get_all_gpos, get_gpo_detail, link_gpo, unlink_gpo,
    set_gpo_link_enforced, toggle_gpo_link, get_linkable_containers,
)
from services.rbac import require_permission
from services.audit import log_action

gpo_bp = Blueprint('gpo', __name__, url_prefix='/gpo')


@gpo_bp.route('/')
def list_gpos():
    success, data = get_all_gpos()
    if not success:
        flash(f'Failed to load GPOs: {data}', 'danger')
        data = []
    return render_template('gpo/list.html', gpos=data)


@gpo_bp.route('/detail')
def detail():
    dn = request.args.get('dn', '')
    if not dn:
        flash('No GPO DN specified.', 'warning')
        return redirect(url_for('gpo.list_gpos'))
    success, data = get_gpo_detail(dn)
    if not success:
        flash(f'Failed to load GPO: {data}', 'danger')
        return redirect(url_for('gpo.list_gpos'))

    # Get containers for linking
    cont_success, containers = get_linkable_containers()
    if not cont_success:
        containers = []

    return render_template('gpo/detail.html', gpo=data, containers=containers)


@gpo_bp.route('/link', methods=['POST'])
@require_permission('gpo.manage_links')
def link():
    gpo_dn = request.form.get('gpo_dn', '')
    container_dn = request.form.get('container_dn', '')
    enforced = 'enforced' in request.form

    if not gpo_dn or not container_dn:
        flash('GPO DN and container DN are required.', 'danger')
        return redirect(url_for('gpo.list_gpos'))

    success, msg = link_gpo(gpo_dn, container_dn, enforced)
    flash(msg, 'success' if success else 'danger')
    log_action('link_gpo', gpo_dn, f'Container: {container_dn}. {msg}',
               'success' if success else 'failure')
    return redirect(url_for('gpo.detail', dn=gpo_dn))


@gpo_bp.route('/unlink', methods=['POST'])
@require_permission('gpo.manage_links')
def unlink():
    gpo_dn = request.form.get('gpo_dn', '')
    container_dn = request.form.get('container_dn', '')

    if not gpo_dn or not container_dn:
        flash('GPO DN and container DN are required.', 'danger')
        return redirect(url_for('gpo.list_gpos'))

    success, msg = unlink_gpo(gpo_dn, container_dn)
    flash(msg, 'success' if success else 'danger')
    log_action('unlink_gpo', gpo_dn, f'Container: {container_dn}. {msg}',
               'success' if success else 'failure')
    return redirect(url_for('gpo.detail', dn=gpo_dn))


@gpo_bp.route('/toggle-link', methods=['POST'])
@require_permission('gpo.manage_links')
def toggle_link():
    gpo_dn = request.form.get('gpo_dn', '')
    container_dn = request.form.get('container_dn', '')

    if not gpo_dn or not container_dn:
        flash('GPO DN and container DN are required.', 'danger')
        return redirect(url_for('gpo.list_gpos'))

    success, msg = toggle_gpo_link(gpo_dn, container_dn)
    flash(msg, 'success' if success else 'danger')
    log_action('toggle_gpo_link', gpo_dn, f'Container: {container_dn}. {msg}',
               'success' if success else 'failure')
    return redirect(url_for('gpo.detail', dn=gpo_dn))


@gpo_bp.route('/set-enforced', methods=['POST'])
@require_permission('gpo.manage_links')
def set_enforced():
    gpo_dn = request.form.get('gpo_dn', '')
    container_dn = request.form.get('container_dn', '')
    enforced = request.form.get('enforced', '1') == '1'

    if not gpo_dn or not container_dn:
        flash('GPO DN and container DN are required.', 'danger')
        return redirect(url_for('gpo.list_gpos'))

    success, msg = set_gpo_link_enforced(gpo_dn, container_dn, enforced)
    flash(msg, 'success' if success else 'danger')
    log_action('set_gpo_enforced', gpo_dn, f'Container: {container_dn}. {msg}',
               'success' if success else 'failure')
    return redirect(url_for('gpo.detail', dn=gpo_dn))
