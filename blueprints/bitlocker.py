from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_bitlocker import search_recovery_keys, get_computer_recovery_keys
from services.rbac import require_permission
from services.audit import log_action

bitlocker_bp = Blueprint('bitlocker', __name__, url_prefix='/bitlocker')


@bitlocker_bp.route('/')
@require_permission('bitlocker.view')
def index():
    query = request.args.get('q', '')
    keys = []
    if query:
        success, data = search_recovery_keys(query)
        if not success:
            flash(f'Search failed: {data}', 'danger')
        else:
            keys = data
    return render_template('bitlocker/index.html', keys=keys, query=query)


@bitlocker_bp.route('/computer/<cn>')
@require_permission('bitlocker.view')
def computer_keys(cn):
    success, data = get_computer_recovery_keys(cn)
    if not success:
        flash(f'Failed to load recovery keys: {data}', 'danger')
        return redirect(url_for('bitlocker.index'))
    log_action('view_bitlocker_keys', cn, f'Keys found: {len(data["keys"])}')
    return render_template('bitlocker/computer.html', data=data)
