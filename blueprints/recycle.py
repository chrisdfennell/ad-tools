from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_recycle import get_deleted_objects, restore_deleted_object
from services.audit import log_action

recycle_bp = Blueprint('recycle', __name__, url_prefix='/recycle')


@recycle_bp.route('/')
def list_deleted():
    success, data = get_deleted_objects()
    if not success:
        flash(f'Failed to load recycle bin: {data}', 'danger')
        data = []
    return render_template('recycle/list.html', objects=data)


@recycle_bp.route('/restore', methods=['POST'])
def restore():
    deleted_dn = request.form.get('deleted_dn', '')
    target_ou = request.form.get('target_ou', '') or None
    if not deleted_dn:
        flash('No object specified.', 'danger')
        return redirect(url_for('recycle.list_deleted'))

    success, msg = restore_deleted_object(deleted_dn, target_ou)
    flash(msg, 'success' if success else 'danger')
    log_action('restore_object', deleted_dn, msg, 'success' if success else 'failure')
    return redirect(url_for('recycle.list_deleted'))
