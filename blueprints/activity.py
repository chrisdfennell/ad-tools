from flask import Blueprint, render_template, request, flash, jsonify

from services.ad_activity import (
    get_locked_accounts, get_recent_password_changes,
    get_recently_created_accounts, get_recently_modified_accounts,
)
from services.ad_users import unlock_user
from services.audit import log_action

activity_bp = Blueprint('activity', __name__, url_prefix='/activity')


@activity_bp.route('/')
def index():
    hours = request.args.get('hours', 24, type=int)

    lock_ok, locked = get_locked_accounts()
    if not lock_ok:
        locked = []

    pwd_ok, pwd_changes = get_recent_password_changes(hours)
    if not pwd_ok:
        pwd_changes = []

    created_ok, created = get_recently_created_accounts(hours * 3)
    if not created_ok:
        created = []

    modified_ok, modified = get_recently_modified_accounts(hours)
    if not modified_ok:
        modified = []

    return render_template('activity/index.html',
                           locked=locked,
                           pwd_changes=pwd_changes,
                           created=created,
                           modified=modified,
                           hours=hours)


@activity_bp.route('/api/locked')
def api_locked():
    """API endpoint for AJAX refresh of locked accounts."""
    success, locked = get_locked_accounts()
    if not success:
        return jsonify([])
    return jsonify(locked)


@activity_bp.route('/api/unlock', methods=['POST'])
def api_unlock():
    """Quick-unlock a locked account via AJAX."""
    dn = request.form.get('dn', '')
    if not dn:
        return jsonify({'success': False, 'message': 'No DN provided'}), 400
    success, msg = unlock_user(dn)
    log_action('quick_unlock', dn, msg, 'success' if success else 'failure')
    return jsonify({'success': success, 'message': msg})
