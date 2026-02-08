from flask import Blueprint, render_template, request, flash

from services.ad_lockout import get_all_locked_users, get_lockout_details, get_lockout_policy
from services.rbac import require_permission

lockout_bp = Blueprint('lockout', __name__, url_prefix='/lockout')


@lockout_bp.route('/')
@require_permission('lockout.view')
def index():
    success, locked = get_all_locked_users()
    if not success:
        flash(f'Failed to query locked users: {locked}', 'danger')
        locked = []

    pol_ok, policy = get_lockout_policy()
    if not pol_ok:
        policy = {'threshold': 0, 'duration_minutes': 0, 'observation_minutes': 0}

    return render_template('lockout/index.html', locked=locked, policy=policy)


@lockout_bp.route('/detail/<sam>')
@require_permission('lockout.view')
def detail(sam):
    success, user = get_lockout_details(sam)
    if not success:
        flash(f'Failed to get lockout details: {user}', 'danger')
        return render_template('lockout/detail.html', user=None)

    pol_ok, policy = get_lockout_policy()
    if not pol_ok:
        policy = {'threshold': 0, 'duration_minutes': 0, 'observation_minutes': 0}

    return render_template('lockout/detail.html', user=user, policy=policy)
