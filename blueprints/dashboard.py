from flask import Blueprint, render_template, flash

from services.ad_dashboard import get_dashboard_stats

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def index():
    success, data = get_dashboard_stats()
    if not success:
        flash(f'Failed to load dashboard stats: {data}', 'danger')
        data = {
            'total_users': 0, 'active_users': 0, 'disabled_users': 0,
            'locked_users': 0, 'locked_user_list': [], 'total_groups': 0,
            'total_computers': 0, 'recent_users': [], 'recent_modified': [],
        }
    return render_template('dashboard.html', stats=data)
