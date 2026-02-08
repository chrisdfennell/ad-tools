from flask import Blueprint, render_template, flash

from services.ad_replication import get_replication_status
from services.rbac import require_permission

replication_bp = Blueprint('replication', __name__, url_prefix='/replication')


@replication_bp.route('/')
@require_permission('replication.view')
def index():
    success, data = get_replication_status()
    if not success:
        flash(f'Failed to get replication status: {data}', 'danger')
        data = {'connections': [], 'dcs': [], 'repl_partners_raw': []}
    return render_template('replication/index.html', data=data)
