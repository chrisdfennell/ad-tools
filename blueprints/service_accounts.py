from flask import Blueprint, render_template, flash

from services.ad_service_accounts import get_service_accounts

svc_bp = Blueprint('service_accounts', __name__, url_prefix='/service-accounts')


@svc_bp.route('/')
def index():
    success, data = get_service_accounts()
    if not success:
        flash(f'Failed to load service accounts: {data}', 'danger')
        data = []
    return render_template('service_accounts/index.html', accounts=data)
