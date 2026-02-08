from flask import Blueprint, render_template, request, flash

from services.ad_acl import get_object_acl
from services.rbac import require_permission

acl_bp = Blueprint('acl', __name__, url_prefix='/acl')


@acl_bp.route('/')
@require_permission('acl.view')
def index():
    dn = request.args.get('dn', '')
    result = None
    if dn:
        success, data = get_object_acl(dn)
        if not success:
            flash(f'Failed to read ACL: {data}', 'danger')
        else:
            result = data
    return render_template('acl/index.html', dn=dn, result=result)
