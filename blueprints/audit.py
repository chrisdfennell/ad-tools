from flask import Blueprint, render_template, request

from services.audit import get_audit_log

audit_bp = Blueprint('audit', __name__, url_prefix='/audit')


@audit_bp.route('/')
def log():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    per_page = 50
    offset = (page - 1) * per_page

    entries, total = get_audit_log(
        limit=per_page, offset=offset,
        action_filter=action_filter, user_filter=user_filter
    )
    total_pages = (total + per_page - 1) // per_page
    return render_template('audit/log.html',
                           entries=entries, page=page, total_pages=total_pages,
                           total=total, action_filter=action_filter, user_filter=user_filter)
