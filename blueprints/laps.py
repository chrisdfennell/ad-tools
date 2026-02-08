from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify

from services.ad_laps import search_laps, get_laps_password
from services.rbac import require_permission
from services.audit import log_action

laps_bp = Blueprint('laps', __name__, url_prefix='/laps')


@laps_bp.route('/')
@require_permission('laps.view')
def index():
    query = request.args.get('q', '')
    computers = []
    if query:
        success, data = search_laps(query)
        if not success:
            flash(f'Search failed: {data}', 'danger')
        else:
            computers = data
    return render_template('laps/index.html', computers=computers, query=query)


@laps_bp.route('/view/<cn>')
@require_permission('laps.view')
def view_password(cn):
    success, data = get_laps_password(cn)
    if not success:
        flash(f'Failed to retrieve LAPS password: {data}', 'danger')
        return redirect(url_for('laps.index'))
    log_action('view_laps_password', cn, f'Type: {data.get("laps_type", "unknown")}')
    return render_template('laps/view.html', computer=data)


@laps_bp.route('/api/search')
@require_permission('laps.view')
def api_search():
    query = request.args.get('q', '')
    if len(query) < 2:
        return jsonify([])
    success, data = search_laps(query)
    if not success:
        return jsonify([])
    return jsonify([{
        'cn': c['cn'], 'os': c['os'], 'laps_type': c['laps_type'],
        'status': c['status'],
    } for c in data[:20]])
