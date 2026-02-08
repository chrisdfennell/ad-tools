from flask import Blueprint, render_template, request, jsonify

from services.ad_orgchart import get_org_tree, get_direct_reports

orgchart_bp = Blueprint('orgchart', __name__, url_prefix='/orgchart')


@orgchart_bp.route('/')
def index():
    success, data = get_org_tree()
    if not success:
        data = []
    return render_template('orgchart/index.html', tree=data)


@orgchart_bp.route('/api/reports/<sam>')
def api_reports(sam):
    success, data = get_direct_reports(sam)
    if not success:
        return jsonify({'error': str(data)}), 404
    return jsonify(data)
