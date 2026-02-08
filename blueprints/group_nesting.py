from flask import Blueprint, render_template, request, flash, jsonify

from services.ad_group_nesting import get_group_nesting_tree, get_member_of_tree, find_circular_nesting
from services.rbac import require_permission

nesting_bp = Blueprint('group_nesting', __name__, url_prefix='/group-nesting')


@nesting_bp.route('/')
@require_permission('group_nesting.view')
def index():
    group_cn = request.args.get('group', '')
    direction = request.args.get('direction', 'members')
    tree = None
    circular = None

    if group_cn:
        if direction == 'memberof':
            success, data = get_member_of_tree(group_cn)
        else:
            success, data = get_group_nesting_tree(group_cn)

        if not success:
            flash(f'Failed to build nesting tree: {data}', 'danger')
        else:
            tree = data

    return render_template('group_nesting/index.html',
                           group=group_cn, direction=direction, tree=tree)


@nesting_bp.route('/circular')
@require_permission('group_nesting.view')
def circular():
    success, data = find_circular_nesting()
    if not success:
        flash(f'Failed to scan for circular nesting: {data}', 'danger')
        data = []
    return render_template('group_nesting/circular.html', cycles=data)


@nesting_bp.route('/api/tree')
@require_permission('group_nesting.view')
def api_tree():
    group_cn = request.args.get('group', '')
    if not group_cn:
        return jsonify({'error': 'No group specified'}), 400
    success, data = get_group_nesting_tree(group_cn)
    if not success:
        return jsonify({'error': data}), 404
    return jsonify(data)
