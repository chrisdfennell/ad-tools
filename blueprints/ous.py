from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify

from services.ad_ous import get_ou_tree, get_ou_contents, create_ou, delete_ou, move_object

ous_bp = Blueprint('ous', __name__, url_prefix='/ous')


@ous_bp.route('/')
def tree():
    success, tree_data = get_ou_tree()
    if not success:
        flash(f'Failed to load OU tree: {tree_data}', 'danger')
        tree_data = {'dn': '', 'name': 'Error', 'children': [], 'description': ''}
    return render_template('ous/tree.html', tree=tree_data)


@ous_bp.route('/contents')
def contents():
    """AJAX endpoint: return contents of an OU as JSON."""
    ou_dn = request.args.get('dn', '')
    if not ou_dn:
        return jsonify({'error': 'No DN provided'}), 400
    success, data = get_ou_contents(ou_dn)
    if not success:
        return jsonify({'error': data}), 500
    return jsonify(data)


@ous_bp.route('/create', methods=['POST'])
def create():
    name = request.form['name']
    parent_dn = request.form['parent_dn']
    success, msg = create_ou(name, parent_dn)
    flash(msg, 'success' if success else 'danger')
    return redirect(url_for('ous.tree'))


@ous_bp.route('/delete', methods=['POST'])
def delete():
    ou_dn = request.form['ou_dn']
    success, msg = delete_ou(ou_dn)
    flash(msg, 'success' if success else 'danger')
    return redirect(url_for('ous.tree'))


@ous_bp.route('/move', methods=['POST'])
def move():
    object_dn = request.form['object_dn']
    new_ou_dn = request.form['new_ou_dn']
    success, msg = move_object(object_dn, new_ou_dn)
    flash(msg, 'success' if success else 'danger')
    return redirect(url_for('ous.tree'))
