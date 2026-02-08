from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify

from services.ad_attributes import get_object_attributes, modify_object_attribute, search_objects
from services.audit import log_action

attributes_bp = Blueprint('attributes', __name__, url_prefix='/attributes')


@attributes_bp.route('/')
def index():
    return render_template('attributes/index.html')


@attributes_bp.route('/edit')
def edit():
    dn = request.args.get('dn', '')
    if not dn:
        flash('No DN specified.', 'warning')
        return redirect(url_for('attributes.index'))
    success, data = get_object_attributes(dn)
    if not success:
        flash(f'Failed to load object: {data}', 'danger')
        return redirect(url_for('attributes.index'))
    return render_template('attributes/edit.html', obj=data)


@attributes_bp.route('/edit', methods=['POST'])
def edit_submit():
    dn = request.form.get('dn', '')
    attribute = request.form.get('attribute', '')
    value = request.form.get('value', '')
    if not dn or not attribute:
        flash('DN and attribute name are required.', 'danger')
        return redirect(url_for('attributes.index'))
    success, msg = modify_object_attribute(dn, attribute, value)
    flash(msg, 'success' if success else 'danger')
    log_action('edit_attribute', dn, f'{attribute}={value[:100]}', 'success' if success else 'failure')
    return redirect(url_for('attributes.edit', dn=dn))


@attributes_bp.route('/api/search')
def api_search():
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    success, results = search_objects(q)
    if not success:
        return jsonify([])
    return jsonify(results[:30])
