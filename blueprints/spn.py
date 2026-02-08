from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_spn import search_spns, get_spns_for_object, add_spn, remove_spn
from services.audit import log_action

spn_bp = Blueprint('spn', __name__, url_prefix='/spn')


@spn_bp.route('/')
def index():
    query = request.args.get('q', '*')
    success, results = search_spns(query)
    if not success:
        flash(f'Search failed: {results}', 'danger')
        results = []
    return render_template('spn/index.html', results=results, query=query if query != '*' else '')


@spn_bp.route('/<sam>/detail')
def detail(sam):
    success, obj = get_spns_for_object(sam)
    if not success:
        flash(f'Object not found: {obj}', 'danger')
        return redirect(url_for('spn.index'))
    return render_template('spn/detail.html', obj=obj)


@spn_bp.route('/<sam>/add', methods=['POST'])
def add(sam):
    success, obj = get_spns_for_object(sam)
    if not success:
        flash(f'Object not found: {obj}', 'danger')
        return redirect(url_for('spn.index'))
    spn_value = request.form.get('spn', '').strip()
    if not spn_value:
        flash('SPN value is required.', 'danger')
        return redirect(url_for('spn.detail', sam=sam))
    add_success, msg = add_spn(obj['dn'], spn_value)
    flash(msg, 'success' if add_success else 'danger')
    log_action('add_spn', sam, f'SPN: {spn_value}. {msg}', 'success' if add_success else 'failure')
    return redirect(url_for('spn.detail', sam=sam))


@spn_bp.route('/<sam>/remove', methods=['POST'])
def remove(sam):
    success, obj = get_spns_for_object(sam)
    if not success:
        flash(f'Object not found: {obj}', 'danger')
        return redirect(url_for('spn.index'))
    spn_value = request.form.get('spn', '').strip()
    if not spn_value:
        flash('SPN value is required.', 'danger')
        return redirect(url_for('spn.detail', sam=sam))
    rm_success, msg = remove_spn(obj['dn'], spn_value)
    flash(msg, 'success' if rm_success else 'danger')
    log_action('remove_spn', sam, f'SPN: {spn_value}. {msg}', 'success' if rm_success else 'failure')
    return redirect(url_for('spn.detail', sam=sam))
