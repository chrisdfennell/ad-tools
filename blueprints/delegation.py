from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_delegation import get_delegations_on_ous, get_object_acl

delegation_bp = Blueprint('delegation', __name__, url_prefix='/delegation')


@delegation_bp.route('/')
def index():
    success, data = get_delegations_on_ous()
    if not success:
        flash(f'Failed to load delegations: {data}', 'danger')
        data = []
    return render_template('delegation/index.html', delegations=data)


@delegation_bp.route('/acl')
def acl():
    dn = request.args.get('dn', '')
    if not dn:
        flash('No DN specified.', 'warning')
        return redirect(url_for('delegation.index'))
    success, data = get_object_acl(dn)
    if not success:
        flash(f'Failed to read ACL: {data}', 'danger')
        return redirect(url_for('delegation.index'))
    return render_template('delegation/acl.html', obj=data)
