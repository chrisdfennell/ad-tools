from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_fgpp import get_all_fgpp, get_fgpp_detail, get_domain_password_policy, get_effective_policy
from services.rbac import require_permission

fgpp_bp = Blueprint('fgpp', __name__, url_prefix='/fgpp')


@fgpp_bp.route('/')
@require_permission('fgpp.view')
def index():
    success, psos = get_all_fgpp()
    if not success:
        flash(f'Failed to load password policies: {psos}', 'danger')
        psos = []

    pol_success, domain_policy = get_domain_password_policy()
    if not pol_success:
        domain_policy = None

    return render_template('fgpp/index.html', psos=psos, domain_policy=domain_policy)


@fgpp_bp.route('/detail')
@require_permission('fgpp.view')
def detail():
    dn = request.args.get('dn', '')
    if not dn:
        flash('No PSO DN specified.', 'warning')
        return redirect(url_for('fgpp.index'))
    success, data = get_fgpp_detail(dn)
    if not success:
        flash(f'Failed to load PSO: {data}', 'danger')
        return redirect(url_for('fgpp.index'))
    return render_template('fgpp/detail.html', pso=data)


@fgpp_bp.route('/effective')
@require_permission('fgpp.view')
def effective():
    sam = request.args.get('sam', '')
    policy = None
    if sam:
        success, data = get_effective_policy(sam)
        if not success:
            flash(f'Failed to determine effective policy: {data}', 'danger')
        else:
            policy = data
    return render_template('fgpp/effective.html', sam=sam, policy=policy)
