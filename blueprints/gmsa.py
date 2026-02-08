from flask import Blueprint, render_template, flash, redirect, url_for

from services.ad_gmsa import get_all_gmsas, get_gmsa_detail

gmsa_bp = Blueprint('gmsa', __name__, url_prefix='/gmsa')


@gmsa_bp.route('/')
def index():
    success, gmsas = get_all_gmsas()
    if not success:
        flash(f'Failed to load gMSAs: {gmsas}', 'danger')
        gmsas = []
    return render_template('gmsa/index.html', gmsas=gmsas)


@gmsa_bp.route('/<sam>/detail')
def detail(sam):
    success, gmsa = get_gmsa_detail(sam)
    if not success:
        flash(f'gMSA not found: {gmsa}', 'danger')
        return redirect(url_for('gmsa.index'))
    return render_template('gmsa/detail.html', gmsa=gmsa)
