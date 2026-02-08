from flask import Blueprint, render_template, flash

from services.ad_health import (
    get_fsmo_roles, get_functional_levels, get_domain_controllers,
    get_sites_and_subnets, get_replication_status, get_tombstone_lifetime,
)
from services.rbac import require_permission

health_bp = Blueprint('ad_health', __name__, url_prefix='/health')


@health_bp.route('/')
@require_permission('ad_health.view')
def index():
    # Gather all health data
    fsmo_ok, fsmo = get_fsmo_roles()
    if not fsmo_ok:
        flash(f'Failed to load FSMO roles: {fsmo}', 'warning')
        fsmo = {}

    levels_ok, levels = get_functional_levels()
    if not levels_ok:
        flash(f'Failed to load functional levels: {levels}', 'warning')
        levels = {}

    dc_ok, dcs = get_domain_controllers()
    if not dc_ok:
        flash(f'Failed to load domain controllers: {dcs}', 'warning')
        dcs = []

    sites_ok, sites = get_sites_and_subnets()
    if not sites_ok:
        flash(f'Failed to load sites: {sites}', 'warning')
        sites = []

    repl_ok, replication = get_replication_status()
    if not repl_ok:
        flash(f'Failed to load replication: {replication}', 'warning')
        replication = []

    tomb_ok, tombstone = get_tombstone_lifetime()
    if not tomb_ok:
        flash(f'Failed to load tombstone info: {tombstone}', 'warning')
        tombstone = {}

    return render_template('ad_health/index.html',
                           fsmo=fsmo, levels=levels, dcs=dcs,
                           sites=sites, replication=replication,
                           tombstone=tombstone)
