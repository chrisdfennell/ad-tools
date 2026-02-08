from flask import Blueprint, render_template, flash

from services.ad_sites import get_sites, get_site_links
from services.rbac import require_permission

sites_bp = Blueprint('sites', __name__, url_prefix='/sites')


@sites_bp.route('/')
@require_permission('sites.view')
def index():
    ok_sites, sites = get_sites()
    if not ok_sites:
        flash(f'Failed to load sites: {sites}', 'danger')
        sites = []

    ok_links, links = get_site_links()
    if not ok_links:
        flash(f'Failed to load site links: {links}', 'danger')
        links = []

    total_subnets = sum(len(s['subnets']) for s in sites)
    total_servers = sum(len(s['servers']) for s in sites)

    return render_template('sites/index.html',
                           sites=sites, links=links,
                           total_subnets=total_subnets,
                           total_servers=total_servers)
