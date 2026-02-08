from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_dns import get_dns_zones, get_dns_records

dns_bp = Blueprint('dns', __name__, url_prefix='/dns')


@dns_bp.route('/')
def zones():
    success, data = get_dns_zones()
    if not success:
        flash(f'Failed to load DNS zones: {data}', 'danger')
        data = []
    return render_template('dns/zones.html', zones=data)


@dns_bp.route('/records')
def records():
    zone_dn = request.args.get('zone_dn', '')
    zone_name = request.args.get('zone_name', '')
    if not zone_dn:
        flash('No zone specified.', 'warning')
        return redirect(url_for('dns.zones'))
    success, data = get_dns_records(zone_dn)
    if not success:
        flash(f'Failed to load records: {data}', 'danger')
        data = []
    return render_template('dns/records.html', records=data, zone_name=zone_name, zone_dn=zone_dn)
