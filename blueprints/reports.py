import csv
import io

from flask import Blueprint, render_template, request, flash, Response

from services.ad_reports import get_password_expiry_report, get_stale_objects, get_privileged_accounts
from services.audit import log_action

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/password-expiry')
def password_expiry():
    days = request.args.get('days', 30, type=int)
    success, data = get_password_expiry_report(days)
    if not success:
        flash(f'Failed to load report: {data}', 'danger')
        data = []
    return render_template('reports/password_expiry.html', users=data, days=days)


@reports_bp.route('/password-expiry/export')
def password_expiry_export():
    days = request.args.get('days', 30, type=int)
    success, data = get_password_expiry_report(days)
    if not success:
        flash(f'Export failed: {data}', 'danger')
        return '', 500

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['sam', 'cn', 'pwd_last_set', 'expires', 'days_remaining'])
    writer.writeheader()
    for row in data:
        writer.writerow({k: row.get(k, '') for k in writer.fieldnames})
    log_action('export_report', 'password_expiry', f'{len(data)} rows', 'success')
    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=password_expiry_{days}d.csv'},
    )


@reports_bp.route('/stale-objects')
def stale_objects():
    days = request.args.get('days', 90, type=int)
    obj_type = request.args.get('type', 'users')
    if obj_type not in ('users', 'computers'):
        obj_type = 'users'
    success, data = get_stale_objects(days, obj_type)
    if not success:
        flash(f'Failed to load report: {data}', 'danger')
        data = []
    return render_template('reports/stale_objects.html', objects=data, days=days, obj_type=obj_type)


@reports_bp.route('/stale-objects/export')
def stale_objects_export():
    days = request.args.get('days', 90, type=int)
    obj_type = request.args.get('type', 'users')
    if obj_type not in ('users', 'computers'):
        obj_type = 'users'
    success, data = get_stale_objects(days, obj_type)
    if not success:
        flash(f'Export failed: {data}', 'danger')
        return '', 500

    fields = ['sam', 'cn', 'last_logon', 'when_created', 'status']
    if obj_type == 'computers':
        fields.append('os')

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for row in data:
        writer.writerow({k: row.get(k, '') for k in fields})
    log_action('export_report', f'stale_{obj_type}', f'{len(data)} rows', 'success')
    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=stale_{obj_type}_{days}d.csv'},
    )


@reports_bp.route('/privileged')
def privileged():
    success, data = get_privileged_accounts()
    if not success:
        flash(f'Failed to load report: {data}', 'danger')
        data = []
    return render_template('reports/privileged.html', accounts=data)


@reports_bp.route('/privileged/export')
def privileged_export():
    success, data = get_privileged_accounts()
    if not success:
        flash(f'Export failed: {data}', 'danger')
        return '', 500

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['sam', 'cn', 'display_name', 'status', 'source'])
    writer.writeheader()
    for row in data:
        writer.writerow({k: row.get(k, '') for k in writer.fieldnames})
    log_action('export_report', 'privileged', f'{len(data)} rows', 'success')
    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=privileged_accounts.csv'},
    )
