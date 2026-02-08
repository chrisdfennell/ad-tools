from flask import Blueprint, render_template, request, flash, redirect, url_for, session

from services.scheduled_reports import (
    get_all_schedules, create_schedule, delete_schedule, toggle_schedule,
    get_all_alerts, create_alert, delete_alert, toggle_alert,
    send_test_email, REPORT_TYPES, ALERT_TYPES, SCHEDULE_OPTIONS,
)
from services.rbac import require_permission
from services.audit import log_action

schedules_bp = Blueprint('scheduled_reports', __name__, url_prefix='/schedules')


@schedules_bp.route('/')
@require_permission('scheduled_reports.view')
def index():
    schedules = get_all_schedules()
    alerts = get_all_alerts()
    return render_template('scheduled_reports/index.html',
                           schedules=schedules, alerts=alerts,
                           report_types=REPORT_TYPES, alert_types=ALERT_TYPES,
                           schedule_options=SCHEDULE_OPTIONS)


@schedules_bp.route('/create', methods=['POST'])
@require_permission('scheduled_reports.manage')
def create():
    name = request.form.get('name', '').strip()
    report_type = request.form.get('report_type', '')
    schedule = request.form.get('schedule', '')
    recipients = request.form.get('recipients', '').strip()

    if not all([name, report_type, schedule, recipients]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('scheduled_reports.index'))

    params = {}
    days = request.form.get('days', '')
    if days:
        params['days'] = int(days)

    success, msg = create_schedule(name, report_type, schedule, recipients,
                                    params, session.get('username', 'system'))
    flash(msg, 'success' if success else 'danger')
    log_action('create_schedule', name, msg, 'success' if success else 'failure')
    return redirect(url_for('scheduled_reports.index'))


@schedules_bp.route('/delete/<int:schedule_id>', methods=['POST'])
@require_permission('scheduled_reports.manage')
def delete(schedule_id):
    success, msg = delete_schedule(schedule_id)
    flash(msg, 'success' if success else 'danger')
    log_action('delete_schedule', str(schedule_id), msg, 'success' if success else 'failure')
    return redirect(url_for('scheduled_reports.index'))


@schedules_bp.route('/toggle/<int:schedule_id>', methods=['POST'])
@require_permission('scheduled_reports.manage')
def toggle(schedule_id):
    success, msg = toggle_schedule(schedule_id)
    flash(f'Schedule {msg.lower()}.', 'success' if success else 'danger')
    return redirect(url_for('scheduled_reports.index'))


@schedules_bp.route('/alert/create', methods=['POST'])
@require_permission('scheduled_reports.manage')
def create_alert_route():
    name = request.form.get('name', '').strip()
    alert_type = request.form.get('alert_type', '')
    recipients = request.form.get('recipients', '').strip()

    if not all([name, alert_type, recipients]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('scheduled_reports.index'))

    success, msg = create_alert(name, alert_type, recipients, {},
                                 session.get('username', 'system'))
    flash(msg, 'success' if success else 'danger')
    log_action('create_alert', name, msg, 'success' if success else 'failure')
    return redirect(url_for('scheduled_reports.index'))


@schedules_bp.route('/alert/delete/<int:alert_id>', methods=['POST'])
@require_permission('scheduled_reports.manage')
def delete_alert_route(alert_id):
    success, msg = delete_alert(alert_id)
    flash(msg, 'success' if success else 'danger')
    return redirect(url_for('scheduled_reports.index'))


@schedules_bp.route('/alert/toggle/<int:alert_id>', methods=['POST'])
@require_permission('scheduled_reports.manage')
def toggle_alert_route(alert_id):
    success, msg = toggle_alert(alert_id)
    flash(f'Alert {msg.lower()}.', 'success' if success else 'danger')
    return redirect(url_for('scheduled_reports.index'))


@schedules_bp.route('/test-email', methods=['POST'])
@require_permission('scheduled_reports.manage')
def test_email():
    recipients = request.form.get('recipients', '').strip()
    if not recipients:
        flash('Enter an email address to test.', 'danger')
        return redirect(url_for('scheduled_reports.index'))
    success, msg = send_test_email(recipients)
    flash(msg, 'success' if success else 'danger')
    return redirect(url_for('scheduled_reports.index'))
