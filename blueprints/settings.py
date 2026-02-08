from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app

from services.app_settings import (
    SETTING_GROUPS, get_all_settings, save_settings,
)
from services.rbac import require_permission
from services.audit import log_action

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


@settings_bp.route('/', methods=['GET', 'POST'])
@require_permission('settings.manage')
def index():
    if request.method == 'POST':
        new_settings = {}
        for group_name, fields in SETTING_GROUPS.items():
            for field in fields:
                val = request.form.get(field['key'], '').strip()
                new_settings[field['key']] = val

        ok, msg = save_settings(new_settings)
        flash(msg, 'success' if ok else 'danger')
        log_action('update_settings', 'app_settings',
                   f'{len(new_settings)} settings updated', 'success' if ok else 'failure')

        # Update app config in memory for immediate effect
        if ok:
            for key, val in new_settings.items():
                if val:
                    current_app.config[key] = val

        return redirect(url_for('settings.index'))

    saved = get_all_settings()

    # Merge: env var → saved setting → default
    for group_name, fields in SETTING_GROUPS.items():
        for field in fields:
            key = field['key']
            if key in saved:
                field['current'] = saved[key]
            else:
                field['current'] = current_app.config.get(key, field['default']) or field['default']

    return render_template('settings/index.html', setting_groups=SETTING_GROUPS)
