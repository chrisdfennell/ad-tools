from flask import Blueprint, render_template, request, flash, jsonify

from services.ad_bulk_attr import BULK_SAFE_ATTRIBUTES, search_objects, bulk_modify_attribute
from services.rbac import require_permission
from services.audit import log_action

bulk_attr_bp = Blueprint('bulk_attr', __name__, url_prefix='/bulk-attr')


@bulk_attr_bp.route('/', methods=['GET', 'POST'])
@require_permission('bulk_attr.edit')
def index():
    if request.method == 'POST':
        dns = request.form.getlist('dns')
        attribute = request.form.get('attribute', '').strip()
        value = request.form.get('value', '').strip()
        clear = request.form.get('clear') == '1'

        if not dns:
            flash('No objects selected.', 'warning')
        elif not attribute:
            flash('No attribute specified.', 'warning')
        elif attribute not in BULK_SAFE_ATTRIBUTES:
            flash(f'Attribute "{attribute}" is not allowed for bulk editing.', 'danger')
        elif not value and not clear:
            flash('Provide a value or check "Clear attribute".', 'warning')
        else:
            ok, fail, errors = bulk_modify_attribute(dns, attribute, value, clear)
            action = 'clear' if clear else f'set to "{value}"'
            log_action('bulk_attr_edit', attribute,
                       f'{action} on {ok + fail} objects: {ok} ok, {fail} failed', 'success')
            if fail == 0:
                flash(f'Successfully updated {ok} objects.', 'success')
            else:
                flash(f'Updated {ok}, failed {fail}. Errors: {"; ".join(errors[:5])}', 'warning')

    return render_template('bulk_attr/index.html', attributes=BULK_SAFE_ATTRIBUTES)


@bulk_attr_bp.route('/api/search')
@require_permission('bulk_attr.edit')
def api_search():
    q = request.args.get('q', '').strip()
    obj_type = request.args.get('type', 'users')
    if len(q) < 2:
        return jsonify([])
    ok, results = search_objects(q, obj_type)
    return jsonify(results if ok else [])
