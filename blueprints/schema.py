from flask import Blueprint, render_template, request, flash

from services.ad_schema import get_object_classes, get_attribute_definitions
from services.rbac import require_permission

schema_bp = Blueprint('schema', __name__, url_prefix='/schema')


@schema_bp.route('/')
@require_permission('schema.view')
def index():
    tab = request.args.get('tab', 'classes')
    query = request.args.get('q', '').strip()

    classes = []
    attrs = []

    if tab == 'attributes':
        ok, data = get_attribute_definitions(query)
        if not ok:
            flash(f'Failed to load attributes: {data}', 'danger')
        else:
            attrs = data
    else:
        ok, data = get_object_classes(query)
        if not ok:
            flash(f'Failed to load object classes: {data}', 'danger')
        else:
            classes = data

    return render_template('schema/index.html',
                           tab=tab, query=query,
                           classes=classes, attrs=attrs)
