import csv
import io

from flask import Blueprint, render_template, request, flash, Response

from services.ad_ldap_query import execute_query, SAVED_QUERIES
from services.audit import log_action

ldap_query_bp = Blueprint('ldap_query', __name__, url_prefix='/ldap-query')


@ldap_query_bp.route('/', methods=['GET', 'POST'])
def index():
    results = None
    query_data = {
        'search_base': '',
        'filter': '',
        'attributes': 'cn,sAMAccountName,distinguishedName',
        'scope': 'subtree',
    }

    # Load a saved query if requested
    saved = request.args.get('saved', '')
    if saved and saved in SAVED_QUERIES:
        sq = SAVED_QUERIES[saved]
        query_data['filter'] = sq['filter']
        query_data['attributes'] = sq['attrs']

    if request.method == 'POST':
        query_data = {
            'search_base': request.form.get('search_base', ''),
            'filter': request.form.get('filter', ''),
            'attributes': request.form.get('attributes', '*'),
            'scope': request.form.get('scope', 'subtree'),
        }
        if not query_data['filter']:
            flash('LDAP filter is required.', 'danger')
        else:
            success, data = execute_query(
                query_data['search_base'],
                query_data['filter'],
                query_data['attributes'],
                query_data['scope'],
            )
            if success:
                results = data
                log_action('ldap_query', query_data['filter'],
                           f'{data["count"]} results', 'success')
            else:
                flash(f'Query failed: {data}', 'danger')

    return render_template('ldap_query/index.html',
                           query=query_data, results=results,
                           saved_queries=SAVED_QUERIES)


@ldap_query_bp.route('/export', methods=['POST'])
def export_csv():
    """Export query results as CSV."""
    query_filter = request.form.get('filter', '')
    search_base = request.form.get('search_base', '')
    attributes = request.form.get('attributes', '*')
    scope = request.form.get('scope', 'subtree')

    if not query_filter:
        flash('No query to export.', 'danger')
        return '', 400

    success, data = execute_query(search_base, query_filter, attributes, scope)
    if not success:
        flash(f'Export failed: {data}', 'danger')
        return '', 500

    output = io.StringIO()
    fields = ['dn'] + data['attributes']
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for row in data['results']:
        writer.writerow(row)

    log_action('ldap_query_export', query_filter, f'{data["count"]} rows', 'success')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=ldap_query_export.csv'},
    )
