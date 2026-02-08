from flask import Blueprint, render_template, request

from services.ad_search import global_search

search_bp = Blueprint('search', __name__, url_prefix='/search')


@search_bp.route('/')
def index():
    query = request.args.get('q', '').strip()
    results = None
    total = 0
    if query:
        success, data, total = global_search(query)
        if success:
            results = data
        else:
            results = {'users': [], 'groups': [], 'computers': [], 'ous': []}
    return render_template('search/results.html', query=query, results=results, total=total)
