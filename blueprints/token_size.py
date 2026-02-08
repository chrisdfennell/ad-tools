from flask import Blueprint, render_template, request, flash

from services.ad_token_size import estimate_token_size

token_bp = Blueprint('token_size', __name__, url_prefix='/token-size')


@token_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    sam = request.args.get('sam', '') or request.form.get('sam', '')

    if sam:
        success, data = estimate_token_size(sam)
        if success:
            result = data
        else:
            flash(f'Error: {data}', 'danger')

    return render_template('token_size/index.html', result=result, sam=sam)
