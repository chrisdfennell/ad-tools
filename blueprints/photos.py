from flask import Blueprint, render_template, request, flash, redirect, url_for, Response

from services.ad_photos import get_user_photo, set_user_photo, delete_user_photo
from services.rbac import require_permission
from services.audit import log_action

photos_bp = Blueprint('photos', __name__, url_prefix='/photos')

MAX_PHOTO_SIZE = 100 * 1024  # 100KB limit for AD thumbnailPhoto


@photos_bp.route('/<sam>')
@require_permission('photos.view')
def view(sam):
    success, data = get_user_photo(sam)
    if not success:
        flash(f'Failed to load photo: {data}', 'danger')
        return redirect(url_for('users.detail', sam=sam))
    return render_template('photos/view.html', user=data, sam=sam)


@photos_bp.route('/<sam>/upload', methods=['POST'])
@require_permission('photos.edit')
def upload(sam):
    file = request.files.get('photo')
    if not file or not file.filename:
        flash('No file selected.', 'danger')
        return redirect(url_for('photos.view', sam=sam))

    photo_bytes = file.read()

    if len(photo_bytes) > MAX_PHOTO_SIZE:
        flash(f'Photo too large ({len(photo_bytes)//1024}KB). Maximum is {MAX_PHOTO_SIZE//1024}KB.', 'danger')
        return redirect(url_for('photos.view', sam=sam))

    success, msg = set_user_photo(sam, photo_bytes)
    flash(msg, 'success' if success else 'danger')
    log_action('set_user_photo', sam, f'Size: {len(photo_bytes)} bytes', 'success' if success else 'failure')
    return redirect(url_for('photos.view', sam=sam))


@photos_bp.route('/<sam>/delete', methods=['POST'])
@require_permission('photos.edit')
def delete(sam):
    success, msg = delete_user_photo(sam)
    flash(msg, 'success' if success else 'danger')
    log_action('delete_user_photo', sam, msg, 'success' if success else 'failure')
    return redirect(url_for('photos.view', sam=sam))


@photos_bp.route('/<sam>/raw')
@require_permission('photos.view')
def raw(sam):
    """Serve the raw photo as an image for <img> tags."""
    import base64
    success, data = get_user_photo(sam)
    if not success or not data.get('has_photo'):
        # Return a 1x1 transparent PNG
        return Response(b'', mimetype='image/png', status=404)
    photo_bytes = base64.b64decode(data['photo_b64'])
    # Detect format from magic bytes
    if photo_bytes[:2] == b'\xff\xd8':
        mime = 'image/jpeg'
    elif photo_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        mime = 'image/png'
    else:
        mime = 'image/jpeg'
    return Response(photo_bytes, mimetype=mime)
