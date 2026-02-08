from flask import Blueprint, render_template, request, flash, redirect, url_for, Response, jsonify

from services.ad_users import (
    search_users, get_user, create_user, modify_user, delete_user,
    disable_user, enable_user, unlock_user, reset_password,
    get_user_groups, bulk_import, export_users,
)
from services.ad_ous import get_ou_tree, move_object
from services.ad_groups import search_groups, add_member, remove_member
from services.audit import log_action, get_target_history

users_bp = Blueprint('users', __name__, url_prefix='/users')


@users_bp.route('/')
def list_users():
    query = request.args.get('q', '*')
    success, users = search_users(query)
    if not success:
        flash(f'Search failed: {users}', 'danger')
        users = []
    return render_template('users/list.html', users=users, query=query if query != '*' else '')


@users_bp.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        success, msg = create_user(
            fname=request.form['fname'],
            lname=request.form['lname'],
            username=request.form['username'],
            password=request.form['password'],
            email=request.form.get('email', ''),
            phone=request.form.get('phone', ''),
            mobile=request.form.get('mobile', ''),
            title=request.form.get('title', ''),
            department=request.form.get('department', ''),
            company=request.form.get('company', ''),
            description=request.form.get('description', ''),
            target_ou=request.form.get('target_ou') or None,
        )
        flash(msg, 'success' if success else 'danger')
        log_action('create_user', request.form['username'], msg, 'success' if success else 'failure')
        if success:
            return redirect(url_for('users.list_users'))

    # Get OUs for target OU dropdown
    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('users/create.html', ous=ous)


@users_bp.route('/<sam>/detail')
def detail(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    grp_success, groups = get_user_groups(user['dn'])
    if not grp_success:
        groups = []
    # Get OUs for move dropdown
    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    timeline = get_target_history(sam, limit=20)
    return render_template('users/detail.html', user=user, groups=groups, ous=ous, timeline=timeline)


@users_bp.route('/<sam>/edit', methods=['GET', 'POST'])
def edit(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))

    if request.method == 'POST':
        changes = {}
        for field in ['givenName', 'sn', 'displayName', 'mail', 'telephoneNumber',
                       'mobile', 'title', 'department', 'company', 'description']:
            form_val = request.form.get(field, '')
            changes[field] = form_val
        # Account expiration
        account_expires = request.form.get('accountExpires', '')
        changes['accountExpires'] = account_expires
        # Extension attributes
        for i in range(1, 16):
            attr = f'extensionAttribute{i}'
            form_val = request.form.get(attr, '')
            changes[attr] = form_val
        mod_success, msg = modify_user(user['dn'], changes)
        flash(msg, 'success' if mod_success else 'danger')
        log_action('modify_user', sam, msg, 'success' if mod_success else 'failure')
        if mod_success:
            return redirect(url_for('users.detail', sam=sam))

    return render_template('users/edit.html', user=user)


@users_bp.route('/<sam>/delete', methods=['POST'])
def delete(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    del_success, msg = delete_user(user['dn'])
    flash(msg, 'success' if del_success else 'danger')
    log_action('delete_user', sam, msg, 'success' if del_success else 'failure')
    return redirect(url_for('users.list_users'))


@users_bp.route('/<sam>/disable', methods=['POST'])
def disable(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    dis_success, msg = disable_user(user['dn'])
    flash(msg, 'success' if dis_success else 'danger')
    log_action('disable_user', sam, msg, 'success' if dis_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/<sam>/enable', methods=['POST'])
def enable(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    en_success, msg = enable_user(user['dn'])
    flash(msg, 'success' if en_success else 'danger')
    log_action('enable_user', sam, msg, 'success' if en_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/<sam>/unlock', methods=['POST'])
def unlock(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    un_success, msg = unlock_user(user['dn'])
    flash(msg, 'success' if un_success else 'danger')
    log_action('unlock_user', sam, msg, 'success' if un_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/<sam>/reset-password', methods=['POST'])
def pwd_reset(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    new_password = request.form['new_password']
    must_change = 'must_change' in request.form
    rst_success, msg = reset_password(user['dn'], new_password, must_change)
    flash(msg, 'success' if rst_success else 'danger')
    log_action('reset_password', sam, '', 'success' if rst_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/<sam>/copy')
def copy(sam):
    """Pre-fill create form from an existing user (template/copy)."""
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    grp_success, groups = get_user_groups(user['dn'])
    if not grp_success:
        groups = []
    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('users/copy.html', template_user=user, groups=groups, ous=ous)


@users_bp.route('/<sam>/copy', methods=['POST'])
def copy_submit(sam):
    """Create a new user from template, then add to same groups."""
    success, template_user = get_user(sam)
    template_groups = []
    if success:
        grp_success, template_groups = get_user_groups(template_user['dn'])
        if not grp_success:
            template_groups = []

    create_success, msg = create_user(
        fname=request.form['fname'],
        lname=request.form['lname'],
        username=request.form['username'],
        password=request.form['password'],
        email=request.form.get('email', ''),
        phone=request.form.get('phone', ''),
        mobile=request.form.get('mobile', ''),
        title=request.form.get('title', ''),
        department=request.form.get('department', ''),
        company=request.form.get('company', ''),
        description=request.form.get('description', ''),
        target_ou=request.form.get('target_ou') or None,
    )
    flash(msg, 'success' if create_success else 'danger')
    log_action('copy_user', request.form['username'], f'Copied from {sam}. {msg}',
               'success' if create_success else 'failure')

    if create_success and 'copy_groups' in request.form:
        new_sam = request.form['username']
        new_success, new_user = get_user(new_sam)
        if new_success:
            for grp in template_groups:
                add_member(grp['dn'], new_user['dn'])
            flash(f'Added to {len(template_groups)} group(s) from template.', 'info')
        return redirect(url_for('users.detail', sam=new_sam))
    elif create_success:
        return redirect(url_for('users.detail', sam=request.form['username']))

    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('users/copy.html', template_user=template_user if success else {}, groups=template_groups, ous=ous)


@users_bp.route('/<sam>/move', methods=['POST'])
def move(sam):
    """Move a user to a different OU."""
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    target_ou = request.form.get('target_ou', '')
    if not target_ou:
        flash('No target OU specified.', 'danger')
        return redirect(url_for('users.detail', sam=sam))
    mv_success, msg = move_object(user['dn'], target_ou)
    flash(msg, 'success' if mv_success else 'danger')
    log_action('move_user', sam, f'To: {target_ou}. {msg}', 'success' if mv_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/bulk-action', methods=['POST'])
def bulk_action():
    """Handle bulk actions on multiple users."""
    selected_dns = request.form.getlist('selected_dns')
    action = request.form.get('action', '')
    if not selected_dns:
        flash('No users selected.', 'warning')
        return redirect(url_for('users.list_users'))

    results = []
    for dn in selected_dns:
        if action == 'disable':
            s, m = disable_user(dn)
            results.append((dn, s, m))
            log_action('bulk_disable_user', dn, m, 'success' if s else 'failure')
        elif action == 'enable':
            s, m = enable_user(dn)
            results.append((dn, s, m))
            log_action('bulk_enable_user', dn, m, 'success' if s else 'failure')
        elif action == 'delete':
            s, m = delete_user(dn)
            results.append((dn, s, m))
            log_action('bulk_delete_user', dn, m, 'success' if s else 'failure')

    success_count = sum(1 for _, s, _ in results if s)
    fail_count = len(results) - success_count
    flash(f'Bulk {action}: {success_count} succeeded, {fail_count} failed.', 'success' if fail_count == 0 else 'warning')
    return redirect(url_for('users.list_users'))


@users_bp.route('/bulk', methods=['GET'])
def bulk():
    return render_template('users/bulk.html')


@users_bp.route('/bulk/import', methods=['POST'])
def bulk_import_route():
    file = request.files.get('csv_file')
    if not file:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('users.bulk'))
    csv_content = file.read().decode('utf-8')
    results = bulk_import(csv_content)
    for r in results:
        log_action('bulk_import_user', r['username'], r['message'], 'success' if r['success'] else 'failure')
    return render_template('users/bulk.html', results=results)


@users_bp.route('/bulk/export')
def bulk_export():
    success, csv_data = export_users()
    if not success:
        flash(f'Export failed: {csv_data}', 'danger')
        return redirect(url_for('users.bulk'))
    log_action('export_users', 'all', 'CSV export')
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=ad_users_export.csv'},
    )


@users_bp.route('/<sam>/add-to-group', methods=['POST'])
def add_to_group(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    group_dn = request.form['group_dn']
    add_success, msg = add_member(group_dn, user['dn'])
    flash(msg, 'success' if add_success else 'danger')
    log_action('add_to_group', sam, f'Group: {group_dn}', 'success' if add_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/<sam>/remove-from-group', methods=['POST'])
def remove_from_group(sam):
    success, user = get_user(sam)
    if not success:
        flash(f'User not found: {user}', 'danger')
        return redirect(url_for('users.list_users'))
    group_dn = request.form['group_dn']
    rm_success, msg = remove_member(group_dn, user['dn'])
    flash(msg, 'success' if rm_success else 'danger')
    log_action('remove_from_group', sam, f'Group: {group_dn}', 'success' if rm_success else 'failure')
    return redirect(url_for('users.detail', sam=sam))


@users_bp.route('/api/search-groups')
def search_groups_api():
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    success, groups = search_groups(q)
    if not success:
        return jsonify([])
    return jsonify([{'cn': g['cn'], 'dn': g['dn'], 'type_label': g['group_type_label']} for g in groups[:20]])


@users_bp.route('/compare')
def compare():
    sam1 = request.args.get('user1', '')
    sam2 = request.args.get('user2', '')
    user1_data = None
    user2_data = None
    groups1 = []
    groups2 = []

    if sam1:
        s, u = get_user(sam1)
        if s:
            user1_data = u
            gs, groups1 = get_user_groups(u['dn'])
            if not gs:
                groups1 = []

    if sam2:
        s, u = get_user(sam2)
        if s:
            user2_data = u
            gs, groups2 = get_user_groups(u['dn'])
            if not gs:
                groups2 = []

    # Build diff data
    diff = None
    if user1_data and user2_data:
        compare_fields = [
            ('Display Name', 'display_name'), ('First Name', 'first_name'),
            ('Last Name', 'last_name'), ('Email', 'email'),
            ('Phone', 'phone'), ('Mobile', 'mobile'),
            ('Title', 'title'), ('Department', 'department'),
            ('Company', 'company'), ('Description', 'description'),
            ('Status', 'status'), ('UPN', 'upn'),
            ('Last Logon', 'last_logon'), ('Password Last Set', 'pwd_last_set'),
            ('Created', 'when_created'), ('Modified', 'when_changed'),
        ]
        diff = []
        for label, key in compare_fields:
            v1 = user1_data.get(key, '')
            v2 = user2_data.get(key, '')
            diff.append({
                'label': label,
                'val1': v1,
                'val2': v2,
                'match': str(v1) == str(v2),
            })

        # Group comparison
        g1_dns = {g['dn'] for g in groups1}
        g2_dns = {g['dn'] for g in groups2}
        g1_names = {g['dn']: g['cn'] for g in groups1}
        g2_names = {g['dn']: g['cn'] for g in groups2}
        all_group_dns = g1_dns | g2_dns
        group_diff = []
        for gdn in sorted(all_group_dns, key=lambda d: g1_names.get(d, g2_names.get(d, d)).lower()):
            group_diff.append({
                'name': g1_names.get(gdn, g2_names.get(gdn, gdn)),
                'in1': gdn in g1_dns,
                'in2': gdn in g2_dns,
            })
    else:
        group_diff = []

    # Get user list for dropdowns
    all_success, all_users = search_users('*')
    user_list = all_users if all_success else []

    return render_template('users/compare.html',
                           user1=user1_data, user2=user2_data,
                           sam1=sam1, sam2=sam2,
                           diff=diff, group_diff=group_diff,
                           user_list=user_list)


def _flatten_ous(tree, depth=0):
    """Flatten OU tree into a list with indentation levels for dropdown."""
    result = []
    if tree.get('dn') and tree.get('name'):
        result.append({'dn': tree['dn'], 'name': ('— ' * depth) + tree['name']})
    for child in tree.get('children', []):
        result.extend(_flatten_ous(child, depth + 1))
    return result
