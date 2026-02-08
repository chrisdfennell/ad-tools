from flask import Blueprint, render_template, request, flash, redirect, url_for

from services.ad_users import create_user, get_user, disable_user, modify_user, get_user_groups
from services.ad_groups import add_member, remove_member, search_groups
from services.ad_ous import get_ou_tree, move_object
from services.audit import log_action

workflows_bp = Blueprint('workflows', __name__, url_prefix='/workflows')


def _flatten_ous(tree, depth=0):
    result = []
    if tree.get('dn') and tree.get('name'):
        result.append({'dn': tree['dn'], 'name': ('--- ' * depth) + tree['name']})
    for child in tree.get('children', []):
        result.extend(_flatten_ous(child, depth + 1))
    return result


@workflows_bp.route('/onboard', methods=['GET', 'POST'])
def onboard():
    if request.method == 'POST':
        # Step 1: Create the user
        fname = request.form.get('fname', '').strip()
        lname = request.form.get('lname', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        mobile = request.form.get('mobile', '').strip()
        title = request.form.get('title', '').strip()
        department = request.form.get('department', '').strip()
        company = request.form.get('company', '').strip()
        description = request.form.get('description', '').strip()
        target_ou = request.form.get('target_ou') or None

        if not all([fname, lname, username, password]):
            flash('First name, last name, username, and password are required.', 'danger')
            ou_success, ou_data = get_ou_tree()
            ous = _flatten_ous(ou_data) if ou_success else []
            return render_template('workflows/onboard.html', ous=ous)

        success, msg = create_user(
            fname, lname, username, password,
            email=email, phone=phone, mobile=mobile,
            title=title, department=department, company=company,
            description=description, target_ou=target_ou,
        )
        if not success:
            flash(f'User creation failed: {msg}', 'danger')
            ou_success, ou_data = get_ou_tree()
            ous = _flatten_ous(ou_data) if ou_success else []
            return render_template('workflows/onboard.html', ous=ous)

        log_action('onboard_create', username, msg, 'success')
        results = [f'User {username} created successfully.']

        # Step 2: Add to groups
        group_dns = request.form.getlist('group_dns')
        user_success, user_data = get_user(username)
        if user_success and group_dns:
            for group_dn in group_dns:
                gs, gm = add_member(group_dn, user_data['dn'])
                results.append(f'Add to group: {"OK" if gs else gm}')
            log_action('onboard_groups', username, f'{len(group_dns)} groups', 'success')

        # Step 3: Set manager
        manager_dn = request.form.get('manager_dn', '').strip()
        if user_success and manager_dn:
            ms, mm = modify_user(user_data['dn'], {'manager': manager_dn})
            results.append(f'Set manager: {"OK" if ms else mm}')

        flash('Onboarding completed! ' + ' | '.join(results), 'success')
        return redirect(url_for('users.detail', sam=username))

    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('workflows/onboard.html', ous=ous)


@workflows_bp.route('/offboard', methods=['GET', 'POST'])
def offboard():
    if request.method == 'POST':
        sam = request.form.get('sam', '').strip()
        if not sam:
            flash('Username is required.', 'danger')
            return render_template('workflows/offboard.html')

        success, user = get_user(sam)
        if not success:
            flash(f'User not found: {user}', 'danger')
            return render_template('workflows/offboard.html')

        results = []

        # Step 1: Disable account
        if 'disable_account' in request.form:
            ds, dm = disable_user(user['dn'])
            results.append(f'Disable account: {"OK" if ds else dm}')
            log_action('offboard_disable', sam, dm, 'success' if ds else 'failure')

        # Step 2: Remove from groups
        if 'remove_groups' in request.form:
            gs, groups = get_user_groups(user['dn'])
            if gs:
                removed = 0
                for grp in groups:
                    rs, rm = remove_member(grp['dn'], user['dn'])
                    if rs:
                        removed += 1
                results.append(f'Removed from {removed}/{len(groups)} groups')
                log_action('offboard_groups', sam, f'{removed} groups removed', 'success')

        # Step 3: Clear manager
        if 'clear_manager' in request.form:
            ms, mm = modify_user(user['dn'], {'manager': ''})
            results.append(f'Clear manager: {"OK" if ms else mm}')

        # Step 4: Update description
        if 'set_description' in request.form:
            import datetime
            desc = f'Offboarded on {datetime.date.today().isoformat()} by {request.form.get("offboarded_by", "admin")}'
            ms, mm = modify_user(user['dn'], {'description': desc})
            results.append(f'Set description: {"OK" if ms else mm}')

        # Step 5: Move to disabled OU
        target_ou = request.form.get('target_ou', '').strip()
        if target_ou:
            mvs, mvm = move_object(user['dn'], target_ou)
            results.append(f'Move to OU: {"OK" if mvs else mvm}')
            log_action('offboard_move', sam, f'To: {target_ou}', 'success' if mvs else 'failure')

        flash('Offboarding completed! ' + ' | '.join(results), 'success')
        return redirect(url_for('users.detail', sam=sam))

    ou_success, ou_data = get_ou_tree()
    ous = _flatten_ous(ou_data) if ou_success else []
    return render_template('workflows/offboard.html', ous=ous)
