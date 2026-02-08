import ssl
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from ldap3 import Server, Connection, NTLM, Tls, SUBTREE, ALL

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('auth/login.html')

        from flask import current_app
        cfg = current_app.config
        domain = cfg['AD_DOMAIN']

        try:
            tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(
                f"ldaps://{cfg['AD_SERVER_IP']}:636",
                use_ssl=True,
                tls=tls_config,
            )
            conn = Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
            conn.unbind()
        except Exception:
            flash('Invalid credentials or cannot connect to AD.', 'danger')
            return render_template('auth/login.html')

        # Credentials are valid -- determine role via RBAC
        from services.rbac import get_user_role
        role = get_user_role(cfg, username)

        if not role:
            flash('Access denied. You are not a member of any authorized group.', 'danger')
            return render_template('auth/login.html')

        session['logged_in'] = True
        session['username'] = username
        session['role'] = role
        flash(f'Welcome, {username}! (Role: {role})', 'success')
        return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
