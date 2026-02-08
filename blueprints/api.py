import ssl
import functools
from flask import Blueprint, request, jsonify, session
from ldap3 import Server, Connection, NTLM, Tls

api_bp = Blueprint('api', __name__, url_prefix='/api')


def api_auth_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Check session auth first
        if session.get('logged_in'):
            return f(*args, **kwargs)
        # Check Basic auth header
        auth = request.authorization
        if not auth:
            return jsonify({'error': 'Authentication required'}), 401
        from flask import current_app
        cfg = current_app.config
        try:
            tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(f"ldaps://{cfg['AD_SERVER_IP']}:636", use_ssl=True, tls=tls_config)
            conn = Connection(server, user=f"{cfg['AD_DOMAIN']}\\{auth.username}",
                              password=auth.password, authentication=NTLM, auto_bind=True)
            conn.unbind()
        except Exception:
            return jsonify({'error': 'Invalid credentials'}), 401
        return f(*args, **kwargs)
    return decorated


@api_bp.route('/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'username and password required'}), 400
    from flask import current_app
    cfg = current_app.config
    try:
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(f"ldaps://{cfg['AD_SERVER_IP']}:636", use_ssl=True, tls=tls_config)
        conn = Connection(server, user=f"{cfg['AD_DOMAIN']}\\{data['username']}",
                          password=data['password'], authentication=NTLM, auto_bind=True)
        conn.unbind()
        session['logged_in'] = True
        session['username'] = data['username']
        return jsonify({'message': 'Login successful', 'username': data['username']})
    except Exception:
        return jsonify({'error': 'Invalid credentials'}), 401


@api_bp.route('/users', methods=['GET'])
@api_auth_required
def list_users():
    from services.ad_users import search_users
    query = request.args.get('q', '*')
    success, data = search_users(query)
    if not success:
        return jsonify({'error': data}), 500
    return jsonify({'users': data})


@api_bp.route('/users/<sam>', methods=['GET'])
@api_auth_required
def get_user(sam):
    from services.ad_users import get_user as svc_get_user, get_user_groups
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    grp_success, groups = get_user_groups(user['dn'])
    user['groups'] = groups if grp_success else []
    return jsonify({'user': user})


@api_bp.route('/users', methods=['POST'])
@api_auth_required
def create_user():
    from services.ad_users import create_user as svc_create
    from services.audit import log_action
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    required = ['fname', 'lname', 'username', 'password']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    success, msg = svc_create(
        fname=data['fname'], lname=data['lname'],
        username=data['username'], password=data['password'],
        email=data.get('email', ''), phone=data.get('phone', ''),
        mobile=data.get('mobile', ''), title=data.get('title', ''),
        department=data.get('department', ''), company=data.get('company', ''),
        description=data.get('description', ''), target_ou=data.get('target_ou'),
    )
    log_action('create_user', data['username'], msg, 'success' if success else 'failure')
    if not success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg}), 201


@api_bp.route('/users/<sam>', methods=['DELETE'])
@api_auth_required
def delete_user(sam):
    from services.ad_users import get_user as svc_get_user, delete_user as svc_delete
    from services.audit import log_action
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    del_success, msg = svc_delete(user['dn'])
    log_action('delete_user', sam, msg, 'success' if del_success else 'failure')
    if not del_success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg})


@api_bp.route('/users/<sam>/reset-password', methods=['POST'])
@api_auth_required
def reset_password(sam):
    from services.ad_users import get_user as svc_get_user, reset_password as svc_reset
    from services.audit import log_action
    data = request.get_json()
    if not data or not data.get('new_password'):
        return jsonify({'error': 'new_password required'}), 400
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    rst_success, msg = svc_reset(user['dn'], data['new_password'], data.get('must_change', False))
    log_action('reset_password', sam, '', 'success' if rst_success else 'failure')
    if not rst_success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg})


@api_bp.route('/users/<sam>/disable', methods=['POST'])
@api_auth_required
def disable_user(sam):
    from services.ad_users import get_user as svc_get_user, disable_user as svc_disable
    from services.audit import log_action
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    dis_success, msg = svc_disable(user['dn'])
    log_action('disable_user', sam, msg, 'success' if dis_success else 'failure')
    if not dis_success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg})


@api_bp.route('/users/<sam>/enable', methods=['POST'])
@api_auth_required
def enable_user(sam):
    from services.ad_users import get_user as svc_get_user, enable_user as svc_enable
    from services.audit import log_action
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    en_success, msg = svc_enable(user['dn'])
    log_action('enable_user', sam, msg, 'success' if en_success else 'failure')
    if not en_success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg})


@api_bp.route('/users/<sam>/unlock', methods=['POST'])
@api_auth_required
def unlock_user(sam):
    from services.ad_users import get_user as svc_get_user, unlock_user as svc_unlock
    from services.audit import log_action
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    un_success, msg = svc_unlock(user['dn'])
    log_action('unlock_user', sam, msg, 'success' if un_success else 'failure')
    if not un_success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg})


@api_bp.route('/users/<sam>/groups', methods=['POST'])
@api_auth_required
def add_to_group(sam):
    from services.ad_users import get_user as svc_get_user
    from services.ad_groups import add_member
    from services.audit import log_action
    data = request.get_json()
    if not data or not data.get('group_dn'):
        return jsonify({'error': 'group_dn required'}), 400
    success, user = svc_get_user(sam)
    if not success:
        return jsonify({'error': user}), 404
    add_success, msg = add_member(data['group_dn'], user['dn'])
    log_action('add_to_group', sam, f"group: {data['group_dn']}", 'success' if add_success else 'failure')
    if not add_success:
        return jsonify({'error': msg}), 400
    return jsonify({'message': msg})


@api_bp.route('/groups', methods=['GET'])
@api_auth_required
def list_groups():
    from services.ad_groups import search_groups
    query = request.args.get('q', '*')
    success, data = search_groups(query)
    if not success:
        return jsonify({'error': data}), 500
    return jsonify({'groups': data})


@api_bp.route('/computers', methods=['GET'])
@api_auth_required
def list_computers():
    from services.ad_computers import search_computers
    query = request.args.get('q', '*')
    success, data = search_computers(query)
    if not success:
        return jsonify({'error': data}), 500
    return jsonify({'computers': data})
