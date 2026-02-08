from flask import Flask, session, redirect, url_for, request
from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    from blueprints.auth import auth_bp
    from blueprints.dashboard import dashboard_bp
    from blueprints.users import users_bp
    from blueprints.groups import groups_bp
    from blueprints.ous import ous_bp
    from blueprints.computers import computers_bp
    from blueprints.audit import audit_bp
    from blueprints.reports import reports_bp
    from blueprints.recycle import recycle_bp
    from blueprints.api import api_bp
    from blueprints.attributes import attributes_bp
    from blueprints.search import search_bp
    from blueprints.orgchart import orgchart_bp
    from blueprints.gpo import gpo_bp
    from blueprints.delegation import delegation_bp
    from blueprints.service_accounts import svc_bp
    from blueprints.dns import dns_bp
    from blueprints.activity import activity_bp
    from blueprints.laps import laps_bp
    from blueprints.bitlocker import bitlocker_bp
    from blueprints.fgpp import fgpp_bp
    from blueprints.group_nesting import nesting_bp
    from blueprints.ad_health import health_bp
    from blueprints.scheduled_reports import schedules_bp
    from blueprints.photos import photos_bp
    # Round 2 blueprints
    from blueprints.bulk_groups import bulk_groups_bp
    from blueprints.ldap_query import ldap_query_bp
    from blueprints.gmsa import gmsa_bp
    from blueprints.spn import spn_bp
    from blueprints.token_size import token_bp
    from blueprints.workflows import workflows_bp
    # Round 3 blueprints
    from blueprints.lockout import lockout_bp
    from blueprints.sites import sites_bp
    from blueprints.acl import acl_bp
    from blueprints.bulk_attr import bulk_attr_bp
    from blueprints.schema import schema_bp
    from blueprints.replication import replication_bp
    from blueprints.dynamic_groups import dyn_groups_bp
    from blueprints.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(ous_bp)
    app.register_blueprint(computers_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(recycle_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(attributes_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(orgchart_bp)
    app.register_blueprint(gpo_bp)
    app.register_blueprint(delegation_bp)
    app.register_blueprint(svc_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(activity_bp)
    app.register_blueprint(laps_bp)
    app.register_blueprint(bitlocker_bp)
    app.register_blueprint(fgpp_bp)
    app.register_blueprint(nesting_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(schedules_bp)
    app.register_blueprint(photos_bp)
    # Round 2 blueprints
    app.register_blueprint(bulk_groups_bp)
    app.register_blueprint(ldap_query_bp)
    app.register_blueprint(gmsa_bp)
    app.register_blueprint(spn_bp)
    app.register_blueprint(token_bp)
    app.register_blueprint(workflows_bp)
    # Round 3 blueprints
    app.register_blueprint(lockout_bp)
    app.register_blueprint(sites_bp)
    app.register_blueprint(acl_bp)
    app.register_blueprint(bulk_attr_bp)
    app.register_blueprint(schema_bp)
    app.register_blueprint(replication_bp)
    app.register_blueprint(dyn_groups_bp)
    app.register_blueprint(settings_bp)

    # Initialize databases
    from services.audit import init_db
    from services.scheduled_reports import init_scheduled_reports_db
    from services.dynamic_groups import init_dynamic_groups_db
    from services.app_settings import init_settings_db
    with app.app_context():
        init_db()
        init_scheduled_reports_db()
        init_dynamic_groups_db()
        init_settings_db()

        # Load saved settings from SQLite, overriding env vars
        from services.app_settings import get_all_settings
        saved = get_all_settings()
        for key, value in saved.items():
            if value:  # only override if non-empty
                app.config[key] = value

    @app.before_request
    def require_login():
        allowed = ('auth.login', 'static', 'api.api_login')
        if request.endpoint and request.endpoint in allowed:
            return
        if not session.get('logged_in'):
            return redirect(url_for('auth.login'))

    @app.context_processor
    def inject_branding():
        from services.rbac import has_permission
        domain = app.config.get('DOMAIN_DISPLAY') or \
            f"{app.config.get('AD_DOMAIN', '')}.{app.config.get('AD_SUFFIX', '')}"
        return {
            'app_name': app.config.get('APP_NAME', 'AD Tools'),
            'domain_display': domain,
            'logged_in_user': session.get('username', ''),
            'user_role': session.get('role', ''),
            'has_permission': has_permission,
        }

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
