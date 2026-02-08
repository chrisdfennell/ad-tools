import ssl
from ldap3 import Server, Connection, ALL, NTLM, Tls
from flask import current_app


def get_connection():
    """Create and return an authenticated LDAPS connection to Active Directory."""
    cfg = current_app.config
    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    server = Server(
        f"ldaps://{cfg['AD_SERVER_IP']}:636",
        get_info=ALL,
        use_ssl=True,
        tls=tls_config,
    )
    conn = Connection(
        server,
        user=f"{cfg['AD_DOMAIN']}\\{cfg['AD_USER']}",
        password=cfg['AD_PASSWORD'],
        authentication=NTLM,
        auto_bind=True,
    )
    return conn
