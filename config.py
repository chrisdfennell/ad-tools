import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-me')

    # AD Connection
    AD_SERVER_IP = os.environ.get('AD_SERVER_IP')
    AD_DOMAIN = os.environ.get('AD_DOMAIN')
    AD_SUFFIX = os.environ.get('AD_SUFFIX')
    AD_USER = os.environ.get('AD_USER')
    AD_PASSWORD = os.environ.get('AD_PASSWORD')

    # Directory structure
    BASE_DN = os.environ.get('BASE_DN')
    USER_OU = os.environ.get('USER_OU')
    GROUPS_OU = os.environ.get('GROUPS_OU', '')
    COMPUTERS_OU = os.environ.get('COMPUTERS_OU', '')

    # Branding (customizable per deployment)
    APP_NAME = os.environ.get('APP_NAME', 'AD Tools')
    DOMAIN_DISPLAY = os.environ.get('DOMAIN_DISPLAY', '')

    # RBAC - AD groups that map to application roles
    # Domain Admins always get 'admin' role
    HELPDESK_GROUP = os.environ.get('HELPDESK_GROUP', '')
    VIEWER_GROUP = os.environ.get('VIEWER_GROUP', '')

    @property
    def domain_display_name(self):
        return self.DOMAIN_DISPLAY or f"{self.AD_DOMAIN}.{self.AD_SUFFIX}"
