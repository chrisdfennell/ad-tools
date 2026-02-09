# AD Tools

A self-hosted web interface for managing Active Directory, built with Flask and ldap3. Runs in Docker with zero dependencies on Windows — just point it at your Domain Controller.

![Python](https://img.shields.io/badge/python-3.11-blue)
![Flask](https://img.shields.io/badge/flask-3.x-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-blue)

## Features

### User Management
- **All Users** — Browse, search, and filter all AD users with DataTables
- **Create User** — Full user creation form with OU picker and group assignment
- **Edit User** — Modify attributes, move between OUs, manage group memberships
- **Bulk Import/Export** — CSV-based bulk user creation and export
- **Compare Users** — Side-by-side attribute comparison of two users
- **User Photos** — View and upload `thumbnailPhoto` for users

### Workflows
- **Onboarding** — Guided wizard for new employee setup (create user, add to groups, set attributes)
- **Offboarding** — Disable account, remove groups, move to disabled OU, reset password

### Group Management
- **All Groups** — Browse security and distribution groups
- **Create/Edit Groups** — Full group lifecycle management
- **Group Nesting** — Visualize nested group hierarchies
- **Bulk Membership** — Add/remove users across multiple groups at once
- **Dynamic Groups** — Define LDAP filter-based rules that auto-evaluate membership

### Directory
- **OU Browser** — Interactive tree view of Organizational Units with drag-and-drop
- **Computers** — Browse, enable/disable, move, and manage computer accounts
- **Org Chart** — Visual organizational chart based on the `manager` attribute
- **DNS Records** — Browse AD-integrated DNS zones and records
- **Group Policy** — View GPOs, their links, and link status
- **Lockout Insight** — View domain lockout policy, find locked accounts, check lockout details
- **Sites & Subnets** — View AD Sites & Services topology, site links, and subnet assignments
- **Replication** — Monitor DC replication connections, NTDS topology, and partner status

### Security
- **Service Accounts** — Identify accounts with `DONT_EXPIRE_PASSWORD`, SPNs, etc.
- **Delegations** — Find accounts trusted for delegation (unconstrained/constrained/RBCD)
- **LAPS Passwords** — Retrieve Local Administrator Password Solution passwords (Legacy + Windows LAPS)
- **BitLocker Keys** — Retrieve BitLocker recovery keys stored in AD
- **Password Policies** — View Fine-Grained Password Policies (FGPP) and their assignments
- **gMSA Accounts** — Browse Group Managed Service Accounts and their principals
- **SPN Management** — View, add, and remove Service Principal Names
- **Token Size** — Estimate Kerberos token size for users (group membership bloat detection)
- **Permissions (ACL)** — Raw ACL viewer for any AD object with binary Security Descriptor parsing

### Reports
- **Password Expiry** — Users with passwords expiring soon
- **Stale Objects** — Users and computers that haven't logged in recently
- **Privileged Accounts** — Members of sensitive groups (Domain Admins, Enterprise Admins, etc.)
- **Scheduled Reports** — Email reports on a schedule (requires SMTP configuration)

### System
- **AD Health** — FSMO roles, functional levels, domain controller inventory
- **Recycle Bin** — Browse and restore deleted AD objects
- **Audit Log** — Local audit trail of all actions performed through AD Tools
- **Activity Monitor** — Real-time view of recent AD modifications
- **Attribute Editor** — Raw attribute editor for any AD object
- **LDAP Query** — Execute custom LDAP queries with a built-in query builder
- **Schema Browser** — Browse AD schema classes and attribute definitions
- **Bulk Attribute Edit** — Modify a single attribute across multiple objects at once
- **Settings** — Configure branding, RBAC groups, SMTP, and more from the UI (persists to SQLite)

### Other
- **Global Search** — Search users, groups, computers, and OUs from one search bar
- **REST API** — JSON API with token auth for external integrations
- **Dark Mode** — Toggle between light and dark themes
- **Role-Based Access** — Admin, Helpdesk, and Viewer roles mapped to AD groups
- **Dashboard** — Overview charts showing user status distribution, password expiry, and top groups

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/ChrisDFennell/ad-tools.git
cd ad-tools
```

### 2. Configure

Edit `docker-compose.yml` with your AD connection details:

```yaml
environment:
  - SECRET_KEY=change-me-to-a-random-string
  - AD_SERVER_IP=192.168.1.10      # IP of your Domain Controller
  - AD_DOMAIN=yourdomain            # NetBIOS domain name
  - AD_SUFFIX=com                   # Domain suffix
  - AD_USER=svc_adtools             # Service account username
  - AD_PASSWORD=YourPasswordHere    # Service account password
  - BASE_DN=DC=yourdomain,DC=com
  - USER_OU=OU=Users,DC=yourdomain,DC=com
```

### 3. Run

```bash
docker compose up -d
```

Open **http://your-server:8888** and log in with your AD credentials.

### Docker Hub

```bash
docker pull fennch/ad-tools:latest
```

Then create a `docker-compose.yml` using the example above and run `docker compose up -d`.

## Configuration

All configuration is done via environment variables in `docker-compose.yml`. Settings can also be managed from the web UI at **Settings** (admin only), which persists to SQLite and overrides environment variables.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session secret — set to a random string |
| `AD_SERVER_IP` | Yes | IP address of your Domain Controller |
| `AD_DOMAIN` | Yes | NetBIOS domain name (e.g., `CONTOSO`) |
| `AD_SUFFIX` | Yes | Domain suffix (e.g., `com`, `local`, `org`) |
| `AD_USER` | Yes | Service account username |
| `AD_PASSWORD` | Yes | Service account password |
| `BASE_DN` | Yes | Base Distinguished Name (e.g., `DC=contoso,DC=com`) |
| `USER_OU` | Yes | Default OU for new users |
| `GROUPS_OU` | No | Override search base for groups (default: `BASE_DN`) |
| `COMPUTERS_OU` | No | Override search base for computers (default: `BASE_DN`) |
| `APP_NAME` | No | Sidebar title (default: `AD Tools`) |
| `DOMAIN_DISPLAY` | No | Domain shown in sidebar (auto-detected if empty) |
| `HELPDESK_GROUP` | No | AD group for helpdesk role |
| `VIEWER_GROUP` | No | AD group for read-only role |
| `SMTP_HOST` | No | SMTP server for email features |
| `SMTP_PORT` | No | SMTP port (default: `587`) |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASSWORD` | No | SMTP password |
| `SMTP_FROM` | No | From address for emails |
| `SMTP_TLS` | No | Enable TLS (default: `true`) |

## Service Account Requirements

The service account (`AD_USER`) needs the following permissions depending on your usage:

| Access Level | Permissions Needed |
|---|---|
| **Read-only** | Default Domain Users membership is usually sufficient |
| **User management** | Delegated control over target OUs (create/delete/modify users) |
| **Full access** | Domain Admin or equivalent delegated permissions |

The account authenticates over **LDAPS (port 636)** using **NTLM**. Ensure port 636 is accessible from wherever Docker runs.

## Role-Based Access Control (RBAC)

AD Tools maps AD group membership to application roles:

| Role | Access Level | Assignment |
|---|---|---|
| **Admin** | Full access to all features | Members of `Domain Admins` |
| **Helpdesk** | Unlock, reset passwords, view most features | Members of the group set in `HELPDESK_GROUP` |
| **Viewer** | Read-only access | Members of the group set in `VIEWER_GROUP` |

If neither `HELPDESK_GROUP` nor `VIEWER_GROUP` is configured, only Domain Admins can log in.

## Architecture

```
ad-tools/
├── app.py                          # Flask app factory, blueprint registration
├── config.py                       # Configuration from environment variables
├── Dockerfile                      # Python 3.11-slim + Gunicorn
├── docker-compose.yml              # Container orchestration
├── requirements.txt                # flask, ldap3, gunicorn
├── openssl_legacy.cnf              # Enables MD4 for NTLM (required in modern OpenSSL)
├── LICENSE                         # MIT License
│
├── blueprints/                     # Flask blueprints (one per feature)
│   ├── __init__.py
│   ├── acl.py                      # Object ACL/permissions viewer
│   ├── activity.py                 # Activity monitor
│   ├── ad_health.py                # AD health dashboard
│   ├── api.py                      # REST API endpoints
│   ├── attributes.py               # Raw attribute editor
│   ├── audit.py                    # Audit log viewer
│   ├── auth.py                     # Login/logout
│   ├── bitlocker.py                # BitLocker key retrieval
│   ├── bulk_attr.py                # Bulk attribute editor
│   ├── bulk_groups.py              # Bulk group membership
│   ├── computers.py                # Computer management
│   ├── dashboard.py                # Dashboard with charts
│   ├── delegation.py               # Delegation viewer
│   ├── dns.py                      # DNS zone/record browser
│   ├── dynamic_groups.py           # Dynamic group rules
│   ├── fgpp.py                     # Fine-grained password policies
│   ├── gmsa.py                     # gMSA accounts
│   ├── gpo.py                      # Group Policy objects
│   ├── group_nesting.py            # Group nesting visualizer
│   ├── groups.py                   # Group management
│   ├── laps.py                     # LAPS password retrieval
│   ├── ldap_query.py               # Custom LDAP query tool
│   ├── lockout.py                  # Account lockout insight
│   ├── orgchart.py                 # Org chart viewer
│   ├── ous.py                      # OU browser
│   ├── photos.py                   # User photo management
│   ├── recycle.py                  # Recycle bin browser
│   ├── replication.py              # Replication status monitor
│   ├── reports.py                  # Built-in reports
│   ├── scheduled_reports.py        # Scheduled email reports
│   ├── schema.py                   # Schema browser
│   ├── search.py                   # Global search
│   ├── service_accounts.py         # Service account finder
│   ├── settings.py                 # Application settings UI
│   ├── sites.py                    # Sites & subnets viewer
│   ├── spn.py                      # SPN management
│   ├── token_size.py               # Kerberos token size estimator
│   ├── users.py                    # User management
│   └── workflows.py                # Onboarding/offboarding wizards
│
├── services/                       # Business logic & LDAP operations
│   ├── __init__.py
│   ├── ad_acl.py                   # Security descriptor parsing
│   ├── ad_activity.py              # Recent AD modifications
│   ├── ad_attributes.py            # Raw attribute read/write
│   ├── ad_bitlocker.py             # BitLocker recovery keys
│   ├── ad_bulk_attr.py             # Bulk attribute modifications
│   ├── ad_computers.py             # Computer CRUD
│   ├── ad_connection.py            # Shared LDAP connection helper
│   ├── ad_dashboard.py             # Dashboard stats & chart data
│   ├── ad_delegation.py            # Delegation detection
│   ├── ad_dns.py                   # DNS zone/record queries
│   ├── ad_fgpp.py                  # FGPP queries
│   ├── ad_gmsa.py                  # gMSA queries
│   ├── ad_gpo.py                   # GPO queries & link management
│   ├── ad_group_nesting.py         # Nested group resolution
│   ├── ad_groups.py                # Group CRUD
│   ├── ad_health.py                # FSMO, func levels, DC inventory
│   ├── ad_laps.py                  # LAPS password retrieval
│   ├── ad_ldap_query.py            # Custom LDAP query execution
│   ├── ad_lockout.py               # Lockout policy & status
│   ├── ad_orgchart.py              # Manager hierarchy queries
│   ├── ad_ous.py                   # OU CRUD
│   ├── ad_photos.py                # thumbnailPhoto read/write
│   ├── ad_recycle.py               # Deleted object queries
│   ├── ad_replication.py           # NTDS replication topology
│   ├── ad_reports.py               # Report data queries
│   ├── ad_schema.py                # Schema class/attribute queries
│   ├── ad_search.py                # Cross-object search
│   ├── ad_service_accounts.py      # Service account detection
│   ├── ad_sites.py                 # Sites & Services queries
│   ├── ad_spn.py                   # SPN read/write
│   ├── ad_token_size.py            # Token size calculation
│   ├── ad_users.py                 # User CRUD
│   ├── app_settings.py             # SQLite settings storage
│   ├── audit.py                    # SQLite audit logging
│   ├── dynamic_groups.py           # SQLite dynamic group rules
│   ├── rbac.py                     # Role & permission checking
│   └── scheduled_reports.py        # SQLite report schedules
│
├── templates/                      # Jinja2 templates
│   ├── base.html                   # Layout with sidebar navigation
│   ├── index.html                  # Landing redirect
│   ├── dashboard.html              # Dashboard with Chart.js
│   ├── partials/
│   │   ├── confirm_modal.html      # Reusable confirmation dialog
│   │   └── flash_messages.html     # Flash message alerts
│   ├── acl/
│   │   └── index.html
│   ├── activity/
│   │   └── index.html
│   ├── ad_health/
│   │   └── index.html
│   ├── attributes/
│   │   ├── index.html
│   │   └── edit.html
│   ├── audit/
│   │   └── log.html
│   ├── auth/
│   │   └── login.html
│   ├── bitlocker/
│   │   ├── index.html
│   │   └── computer.html
│   ├── bulk_attr/
│   │   └── index.html
│   ├── bulk_groups/
│   │   └── index.html
│   ├── computers/
│   │   ├── list.html
│   │   ├── detail.html
│   │   └── create.html
│   ├── delegation/
│   │   ├── index.html
│   │   └── acl.html
│   ├── dns/
│   │   ├── zones.html
│   │   └── records.html
│   ├── dynamic_groups/
│   │   ├── index.html
│   │   ├── form.html
│   │   └── evaluate.html
│   ├── fgpp/
│   │   ├── index.html
│   │   ├── detail.html
│   │   └── effective.html
│   ├── gmsa/
│   │   ├── index.html
│   │   └── detail.html
│   ├── gpo/
│   │   ├── list.html
│   │   └── detail.html
│   ├── group_nesting/
│   │   ├── index.html
│   │   └── circular.html
│   ├── groups/
│   │   ├── list.html
│   │   ├── detail.html
│   │   ├── create.html
│   │   └── edit.html
│   ├── laps/
│   │   ├── index.html
│   │   └── view.html
│   ├── ldap_query/
│   │   └── index.html
│   ├── lockout/
│   │   ├── index.html
│   │   └── detail.html
│   ├── orgchart/
│   │   └── index.html
│   ├── ous/
│   │   └── tree.html
│   ├── photos/
│   │   └── view.html
│   ├── recycle/
│   │   └── list.html
│   ├── replication/
│   │   └── index.html
│   ├── reports/
│   │   ├── password_expiry.html
│   │   ├── privileged.html
│   │   └── stale_objects.html
│   ├── scheduled_reports/
│   │   └── index.html
│   ├── schema/
│   │   └── index.html
│   ├── search/
│   │   └── results.html
│   ├── service_accounts/
│   │   └── index.html
│   ├── settings/
│   │   └── index.html
│   ├── sites/
│   │   └── index.html
│   ├── spn/
│   │   ├── index.html
│   │   └── detail.html
│   ├── token_size/
│   │   └── index.html
│   ├── users/
│   │   ├── list.html
│   │   ├── detail.html
│   │   ├── create.html
│   │   ├── edit.html
│   │   ├── copy.html
│   │   ├── compare.html
│   │   └── bulk.html
│   └── workflows/
│       ├── onboard.html
│       └── offboard.html
│
└── static/
    ├── css/
    │   └── style.css               # Custom styles + dark mode
    └── js/
        ├── app.js                  # Theme toggle, DataTables init, utilities
        └── ou-tree.js              # OU tree interactive behavior
```

### Tech Stack

- **Backend**: Python 3.11, Flask, ldap3
- **Frontend**: Bootstrap 5.3, Font Awesome 6, DataTables, Chart.js (all via CDN)
- **Server**: Gunicorn (4 workers)
- **Database**: SQLite (audit log, scheduled reports, dynamic groups, settings)
- **Auth**: LDAPS (port 636) with NTLM authentication

## Data Persistence

SQLite databases are stored in `/app/data` inside the container. The `docker-compose.yml` maps this to a named volume (`ad_data`) so data survives container restarts:

- `audit.db` — Audit log of all actions
- `scheduled_reports.db` — Saved report schedules
- `dynamic_groups.db` — Dynamic group rule definitions
- `settings.db` — Application settings (overrides env vars)

To back up:

```bash
docker cp ad_tools:/app/data ./backup
```

## Building from Source

```bash
git clone https://github.com/ChrisDFennell/ad-tools.git
cd ad-tools
docker build -t ad-tools .
docker compose up -d
```

## Contributing

Contributions are welcome! Please open an issue or pull request.

## License

[MIT](LICENSE)
