# CLAUDE.md — Oracle EBS Security Audit Scanner

## Project Overview

An open-source Python-based security audit tool for Oracle E-Business Suite R12.x.
Performs **125 security checks** across **11 audit domains** via two modes: live database
connection or offline CSV analysis. Designed for security auditors, IT risk teams,
SOX compliance reviewers, and EBS administrators.

**Repository**: https://github.com/Krishcalin/Oracle-EBS-Security-Audit
**License**: MIT
**Python**: 3.8+
**Version**: 1.2.0

---

## Architecture

### File Structure

```
Oracle-EBS-Security-Audit/
├── oracle_ebs_scanner.py          # Live scanner — connects to Oracle DB (oracledb)
├── oracle_ebs_offline_scanner.py  # Offline scanner — analyzes CSV exports (stdlib only)
├── export_ebs_audit_data.sql      # 34 SQL export queries for offline mode
├── README.md                      # User-facing documentation
├── CLAUDE.md                      # This file — development context
├── LICENSE                        # MIT License
└── banner.svg                     # GitHub banner image
```

### Scanner Architecture

Both scanners share identical class structure:

```
Scanner Class
├── Finding class (__slots__)
│     rule_id, name, category, severity, source, context,
│     description, recommendation, cwe
│
├── Constants (class-level)
│     DEFAULT_ACCOUNTS, SENSITIVE_RESPONSIBILITIES, SOD_CONFLICTS,
│     CRITICAL_AUDIT_TABLES, DANGEROUS_PROGRAMS, DEFAULT_DB_ACCOUNTS,
│     SENSITIVE_PACKAGES, SEVERITY_ORDER, SEVERITY_COLOR
│
├── Connection / Data Loading
│     Live:    connect(), disconnect(), _query(), _scalar(), _count()
│     Offline: load_data(), _load_csv(), _parse_date(), _is_active()
│
├── Helpers
│     _add(), _vprint(), _warn(), _pass(), _get_profile_value()
│     Live:    _gather_instance_info()
│     Offline: _days_ago(), _get_active_users(), _get_active_user_resps(),
│              _get_db_param(), _safe_float()
│
├── scan() — orchestrator calling 11 check groups:
│     ├── _check_users()            — ORA-USER-001..015  (15 checks)
│     ├── _check_passwords()        — ORA-PWD-001..006   (6 checks)
│     ├── _check_profiles()         — ORA-PROF-001..010  (10 checks)
│     ├── _check_responsibilities() — ORA-ROLE-001..006  (6 checks)
│     ├── _check_sod()              — ORA-SOD-001..020   (20 checks)
│     ├── _check_concurrent()       — ORA-CONC-001..010  (10 checks)
│     ├── _check_audit()            — ORA-AUDIT-001..012 (12 checks)
│     ├── _check_database()         — ORA-DB-001..018    (18 checks)
│     ├── _check_patching()         — ORA-PATCH-001..004 (4 checks)
│     ├── _check_workflow()         — ORA-WF-001..004    (4 checks)
│     └── _check_app_config()       — ORA-APP-001..015   (15 checks)
│
├── Reporting
│     summary(), filter_severity(), print_report(),
│     save_json(), save_html()
│
└── CLI (argparse) — main()
```

---

## Audit Check Inventory (125 checks, 11 domains)

### Domain 1: User Account Security (15 checks)
- ORA-USER-001..008 — Default accounts, inactive users, orphans, terminated employees,
  shared accounts, never-logged-in, population summary
- ORA-USER-009 — Self-service registration without approval
- ORA-USER-010 — SSO/MFA not configured (APPS_SSO profile)
- ORA-USER-011 — Recent accounts created without HR link
- ORA-USER-012 — Weak password hash algorithm detection
- ORA-USER-013 — Direct APPS schema login detection
- ORA-USER-014 — SysAdmin users holding financial responsibilities
- ORA-USER-015 — Concurrent login limit not enforced

### Domain 2: Password & Authentication (6 checks)
- ORA-PWD-001..006 — Password age, failed login limits, length, complexity, reuse

### Domain 3: Profile Options (10 checks)
- ORA-PROF-001..010 — Session timeout, guest password, diagnostics, HTTPS enforcement,
  sign-on notification, concurrent sessions, OAF customization, audit level

### Domain 4: Responsibility & Access (6 checks)
- ORA-ROLE-001..006 — Excessive SysAdmin, multi-sensitive, over-assigned, no end date,
  inactive resps, admin menu on custom resps

### Domain 5: Segregation of Duties (20 checks)
- ORA-SOD-001..006 — Original AP/AR, AP/PO, GL/AP, PO/INV, Admin/AP, HR/AP
- ORA-SOD-007..020 — AR/CM, GL/JE, PO/RECV, INV/ADJ, FA/FA, CM/RECON, HR/PAY,
  AP/VENDOR, PO/BUYER, GL/PERIOD, AP/HOLD, OM/AR, PO/GL, Admin/GL

### Domain 6: Concurrent Programs (10 checks)
- ORA-CONC-001..004 — Dangerous programs, host-based, app-level grants, privileged user
- ORA-CONC-005 — Shell/host execution programs
- ORA-CONC-006 — Security-sensitive programs broadly accessible
- ORA-CONC-007 — Concurrent output directory configuration
- ORA-CONC-008 — FNDCPASS/FNDSCARU recent execution audit
- ORA-CONC-009 — Old concurrent output files not purged
- ORA-CONC-010 — ALL-program request groups on active responsibilities

### Domain 7: Audit Trail (12 checks)
- ORA-AUDIT-001..005 — Audit trail enabled, critical table audit, DB audit, sign-on level, retention
- ORA-AUDIT-006 — Profile option change auditing
- ORA-AUDIT-007 — Responsibility assignment change auditing
- ORA-AUDIT-008 — FND_USER modification auditing
- ORA-AUDIT-009 — Unified Audit policies (12c+)
- ORA-AUDIT-010 — 7-year audit log retention compliance
- ORA-AUDIT-011 — Financial table WHO columns populated
- ORA-AUDIT-012 — Concurrent request history retention

### Domain 8: Database Security (18 checks)
- ORA-DB-001..010 — Default accounts, PUBLIC EXECUTE, DBA grants, UTL_FILE_DIR,
  remote_os_authent, DB links, package grants, open accounts, case-sensitive logon,
  password verify function
- ORA-DB-011 — Network encryption (SQLNET.ENCRYPTION_SERVER)
- ORA-DB-012 — O7_DICTIONARY_ACCESSIBILITY enabled
- ORA-DB-013 — SELECT ANY TABLE grants to non-DBA
- ORA-DB-014 — ALTER SYSTEM privilege grants
- ORA-DB-015 — SYSDBA session auditing disabled
- ORA-DB-016 — Database login rate limiting
- ORA-DB-017 — Database Vault status
- ORA-DB-018 — Fine-Grained Auditing policies

### Domain 9: Patching & Versions (4 checks)
- ORA-PATCH-001..004 — EBS version EOL, last patch, DB version, patch frequency

### Domain 10: Workflow & Approvals (4 checks)
- ORA-WF-001..004 — Stuck items, mailer status, error count, background engine

### Domain 11: Application Configuration (15 checks)
- ORA-APP-001 — Document sequencing not enabled (SOX)
- ORA-APP-002 — Users with unlimited financial approval limits
- ORA-APP-003 — No active AP invoice hold codes
- ORA-APP-004 — Too many users with GL period access
- ORA-APP-005 — Critical lookup types not frozen
- ORA-APP-006 — No flexfield security rules defined
- ORA-APP-007 — OA Framework personalization unrestricted
- ORA-APP-008 — Attachments stored on file system
- ORA-APP-009 — No security alerts configured
- ORA-APP-010 — Unregistered web functions detected
- ORA-APP-011 — Multi-Org security profile not configured
- ORA-APP-012 — Unprotected descriptive flexfields on PII tables
- ORA-APP-013 — External self-service modules active
- ORA-APP-014 — XML Gateway trading partners configured
- ORA-APP-015 — Excessive public Integration Repository services

---

## Offline Scanner CSV Files (34 total)

### Required (4)
- `instance_info.csv` — Instance and version metadata
- `ebs_users.csv` — FND_USER accounts with employee status
- `ebs_user_responsibilities.csv` — User-responsibility assignments
- `ebs_profile_options.csv` — Security-relevant profile option values

### Optional — EBS Application (16)
- `ebs_responsibilities.csv` — Responsibility definitions with menus
- `ebs_concurrent_programs.csv` — Enabled concurrent programs
- `ebs_request_group_access.csv` — Request group to program mappings
- `ebs_concurrent_requests.csv` — Recent completed requests
- `ebs_audit_config.csv` — Audit trail table configuration
- `ebs_patches.csv` — Applied patches (AD_BUGS)
- `ebs_workflow_components.csv` — Workflow service component status
- `ebs_workflow_stuck.csv` — Stuck workflow items
- `ebs_workflow_errors.csv` — Workflow error count
- `ebs_login_audit_old.csv` — Old audit record count
- `ebs_logins.csv` — Recent login records
- `ebs_approval_limits.csv` — AP approval limits per user
- `ebs_hold_codes.csv` — AP invoice hold codes
- `ebs_lookup_types.csv` — Lookup type customization levels
- `ebs_flex_rules.csv` — Flexfield security rule usages
- `ebs_alerts.csv` — Oracle Alert definitions

### Optional — EBS Application Configuration (3)
- `ebs_form_functions.csv` — Form function security
- `ebs_dff_config.csv` — Descriptive flexfield config
- `ebs_xml_gateway.csv` — XML Gateway trading partners
- `ebs_irep_services.csv` — Integration Repository services

### Optional — Database (10)
- `db_users.csv` — Database user accounts
- `db_role_privs.csv` — Database role grants
- `db_tab_privs.csv` — Object privilege grants (sensitive packages)
- `db_links.csv` — Database links
- `db_profiles.csv` — Database password/resource profiles
- `db_parameters.csv` — Security-relevant init parameters
- `db_sys_privs.csv` — Database system privilege grants
- `db_dv_status.csv` — Database Vault status
- `db_fga_policies.csv` — Fine-Grained Audit policies
- `db_unified_audit.csv` — Unified Audit enabled policies

---

## Key Tables & Views Queried

### EBS Application Tables
```
FND_USER, FND_USER_RESP_GROUPS_DIRECT, FND_RESPONSIBILITY, FND_RESPONSIBILITY_TL,
FND_PROFILE_OPTIONS, FND_PROFILE_OPTION_VALUES, FND_CONCURRENT_PROGRAMS,
FND_CONCURRENT_PROGRAMS_TL, FND_CONCURRENT_REQUESTS, FND_REQUEST_GROUPS,
FND_REQUEST_GROUP_UNITS, FND_MENUS, FND_LOGINS, FND_LOGIN_RESP_ACTIONS,
FND_SVC_COMPONENTS, FND_PRODUCT_GROUPS, FND_AUDIT_TABLES, FND_AUDIT_SCHEMAS,
FND_LOOKUP_TYPES, FND_LOOKUP_VALUES, FND_FLEX_VALUE_RULE_USAGES,
FND_FORM_FUNCTIONS, FND_MENU_ENTRIES, FND_DESCRIPTIVE_FLEXS, FND_IREP_CLASSES,
WF_ITEMS, WF_ITEM_ACTIVITY_STATUSES, AD_BUGS, PER_ALL_PEOPLE_F,
AP_APPROVAL_LIMITS, AP_HOLD_CODES, ALR_ALERTS, ECX_TP_HEADERS,
AP_INVOICES_ALL
```

### Database Dictionary Views
```
V$PARAMETER, V$VERSION, V$INSTANCE,
DBA_USERS, DBA_ROLE_PRIVS, DBA_TAB_PRIVS, DBA_DB_LINKS, DBA_PROFILES,
DBA_SYS_PRIVS, DBA_DV_STATUS, DBA_AUDIT_POLICIES,
AUDIT_UNIFIED_ENABLED_POLICIES
```

---

## Compliance Framework Mapping

| Framework | Covered Domains |
|-----------|----------------|
| **SOX** | SoD (20 pairs), document sequencing, approval limits, audit trail, period controls |
| **CIS Oracle DB Benchmark** | DB hardening, password policies, PUBLIC privileges, audit config, encryption |
| **NIST 800-53** | AC (Access), AU (Audit), IA (Auth), CM (Config), SC (System/Comms) |
| **PCI-DSS v4.0** | Req 2 (defaults), Req 7 (access), Req 8 (auth), Req 10 (audit) |
| **HIPAA** | Access controls, audit controls, person authentication |
| **ISO 27001** | A.9 Access Control, A.12 Operations Security, A.18 Compliance |
| **DISA STIG** | DB parameters, audit config, authentication, encryption |

---

## Development Phases

### Phase 1 — Foundation (v1.0.0, COMPLETE)
- [x] 68 checks across 10 domains
- [x] Live scanner with oracledb
- [x] Offline scanner with CSV (zero dependencies)
- [x] HTML/JSON/Console reporting
- [x] CWE mapping, severity filtering, CI/CD exit codes

### Phase 2 — Deepening + Application Configuration (v1.2.0, COMPLETE)
- [x] 42 new checks deepening existing categories (User, SoD, DB, Audit, Concurrent)
- [x] 15 new checks in new Application Configuration domain
- [x] 14 additional SQL export queries (34 total CSV files)
- [x] 20 SoD conflict pairs (was 6)

### Phase 3 — Data Privacy & PII Protection (PLANNED)
- [ ] 10 checks: PII inventory, PII access grants, credit card data, SSN protection,
      non-prod masking, data retention, FGA on PII, BI Publisher reports, data extracts,
      PER_ALL_PEOPLE_F access breadth

### Phase 4 — Custom Code Security (PLANNED)
- [ ] 10 checks: PL/SQL injection, hardcoded credentials, CUSTOM.pll review,
      FND_USER_PKG misuse, custom concurrent programs, FNDLOAD scripts,
      custom triggers on security tables, synonym/grant bypasses

### Phase 5 — Infrastructure & Middleware (PLANNED)
- [ ] 10 checks: TLS enforcement, WebLogic hardening, HTTP directory listing,
      diagnostic pages, context file permissions, JDK compliance,
      server signature disclosure, default credentials, file permissions

### Phase 6 — Formal Compliance Mapping & Reporting (PLANNED)
- [ ] Per-check SOX/PCI/STIG/CIS/NIST/HIPAA/GDPR mapping
- [ ] Compliance score per framework
- [ ] CSV export for GRC tools
- [ ] Risk scoring (likelihood x impact)
- [ ] Trend tracking (scan-over-scan comparison)

---

## Coding Conventions

- Python 3.8+ (no walrus operator for compatibility)
- Single-file architecture per scanner (no imports beyond stdlib + oracledb)
- `Finding` class uses `__slots__` for memory efficiency
- All findings carry `rule_id`, `severity`, `cwe`, `recommendation`
- Checks that fail silently (missing access/table) use `_vprint()` for verbose-only notice
- Offline scanner gracefully skips checks when CSV files are absent
- Both scanners must stay in sync — same rule IDs, same logic, same Finding text
- SQL export queries in `export_ebs_audit_data.sql` must match offline scanner expectations exactly

---

## Running the Tool

```bash
# ── Live scanner ─────────────────────────────────────────────────
python oracle_ebs_scanner.py --host dbhost --service EBSPROD --user APPS
python oracle_ebs_scanner.py --dsn "host:1521/SVC" --user APPS --json r.json --html r.html

# ── Offline scanner ──────────────────────────────────────────────
python oracle_ebs_offline_scanner.py ./csv_dir/
python oracle_ebs_offline_scanner.py ./csv_dir/ --json r.json --html r.html --severity HIGH

# ── Environment variables ────────────────────────────────────────
export ORA_HOST=dbhost ORA_SERVICE=EBSPROD ORA_USER=APPS ORA_PASSWORD=secret
python oracle_ebs_scanner.py --json report.json
```
