# Oracle E-Business Suite Security Audit Scanner

<p align="center">
  <img src="banner.svg" alt="Oracle EBS Security Audit Scanner" width="100%">
</p>

<p align="center">
  <strong>Open-source Python security audit tool for Oracle E-Business Suite R12.x</strong><br>
  68 checks across 10 security domains &bull; Live DB + Offline CSV modes &bull; JSON + HTML + Console reports
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#check-categories">Check Categories</a> &bull;
  <a href="#output-formats">Output</a> &bull;
  <a href="#required-privileges">Privileges</a> &bull;
  <a href="#compliance-mapping">Compliance</a>
</p>

---

## Overview

Two single-file Python scanners that perform **68 security audit checks** across user access, segregation of duties, profile options, database hardening, patching, workflow controls, and more. Choose **Live** mode (direct database connection) or **Offline** mode (analyze CSV exports). Designed for security auditors, IT risk teams, and EBS administrators.

| Scanner | Mode | Lines | Dependency |
|---------|------|------:|------------|
| `oracle_ebs_scanner.py` | Live DB (oracledb) | ~2,330 | `oracledb` |
| `oracle_ebs_offline_scanner.py` | Offline CSV | ~2,090 | None (stdlib) |
| `export_ebs_audit_data.sql` | SQL export queries | ~356 | — |

- **68 checks** across 10 categories
- **Python 3.8+**, MIT License

---

## Quick Start

```bash
# Install dependency
pip install oracledb

# Run with Easy Connect syntax
python oracle_ebs_scanner.py \
    --host dbhost.example.com \
    --port 1521 \
    --service EBSPROD \
    --user APPS

# Run with DSN string + all output formats
python oracle_ebs_scanner.py \
    --dsn "dbhost:1521/EBSPROD" \
    --user APPS \
    --json report.json \
    --html report.html \
    --severity MEDIUM

# Using environment variables
export ORA_HOST=dbhost ORA_SERVICE=EBSPROD ORA_USER=APPS ORA_PASSWORD=secret
python oracle_ebs_scanner.py --json report.json
```

The password is prompted securely if not provided via `--password` or `ORA_PASSWORD`.

---

## CLI Reference

```
usage: oracle_ebs_scanner [-h] [--host HOST] [--port PORT] [--service SERVICE]
                          [--dsn DSN] [--user USER] [--password PASS]
                          [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                          [--json FILE] [--html FILE] [--verbose] [--version]

Options:
  --host HOST          Database hostname (env: ORA_HOST)
  --port PORT          Database port, default 1521 (env: ORA_PORT)
  --service SERVICE    Database service name (env: ORA_SERVICE)
  --dsn DSN            Full DSN "host:port/service" (env: ORA_DSN)
  --user, -u USER      Database username, typically APPS (env: ORA_USER)
  --password, -p PASS  Database password, prompted if omitted (env: ORA_PASSWORD)
  --severity SEV       Minimum severity to report (default: INFO)
  --json FILE          Save JSON report
  --html FILE          Save HTML report (self-contained, filterable)
  --verbose, -v        Show passed checks, SQL details
  --version            Show version and exit
```

**Exit codes:** `1` if any CRITICAL or HIGH findings, `0` otherwise — ready for CI/CD pipeline gating.

---

## Offline Scanner

When direct database access is not available, use the **offline scanner** to analyze CSV exports:

```bash
# Step 1: DBA runs export queries and saves each result as CSV
#         (use SQL*Plus, SQLcl, SQL Developer, Toad, or DBeaver)
sqlplus APPS/password@EBSPROD @export_ebs_audit_data.sql

# Step 2: Place all CSV files in a directory
ls ebs_export/
# instance_info.csv  ebs_users.csv  ebs_user_responsibilities.csv  ...

# Step 3: Run the offline scanner (zero dependencies)
python oracle_ebs_offline_scanner.py ./ebs_export/
python oracle_ebs_offline_scanner.py ./ebs_export/ \
    --json report.json --html report.html --severity HIGH

# Optional: specify the export date for accurate age calculations
python oracle_ebs_offline_scanner.py ./ebs_export/ --ref-date 2025-01-15
```

### Required CSV files (4)
`instance_info.csv`, `ebs_users.csv`, `ebs_user_responsibilities.csv`, `ebs_profile_options.csv`

### Optional CSV files (16)
`ebs_responsibilities.csv`, `ebs_concurrent_programs.csv`, `ebs_request_group_access.csv`, `ebs_concurrent_requests.csv`, `ebs_audit_config.csv`, `ebs_patches.csv`, `ebs_workflow_components.csv`, `ebs_workflow_stuck.csv`, `ebs_workflow_errors.csv`, `ebs_login_audit_old.csv`, `db_users.csv`, `db_role_privs.csv`, `db_tab_privs.csv`, `db_links.csv`, `db_profiles.csv`, `db_parameters.csv`

> Checks are skipped gracefully when optional CSV files are absent.

---

## Check Categories

### 1. User Account Security (`ORA-USER-001` .. `008`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-USER-001 | HIGH | Default/seeded accounts (SYSADMIN, GUEST, etc.) still active |
| ORA-USER-002 | MEDIUM | Inactive users (no login > 90 days) not disabled |
| ORA-USER-003 | LOW | Users without end date set |
| ORA-USER-004 | MEDIUM | Orphan accounts with no employee/person link |
| ORA-USER-005 | CRITICAL | Terminated employees with active EBS accounts |
| ORA-USER-006 | HIGH | Shared or generic accounts detected |
| ORA-USER-007 | LOW | Users created > 30 days ago who never logged in |
| ORA-USER-008 | INFO | Active user population summary |

### 2. Password & Authentication (`ORA-PWD-001` .. `006`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-PWD-001 | HIGH | Password never changed since account creation |
| ORA-PWD-002 | MEDIUM | Passwords older than 90 days |
| ORA-PWD-003 | CRITICAL | Failed login limit not configured or too high |
| ORA-PWD-004 | HIGH | Minimum password length not set or < 8 |
| ORA-PWD-005 | HIGH | Password complexity (hard-to-guess) not enforced |
| ORA-PWD-006 | MEDIUM | Password reuse not prevented |

### 3. Profile Options (`ORA-PROF-001` .. `010`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-PROF-001 | MEDIUM | Session timeout (ICX_SESSION_TIMEOUT) not set or > 60 min |
| ORA-PROF-002 | HIGH | Guest user password contains default value |
| ORA-PROF-003 | MEDIUM | FND_DIAGNOSTICS enabled in production |
| ORA-PROF-004 | LOW | Application framework logging enabled |
| ORA-PROF-005 | HIGH | APPS_SERVLET_AGENT not using HTTPS |
| ORA-PROF-006 | HIGH | APPS_FRAMEWORK_AGENT not using HTTPS |
| ORA-PROF-007 | LOW | Sign-on notification disabled |
| ORA-PROF-008 | MEDIUM | Concurrent session limit not set |
| ORA-PROF-009 | LOW | OA Framework customization enabled |
| ORA-PROF-010 | MEDIUM | Sign-on audit level not configured or too low |

### 4. Responsibility & Access (`ORA-ROLE-001` .. `006`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-ROLE-001 | CRITICAL | Excessive System Administrator users (> 3) |
| ORA-ROLE-002 | HIGH | Users with 3+ sensitive responsibilities |
| ORA-ROLE-003 | varies | Sensitive responsibility assigned to too many users |
| ORA-ROLE-004 | LOW | Responsibility assignments without end date |
| ORA-ROLE-005 | MEDIUM | Inactive (end-dated) responsibilities still assigned to users |
| ORA-ROLE-006 | HIGH | Custom responsibilities with system admin menus |

### 5. Segregation of Duties (`ORA-SOD-001` .. `006`)

| Check | Severity | Conflict |
|-------|----------|----------|
| ORA-SOD-001 | HIGH | Accounts Payable + Accounts Receivable |
| ORA-SOD-002 | HIGH | Accounts Payable + Purchasing |
| ORA-SOD-003 | HIGH | General Ledger + Accounts Payable |
| ORA-SOD-004 | HIGH | Purchasing + Inventory |
| ORA-SOD-005 | HIGH | System Administrator + Accounts Payable |
| ORA-SOD-006 | HIGH | Human Resources + Accounts Payable |

### 6. Concurrent Programs (`ORA-CONC-001` .. `004`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-CONC-001 | HIGH | Dangerous programs (FNDCPASS, FNDLOAD, etc.) in non-admin groups |
| ORA-CONC-002 | MEDIUM | Host-based concurrent programs enabled (OS execution) |
| ORA-CONC-003 | MEDIUM | Application-level request group grants (unrestricted) |
| ORA-CONC-004 | MEDIUM | Programs submitted under privileged accounts |

### 7. Audit Trail (`ORA-AUDIT-001` .. `005`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-AUDIT-001 | CRITICAL | EBS AuditTrail (AUDITTRAIL:ACTIVATE) not enabled |
| ORA-AUDIT-002 | HIGH | Critical tables not in active audit schema (13 tables checked) |
| ORA-AUDIT-003 | HIGH | Database-level auditing (audit_trail parameter) disabled |
| ORA-AUDIT-004 | MEDIUM | Sign-on audit level insufficient for user tracking |
| ORA-AUDIT-005 | LOW | Audit data older than 1 year needs archival review |

**Critical tables audited:** `FND_USER`, `FND_USER_RESP_GROUPS_DIRECT`, `AP_CHECKS_ALL`, `AP_INVOICES_ALL`, `AP_INVOICE_DISTRIBUTIONS_ALL`, `GL_JE_HEADERS`, `GL_JE_LINES`, `PO_HEADERS_ALL`, `PO_REQUISITION_HEADERS_ALL`, `AR_CASH_RECEIPTS_ALL`, `MTL_MATERIAL_TRANSACTIONS`, `PER_ALL_PEOPLE_F`, `PAY_ELEMENT_ENTRIES_F`

### 8. Database Security (`ORA-DB-001` .. `010`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-DB-001 | HIGH | Default database accounts (SYS, SCOTT, etc.) not locked |
| ORA-DB-002 | HIGH | PUBLIC role has EXECUTE on sensitive packages (UTL_FILE, etc.) |
| ORA-DB-003 | CRITICAL | Excessive DBA role grants to non-system schemas |
| ORA-DB-004 | CRITICAL/MEDIUM | UTL_FILE_DIR parameter set too broadly |
| ORA-DB-005 | CRITICAL | Remote OS authentication enabled |
| ORA-DB-006 | MEDIUM | Database links with potential embedded credentials |
| ORA-DB-007 | MEDIUM | Sensitive package EXECUTE grants to non-DBA schemas |
| ORA-DB-008 | MEDIUM | Excessive open (unlocked) non-EBS database accounts |
| ORA-DB-009 | MEDIUM | Case-sensitive logon disabled |
| ORA-DB-010 | HIGH | PASSWORD_VERIFY_FUNCTION not set in DEFAULT profile |

### 9. Patching & Versions (`ORA-PATCH-001` .. `004`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-PATCH-001 | CRITICAL/HIGH/INFO | EBS version end-of-life / support status |
| ORA-PATCH-002 | INFO/HIGH | Last applied patch and date |
| ORA-PATCH-003 | CRITICAL/HIGH/INFO | Database version (11g/12c EOL, 19c+ current) |
| ORA-PATCH-004 | HIGH/INFO | Patch activity in last 6 months |

### 10. Workflow & Approvals (`ORA-WF-001` .. `004`)

| Check | Severity | Description |
|-------|----------|-------------|
| ORA-WF-001 | MEDIUM | Stuck workflow items open > 30 days |
| ORA-WF-002 | MEDIUM | Workflow Notification Mailer not running |
| ORA-WF-003 | MEDIUM | Workflow activity errors in last 30 days |
| ORA-WF-004 | LOW | Workflow background engine not running |

---

## Output Formats

### Console (default)
Color-coded terminal output with severity indicators, organized by category.

### JSON (`--json report.json`)
```json
{
  "scanner": "oracle_ebs_scanner",
  "version": "1.0.0",
  "generated": "2025-01-15T14:30:00",
  "instance": "EBSPROD",
  "host": "dbhost.example.com",
  "ebs_version": "12.2.11",
  "db_version": "Oracle Database 19c Enterprise Edition",
  "findings_count": 24,
  "summary": {"CRITICAL": 2, "HIGH": 8, "MEDIUM": 10, "LOW": 3, "INFO": 1},
  "findings": [...]
}
```

### HTML (`--html report.html`)
Self-contained HTML report with:
- Catppuccin Mocha dark theme
- Severity and category filter dropdowns
- Full-text search
- Color-coded severity badges
- Expandable issue/fix details per finding

---

## Required Privileges

The scanner requires **read-only** `SELECT` access. Connect as `APPS` (recommended) or a custom audit schema with grants on:

### EBS Application Tables
```
FND_USER, FND_USER_RESP_GROUPS_DIRECT, FND_RESPONSIBILITY,
FND_RESPONSIBILITY_TL, FND_PROFILE_OPTIONS, FND_PROFILE_OPTION_VALUES,
FND_CONCURRENT_PROGRAMS, FND_CONCURRENT_PROGRAMS_TL,
FND_CONCURRENT_REQUESTS, FND_REQUEST_GROUPS, FND_REQUEST_GROUP_UNITS,
FND_MENUS, FND_LOGINS, FND_LOGIN_RESP_ACTIONS, FND_SVC_COMPONENTS,
FND_PRODUCT_GROUPS, FND_AUDIT_TABLES, FND_AUDIT_SCHEMAS,
WF_ITEMS, WF_ITEM_ACTIVITY_STATUSES, AD_BUGS,
PER_ALL_PEOPLE_F (optional — for terminated employee check)
```

### Database Dictionary Views
```
V$PARAMETER, V$VERSION, V$INSTANCE,
DBA_USERS, DBA_ROLE_PRIVS, DBA_TAB_PRIVS, DBA_DB_LINKS, DBA_PROFILES
```

> **Note:** If the connecting user lacks access to specific views (e.g., `DBA_*`), those checks will be skipped gracefully with a verbose-mode message.

---

## Compliance Mapping

| Framework | Covered Domains |
|-----------|----------------|
| **SOX (Sarbanes-Oxley)** | SoD controls, access reviews, audit trail, approval workflows |
| **CIS Oracle Database Benchmark** | DB hardening, password policies, PUBLIC privileges, audit config |
| **NIST 800-53** | AC (Access Control), AU (Audit), IA (Identification & Auth), CM (Config Mgmt) |
| **PCI-DSS v4.0** | Req 7 (access control), Req 8 (authentication), Req 10 (audit logging) |
| **HIPAA** | Access controls, audit controls, person authentication |
| **ISO 27001** | A.9 Access Control, A.12 Operations Security, A.18 Compliance |

---

## Architecture

```
oracle_ebs_scanner.py
│
├── Finding class (__slots__)
│     rule_id, name, category, severity, source, context,
│     description, recommendation, cwe
│
├── OracleEBSScanner class
│     ├── connect() / disconnect()       — oracledb connection
│     ├── _query() / _scalar() / _count() — SQL helpers
│     ├── _get_profile_value()           — FND profile lookup
│     ├── scan()                         — orchestrator
│     │     ├── _check_users()           — 8 checks (FND_USER)
│     │     ├── _check_passwords()       — 6 checks (FND_USER + profiles)
│     │     ├── _check_profiles()        — 10 checks (FND_PROFILE_*)
│     │     ├── _check_responsibilities()— 6 checks (FND_USER_RESP_GROUPS)
│     │     ├── _check_sod()             — 6 checks (SoD conflict pairs)
│     │     ├── _check_concurrent()      — 4 checks (FND_CONCURRENT_*)
│     │     ├── _check_audit()           — 5 checks (FND_AUDIT_*, V$PARAM)
│     │     ├── _check_database()        — 10 checks (DBA_* views)
│     │     ├── _check_patching()        — 4 checks (AD_BUGS, V$VERSION)
│     │     └── _check_workflow()        — 4 checks (WF_ITEMS, FND_SVC)
│     ├── summary() / filter_severity()
│     ├── print_report()                 — console output
│     ├── save_json()                    — JSON export
│     └── save_html()                    — HTML report (Catppuccin Mocha)
│
└── CLI (argparse)
      --host/--port/--service or --dsn
      --user/--password (env var support)
      --json/--html/--severity/--verbose/--version
```

---

## Rule ID Convention

```
ORA-{CATEGORY}-{NNN}

Categories:
  USER   — User Account Security
  PWD    — Password & Authentication
  PROF   — Profile Options
  ROLE   — Responsibility & Access
  SOD    — Segregation of Duties
  CONC   — Concurrent Programs
  AUDIT  — Audit Trail
  DB     — Database Security
  PATCH  — Patching & Versions
  WF     — Workflow & Approvals
```

---

## CWE Coverage

The scanner maps findings to the following CWE identifiers:

| CWE | Description | Checks |
|-----|-------------|--------|
| CWE-250 | Execution with Unnecessary Privileges | ORA-CONC-004 |
| CWE-262 | Not Using Password Aging | ORA-PWD-002 |
| CWE-269 | Improper Privilege Management | ORA-ROLE-001/002/003/006, ORA-CONC-001/003, ORA-DB-002/003/007 |
| CWE-284 | Improper Access Control | ORA-USER-002/003, ORA-ROLE-004, ORA-SOD-*, ORA-WF-001 |
| CWE-285 | Improper Authorization | ORA-USER-002/005 |
| CWE-287 | Improper Authentication | ORA-USER-006, ORA-DB-005 |
| CWE-307 | Improper Restriction of Excessive Auth Attempts | ORA-PWD-003 |
| CWE-319 | Cleartext Transmission | ORA-PROF-005/006 |
| CWE-400 | Uncontrolled Resource Consumption | ORA-PROF-008 |
| CWE-521 | Weak Password Requirements | ORA-PWD-001/004/005/006, ORA-DB-009/010 |
| CWE-522 | Insufficiently Protected Credentials | ORA-DB-006 |
| CWE-532 | Insertion of Sensitive Info into Log File | ORA-PROF-004 |
| CWE-613 | Insufficient Session Expiration | ORA-PROF-001 |
| CWE-732 | Incorrect Permission Assignment | ORA-DB-004 |
| CWE-778 | Insufficient Logging | ORA-PROF-010, ORA-AUDIT-001/002/003/004 |
| CWE-798 | Use of Hard-coded Credentials | ORA-USER-001, ORA-PROF-002, ORA-DB-001 |
| CWE-1104 | Use of Unmaintained Third-Party Components | ORA-PATCH-004 |

---

## Environment Variables

| Variable | Description | CLI Equivalent |
|----------|-------------|---------------|
| `ORA_HOST` | Database hostname | `--host` |
| `ORA_PORT` | Database port (default: 1521) | `--port` |
| `ORA_SERVICE` | Database service name | `--service` |
| `ORA_DSN` | Full DSN string | `--dsn` |
| `ORA_USER` | Database username | `--user` |
| `ORA_PASSWORD` | Database password | `--password` |

---

## Related Projects

| Project | Description |
|---------|-------------|
| [Static-Application-Security-Testing](https://github.com/Krishcalin/Static-Application-Security-Testing) | Java, PHP, Python, MERN, LLM SAST scanners |
| [AWS-Security-Scanner](https://github.com/Krishcalin/AWS-Security-Scanner) | CloudFormation + Terraform IaC scanner |
| [SAP-SuccessFactors](https://github.com/Krishcalin/SAP-SuccessFactors) | SAP SuccessFactors SSPM scanner |
| [SSPM-ServiceNow](https://github.com/Krishcalin/SSPM-ServiceNow) | ServiceNow SSPM scanner |
| [SAP-Code-Vulnerability-Analyzer](https://github.com/Krishcalin/SAP-Code-Vulnerability-Analyzer) | SAP ABAP/BTP SAST scanner |
| [Kubernetes-KSPM](https://github.com/Krishcalin/Kubernetes-Security-Posture-Management) | Kubernetes security posture management |

---

## License

MIT License - see [LICENSE](LICENSE) for details.
