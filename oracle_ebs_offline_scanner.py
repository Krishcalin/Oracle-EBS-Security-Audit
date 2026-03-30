#!/usr/bin/env python3
"""
Oracle E-Business Suite Offline Security Audit Scanner v1.2.0

Analyzes CSV exports from Oracle EBS databases without requiring live
database access.  Same 125 checks as the online scanner, zero dependencies.

Usage:
    1. Run the SQL queries in  export_ebs_audit_data.sql  against your EBS
       database and save each result set as the named CSV file.
    2. Place all CSV files in one directory.
    3. Run:  python oracle_ebs_offline_scanner.py /path/to/csv_dir

Copyright (c) 2025 — MIT License
"""

import argparse
import csv
import datetime
import html as html_mod
import json
import os
import sys
import textwrap

__version__ = "1.2.0"
VERSION = __version__

# ─────────────────────────────────────────────────────────────────────────
# CSV file definitions
# ─────────────────────────────────────────────────────────────────────────

# (filename, required?, description)
CSV_FILES = [
    ("instance_info.csv",            True,  "Instance & version metadata"),
    ("ebs_users.csv",                True,  "EBS user accounts"),
    ("ebs_user_responsibilities.csv",True,  "User-responsibility assignments"),
    ("ebs_profile_options.csv",      True,  "Security profile option values"),
    ("ebs_responsibilities.csv",     False, "Responsibility definitions"),
    ("ebs_concurrent_programs.csv",  False, "Concurrent program list"),
    ("ebs_request_group_access.csv", False, "Request group → program mapping"),
    ("ebs_concurrent_requests.csv",  False, "Recent concurrent requests"),
    ("ebs_audit_config.csv",         False, "Audit trail table config"),
    ("ebs_patches.csv",              False, "Applied patches (AD_BUGS)"),
    ("ebs_workflow_components.csv",  False, "Workflow component status"),
    ("ebs_workflow_stuck.csv",       False, "Stuck workflow items"),
    ("ebs_workflow_errors.csv",      False, "Workflow error count"),
    ("ebs_login_audit_old.csv",      False, "Old audit record count"),
    ("db_users.csv",                 False, "Database user accounts"),
    ("db_role_privs.csv",            False, "Database role grants"),
    ("db_tab_privs.csv",             False, "Database object privileges"),
    ("db_links.csv",                 False, "Database links"),
    ("db_profiles.csv",              False, "Database password profiles"),
    ("db_parameters.csv",            False, "Database init parameters"),
    # Phase 1 additions
    ("ebs_logins.csv",               False, "Recent EBS login records"),
    ("db_sys_privs.csv",             False, "Database system privileges"),
    ("db_dv_status.csv",             False, "Database Vault status"),
    ("db_fga_policies.csv",          False, "Fine-Grained Audit policies"),
    ("db_unified_audit.csv",         False, "Unified Audit policy list"),
    # Phase 2 additions — Application Configuration
    ("ebs_approval_limits.csv",      False, "AP approval limits per user"),
    ("ebs_hold_codes.csv",           False, "AP invoice hold codes"),
    ("ebs_lookup_types.csv",         False, "Lookup type customization levels"),
    ("ebs_flex_rules.csv",           False, "Flexfield security rule usages"),
    ("ebs_alerts.csv",               False, "Oracle Alert definitions"),
    ("ebs_form_functions.csv",       False, "Form function security"),
    ("ebs_dff_config.csv",           False, "Descriptive flexfield config"),
    ("ebs_xml_gateway.csv",          False, "XML Gateway trading partners"),
    ("ebs_irep_services.csv",        False, "Integration Repository services"),
]


# ─────────────────────────────────────────────────────────────────────────
# Finding
# ─────────────────────────────────────────────────────────────────────────

class Finding:
    __slots__ = (
        "rule_id", "name", "category", "severity", "source",
        "context", "description", "recommendation", "cwe",
    )

    def __init__(self, rule_id, name, category, severity, source,
                 context, description, recommendation, cwe=""):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.source = source
        self.context = context
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe

    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}


# ─────────────────────────────────────────────────────────────────────────
# Offline Scanner
# ─────────────────────────────────────────────────────────────────────────

class OracleEBSOfflineScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[84m",
        "LOW":      "\033[92m",
        "INFO":     "\033[97m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    DEFAULT_ACCOUNTS = {
        "SYSADMIN", "GUEST", "OPERATIONS", "INITIAL_SETUP",
        "ANONYMOUS", "AUTOINSTALL", "WIZARD", "IBEGUEST",
        "ASADMIN", "ASGADMIN", "FEEDER SYSTEM",
        "IRC_EMP_GUEST", "IRC_EXT_GUEST", "SYSADMIN1",
    }

    SENSITIVE_RESPONSIBILITIES = {
        "System Administrator":       "CRITICAL",
        "Application Developer":      "HIGH",
        "Functional Administrator":   "HIGH",
        "Security":                   "HIGH",
        "Payables Manager":           "HIGH",
        "Receivables Manager":        "HIGH",
        "General Ledger Super User":  "HIGH",
        "Purchasing Super User":      "HIGH",
        "Human Resources":            "HIGH",
        "US Super HRMS Manager":      "HIGH",
        "Inventory Super User":       "MEDIUM",
        "Order Management Super User":"MEDIUM",
        "Cash Management Super User": "MEDIUM",
        "Fixed Assets Manager":       "MEDIUM",
        "Projects Super User":        "MEDIUM",
    }

    SOD_CONFLICTS = [
        ("Payable",        "Receivable",      "AP/AR",
         "Can create payable invoices and receive AR payments"),
        ("Payable",        "Purchasing",       "AP/PO",
         "Can create POs and approve AP invoices"),
        ("General Ledger", "Payable",          "GL/AP",
         "Can post journals and manage payables"),
        ("Purchasing",     "Inventory",        "PO/INV",
         "Can order goods and receive inventory"),
        ("System Admin",   "Payable",          "Admin/AP",
         "Can create users and process payments"),
        ("Human Resource", "Payable",          "HR/AP",
         "Can maintain employees and process payments"),
        # ── Phase 1 additions ────────────────────────────────────────
        ("Receivable",     "Cash Management",  "AR/CM",
         "Can create customer receipts and reconcile bank statements"),
        ("General Ledger", "Journal",          "GL/JE",
         "Can create and post journal entries without independent review"),
        ("Purchasing",     "Receiving",        "PO/RECV",
         "Can create purchase orders and confirm receipt of goods"),
        ("Inventory",      "Adjust",           "INV/ADJ",
         "Can adjust inventory quantities and approve adjustments"),
        ("Fixed Asset",    "Fixed Asset",      "FA/FA",
         "Can add assets and retire or transfer them"),
        ("Cash Management","Cash Management",  "CM/RECON",
         "Can enter bank statements and reconcile accounts"),
        ("Human Resource", "Payroll",          "HR/PAY",
         "Can create employees and process payroll runs"),
        ("Payable",        "Supplier",         "AP/VENDOR",
         "Can create vendors and approve supplier payments"),
        ("Purchasing",     "Buyer",            "PO/BUYER",
         "Can act as buyer and approve own purchase orders"),
        ("General Ledger", "Period",           "GL/PERIOD",
         "Can open/close accounting periods and post journals"),
        ("Payable",        "Hold",             "AP/HOLD",
         "Can place and release invoice holds and approve payments"),
        ("Order Management","Receivable",      "OM/AR",
         "Can enter sales orders and post receivable receipts"),
        ("Purchasing",     "General Ledger",   "PO/GL",
         "Can create purchasing commitments and post GL journals"),
        ("System Admin",   "General Ledger",   "Admin/GL",
         "Can administer system and post financial transactions"),
    ]

    CRITICAL_AUDIT_TABLES = [
        "FND_USER", "FND_USER_RESP_GROUPS_DIRECT",
        "AP_CHECKS_ALL", "AP_INVOICES_ALL", "AP_INVOICE_DISTRIBUTIONS_ALL",
        "GL_JE_HEADERS", "GL_JE_LINES",
        "PO_HEADERS_ALL", "PO_REQUISITION_HEADERS_ALL",
        "AR_CASH_RECEIPTS_ALL", "MTL_MATERIAL_TRANSACTIONS",
        "PER_ALL_PEOPLE_F", "PAY_ELEMENT_ENTRIES_F",
    ]

    CRITICAL_AUDIT_TABLE_DESC = {
        "FND_USER": "User account master",
        "FND_USER_RESP_GROUPS_DIRECT": "User-responsibility assignments",
        "AP_CHECKS_ALL": "AP payment checks",
        "AP_INVOICES_ALL": "AP invoices",
        "AP_INVOICE_DISTRIBUTIONS_ALL": "AP invoice distributions",
        "GL_JE_HEADERS": "GL journal headers",
        "GL_JE_LINES": "GL journal lines",
        "PO_HEADERS_ALL": "Purchase orders",
        "PO_REQUISITION_HEADERS_ALL": "Purchase requisitions",
        "AR_CASH_RECEIPTS_ALL": "AR cash receipts",
        "MTL_MATERIAL_TRANSACTIONS": "Inventory transactions",
        "PER_ALL_PEOPLE_F": "Employee master",
        "PAY_ELEMENT_ENTRIES_F": "Payroll element entries",
    }

    DANGEROUS_PROGRAMS = {
        "FNDCPASS", "FNDSLOAD", "FNDLOAD", "WFLOAD", "CONCSUB",
        "FNDSCARU", "FNDMDGEN", "AABORDFR", "XLOLOAD",
    }

    DEFAULT_DB_ACCOUNTS = {
        "SYS", "SYSTEM", "DBSNMP", "SCOTT", "OUTLN", "MDSYS",
        "ORDSYS", "CTXSYS", "DSSYS", "PERFSTAT", "WKPROXY",
        "WKSYS", "WK_TEST", "XDB", "WMSYS", "DIP", "EXFSYS",
    }

    SENSITIVE_PACKAGES = {
        "UTL_FILE", "UTL_HTTP", "UTL_SMTP", "UTL_TCP", "UTL_INADDR",
        "DBMS_SQL", "DBMS_JAVA", "DBMS_BACKUP_RESTORE",
        "DBMS_SYS_SQL", "DBMS_RANDOM", "DBMS_LOB",
        "DBMS_ADVISOR", "DBMS_OBFUSCATION_TOOLKIT",
    }

    # ─────────────────────────────────────────────────────────────────
    # Init
    # ─────────────────────────────────────────────────────────────────

    def __init__(self, data_dir, verbose=False, ref_date=None):
        self.data_dir = os.path.abspath(data_dir)
        self.verbose = verbose
        self.ref_date = ref_date or datetime.date.today()
        self.findings: list = []
        self._data: dict = {}
        self._ebs_version = ""
        self._db_version = ""
        self._instance_name = ""
        self._host_name = ""

    # ─────────────────────────────────────────────────────────────────
    # CSV loading
    # ─────────────────────────────────────────────────────────────────

    def _load_csv(self, filename):
        """Load a CSV file and return list of dicts.  Returns [] if missing."""
        path = os.path.join(self.data_dir, filename)
        if not os.path.isfile(path):
            self._vprint(f"  File not found (skipped): {filename}")
            return []
        rows = []
        try:
            with open(path, "r", encoding="utf-8-sig", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    cleaned = {}
                    for k, v in row.items():
                        key = k.strip().upper() if k else k
                        val = v.strip() if v else ""
                        if val.upper() in ("NULL", "NONE", ""):
                            val = ""
                        cleaned[key] = val
                    rows.append(cleaned)
            self._vprint(f"  Loaded {filename}: {len(rows)} rows")
        except Exception as e:
            self._warn(f"Error reading {filename}: {e}")
        return rows

    def load_data(self):
        """Load all CSV files from the data directory."""
        print(f"[*] Loading data from: {self.data_dir}")
        missing_required = []

        for filename, required, desc in CSV_FILES:
            key = filename.replace(".csv", "")
            self._data[key] = self._load_csv(filename)
            if required and not self._data[key]:
                missing_required.append(filename)

        if missing_required:
            self._warn(
                f"Required CSV file(s) missing: {', '.join(missing_required)}\n"
                "  Run the queries in export_ebs_audit_data.sql to generate them."
            )
            return False

        # Extract instance info
        info = self._data.get("instance_info", [])
        if info:
            row = info[0]
            self._instance_name = row.get("INSTANCE_NAME", "")
            self._host_name = row.get("HOST_NAME", "")
            self._db_version = row.get("DB_VERSION", "")
            self._ebs_version = row.get("EBS_VERSION", "")
            self._vprint(f"  Instance   : {self._instance_name} @ {self._host_name}")
            self._vprint(f"  EBS Release: {self._ebs_version}")
            self._vprint(f"  DB Version : {self._db_version}")

        return True

    # ─────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────

    def _add(self, finding):
        self.findings.append(finding)

    def _vprint(self, msg):
        if self.verbose:
            print(f"  [v] {msg}")

    def _warn(self, msg):
        print(f"  [!] {msg}", file=sys.stderr)

    def _pass(self, check_id, name):
        self._vprint(f"  PASS  {check_id}: {name}")

    def _parse_date(self, s):
        """Parse a date string from CSV.  Returns datetime.date or None."""
        if not s or not s.strip():
            return None
        s = s.strip()
        for fmt in (
            "%Y-%m-%d", "%d-%b-%Y", "%d-%b-%y", "%m/%d/%Y",
            "%Y-%m-%d %H:%M:%S", "%d-%b-%Y %H:%M:%S",
            "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return datetime.datetime.strptime(s, fmt).date()
            except ValueError:
                continue
        return None

    def _is_active(self, row, end_col="END_DATE"):
        """Check if a row's end date is null or in the future."""
        end = row.get(end_col, "")
        if not end:
            return True
        d = self._parse_date(end)
        if d is None:
            return True
        return d > self.ref_date

    def _days_ago(self, date_str):
        """Return number of days between ref_date and date_str, or None."""
        d = self._parse_date(date_str)
        if d is None:
            return None
        return (self.ref_date - d).days

    def _get_profile_value(self, profile_name, level_id="10001"):
        """Get profile option value from loaded data."""
        for row in self._data.get("ebs_profile_options", []):
            if (row.get("PROFILE_OPTION_NAME", "").upper()
                    == profile_name.upper()
                    and row.get("LEVEL_ID", "") == str(level_id)):
                return row.get("PROFILE_OPTION_VALUE", "")
        return ""

    def _get_active_users(self):
        """Return list of active user rows."""
        return [
            u for u in self._data.get("ebs_users", [])
            if self._is_active(u)
        ]

    def _get_active_user_resps(self):
        """Return active user-responsibility rows (both user and resp active)."""
        return [
            r for r in self._data.get("ebs_user_responsibilities", [])
            if self._is_active(r, "USER_END_DATE")
            and self._is_active(r, "RESP_END_DATE")
        ]

    def _safe_float(self, val):
        """Parse a numeric string to float, returning 0 on failure."""
        try:
            return float(val)
        except (ValueError, TypeError):
            return 0.0

    def _get_db_param(self, name):
        """Get database parameter value."""
        for row in self._data.get("db_parameters", []):
            if row.get("NAME", "").lower() == name.lower():
                return row.get("VALUE", "")
        return ""

    # ═════════════════════════════════════════════════════════════════
    # Main scan
    # ═════════════════════════════════════════════════════════════════

    def scan(self):
        """Run all security audit check groups."""
        groups = [
            ("User Account Security",       self._check_users),
            ("Password & Authentication",    self._check_passwords),
            ("Profile Options",              self._check_profiles),
            ("Responsibility & Access",      self._check_responsibilities),
            ("Segregation of Duties",        self._check_sod),
            ("Concurrent Programs",          self._check_concurrent),
            ("Audit Trail",                  self._check_audit),
            ("Database Security",            self._check_database),
            ("Patching & Versions",          self._check_patching),
            ("Workflow & Approvals",         self._check_workflow),
            ("Application Configuration",   self._check_app_config),
        ]

        for name, fn in groups:
            print(f"\n{'─' * 60}")
            print(f"  Checking: {name}")
            print(f"{'─' * 60}")
            try:
                fn()
            except Exception as e:
                self._warn(f"Error in {name}: {e}")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 1 — User Account Security  (ORA-USER-001 .. 008)
    # ═════════════════════════════════════════════════════════════════

    def _check_users(self):
        active_users = self._get_active_users()

        # ORA-USER-001  Default/seeded accounts still active
        defaults = [
            u for u in active_users
            if u.get("USER_NAME", "").upper() in self.DEFAULT_ACCOUNTS
        ]
        if defaults:
            names = ", ".join(u["USER_NAME"] for u in defaults)
            self._add(Finding(
                "ORA-USER-001", "Default accounts still active",
                "User Security", "HIGH",
                "ebs_users.csv", f"Active defaults: {names}",
                f"{len(defaults)} default/seeded EBS account(s) remain active. "
                "These accounts are well-known targets for attackers.",
                "End-date or disable all default EBS accounts that are not "
                "operationally required.",
                "CWE-798",
            ))
        else:
            self._pass("ORA-USER-001", "No active default accounts")

        # ORA-USER-002  Inactive users (no login > 90 days)
        inactive = [
            u for u in active_users
            if u.get("LAST_LOGON_DATE")
            and (self._days_ago(u["LAST_LOGON_DATE"]) or 0) > 90
        ]
        if inactive:
            self._add(Finding(
                "ORA-USER-002", "Inactive users not disabled",
                "User Security", "MEDIUM",
                "ebs_users.csv", f"Inactive > 90 days: {len(inactive)} users",
                f"{len(inactive)} active user(s) have not logged in for "
                "more than 90 days.",
                "Review and end-date accounts that are no longer in use.",
                "CWE-285",
            ))
        else:
            self._pass("ORA-USER-002", "No stale inactive users")

        # ORA-USER-003  Users without end date
        no_end = [
            u for u in self._data.get("ebs_users", [])
            if not u.get("END_DATE")
            and u.get("USER_NAME", "").upper() not in ("SYSADMIN", "AUTOINSTALL")
        ]
        if len(no_end) > 20:
            self._add(Finding(
                "ORA-USER-003", "Users without end date",
                "User Security", "LOW",
                "ebs_users.csv", f"No end date: {len(no_end)} users",
                f"{len(no_end)} user accounts have no end date set.",
                "Set end dates on user accounts aligned with contract or "
                "employment end dates.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-003", "User end-date coverage acceptable")

        # ORA-USER-004  Orphan accounts (no employee link)
        skip = {"SYSADMIN", "GUEST", "AUTOINSTALL", "ANONYMOUS",
                "IBEGUEST", "INITIAL_SETUP", "WIZARD"}
        orphans = [
            u for u in active_users
            if not u.get("EMPLOYEE_ID") and not u.get("PERSON_PARTY_ID")
            and u.get("USER_NAME", "").upper() not in skip
        ]
        if orphans:
            self._add(Finding(
                "ORA-USER-004", "Orphan accounts without employee link",
                "User Security", "MEDIUM",
                "ebs_users.csv", f"Orphan accounts: {len(orphans)}",
                f"{len(orphans)} active user(s) have no link to an employee "
                "or person record.",
                "Link user accounts to HR person records or end-date unneeded "
                "accounts.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-004", "No orphan accounts")

        # ORA-USER-005  Terminated employees with active accounts
        terminated = [
            u for u in active_users
            if u.get("EMPLOYEE_ID")
            and u.get("EMPLOYEE_CURRENT_FLAG", "").upper() not in ("Y", "")
        ]
        # Also catch where flag is explicitly N or null with employee link
        terminated2 = [
            u for u in active_users
            if u.get("EMPLOYEE_ID")
            and u.get("EMPLOYEE_CURRENT_FLAG", "").upper() == "N"
        ]
        terminated = terminated2 if terminated2 else terminated
        if terminated:
            self._add(Finding(
                "ORA-USER-005", "Terminated employees with active accounts",
                "User Security", "CRITICAL",
                "ebs_users.csv",
                f"Terminated but active: {len(terminated)} users",
                f"{len(terminated)} user(s) linked to terminated employees "
                "still have active EBS accounts.",
                "Immediately end-date accounts for terminated employees.",
                "CWE-285",
            ))
        else:
            self._pass("ORA-USER-005", "No terminated employees with active accounts")

        # ORA-USER-006  Shared / generic accounts
        shared = [
            u for u in active_users
            if any(kw in u.get("USER_NAME", "").upper()
                   for kw in ("SHARED", "GENERIC", "TEMPUSER", "TESTUSER"))
            or any(kw in (u.get("DESCRIPTION") or "").upper()
                   for kw in ("SHARED", "GENERIC"))
        ]
        if shared:
            names = ", ".join(u["USER_NAME"] for u in shared[:10])
            self._add(Finding(
                "ORA-USER-006", "Shared or generic accounts detected",
                "User Security", "HIGH",
                "ebs_users.csv", f"Shared/generic: {names}",
                f"{len(shared)} account(s) appear to be shared or generic.",
                "Replace shared accounts with individual named accounts.",
                "CWE-287",
            ))
        else:
            self._pass("ORA-USER-006", "No shared/generic accounts")

        # ORA-USER-007  Users never logged in (created > 30 days ago)
        never = [
            u for u in active_users
            if not u.get("LAST_LOGON_DATE")
            and (self._days_ago(u.get("CREATION_DATE", "")) or 0) > 30
        ]
        if never:
            self._add(Finding(
                "ORA-USER-007", "Users never logged in",
                "User Security", "LOW",
                "ebs_users.csv", f"Never logged in: {len(never)} users",
                f"{len(never)} active account(s) created > 30 days ago have "
                "never been used.",
                "Review and end-date unused accounts.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-007", "No unused never-logged-in accounts")

        # ORA-USER-008  Total active user count
        self._add(Finding(
            "ORA-USER-008", "Active user population summary",
            "User Security", "INFO",
            "ebs_users.csv", f"Total active users: {len(active_users)}",
            f"The EBS instance has {len(active_users)} active user accounts.",
            "Periodically review the user population.",
        ))

        # ORA-USER-009  Self-service registration enabled without controls
        val = self._get_profile_value("SELF_REGISTRATION_ENABLED")
        if val and val.upper() == "Y":
            approval = self._get_profile_value("SELF_REGISTRATION_APPROVAL")
            if not approval or approval.upper() != "Y":
                self._add(Finding(
                    "ORA-USER-009",
                    "Self-service registration enabled without approval",
                    "User Security", "HIGH",
                    "ebs_profile_options.csv",
                    f"SELF_REGISTRATION_ENABLED = Y, APPROVAL = {approval or 'NULL'}",
                    "Self-service user registration is enabled without an "
                    "approval workflow.",
                    "Disable self-service registration or enable the approval "
                    "workflow.",
                    "CWE-284",
                ))
            else:
                self._pass("ORA-USER-009", "Self-service registration has approval")
        else:
            self._pass("ORA-USER-009", "Self-service registration disabled")

        # ORA-USER-010  SSO / External authentication not configured
        val = self._get_profile_value("APPS_SSO")
        if not val or val.upper() == "LOCAL":
            self._add(Finding(
                "ORA-USER-010", "Single Sign-On not configured",
                "User Security", "MEDIUM",
                "ebs_profile_options.csv",
                f"APPS_SSO = {val or 'NULL'}",
                "Oracle EBS is using local authentication instead of SSO/OAM.",
                "Integrate Oracle Access Manager or another SSO provider.",
                "CWE-308",
            ))
        else:
            self._pass("ORA-USER-010", "SSO/External authentication configured")

        # ORA-USER-011  User accounts created recently without HR link
        recent_unlinked = [
            u for u in active_users
            if (self._days_ago(u.get("CREATION_DATE", "")) or 999) <= 30
            and not u.get("EMPLOYEE_ID")
            and not u.get("PERSON_PARTY_ID")
            and u.get("USER_NAME", "").upper() not in skip
        ]
        if recent_unlinked:
            self._add(Finding(
                "ORA-USER-011",
                "Recent accounts created without HR link",
                "User Security", "MEDIUM",
                "ebs_users.csv",
                f"New unlinked accounts (30d): {len(recent_unlinked)}",
                f"{len(recent_unlinked)} user account(s) created in the last "
                "30 days have no link to an employee or person record.",
                "Review recently created accounts and ensure they follow "
                "the approved provisioning workflow.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-011", "Recent accounts properly linked")

        # ORA-USER-012  Password hash algorithm strength
        weak_hash = [
            u for u in active_users
            if u.get("ENCRYPTED_USER_PASSWORD")
            and len(u.get("ENCRYPTED_USER_PASSWORD", "")) < 40
        ]
        if weak_hash:
            self._add(Finding(
                "ORA-USER-012", "Weak password hashes detected",
                "User Security", "HIGH",
                "ebs_users.csv",
                f"Weak hashes: {len(weak_hash)} users",
                f"{len(weak_hash)} active user(s) appear to have passwords "
                "stored with a legacy hash algorithm.",
                "Force password resets for affected users.",
                "CWE-916",
            ))
        else:
            self._pass("ORA-USER-012", "Password hash lengths acceptable")

        # ORA-USER-013  Direct APPS schema login detection
        # (requires ebs_logins.csv — skip if not available)
        logins = self._data.get("ebs_logins", [])
        apps_logins = [
            l for l in logins
            if l.get("LOGIN_NAME", "").upper() == "APPS"
            and (self._days_ago(l.get("START_TIME", "")) or 999) <= 30
        ]
        if apps_logins:
            self._add(Finding(
                "ORA-USER-013", "Direct APPS schema login detected",
                "User Security", "HIGH",
                "ebs_logins.csv",
                f"APPS logins (30d): {len(apps_logins)}",
                f"{len(apps_logins)} direct login(s) using the APPS account "
                "detected in the last 30 days.",
                "Restrict APPS schema access to application tier only.",
                "CWE-250",
            ))
        elif logins:
            self._pass("ORA-USER-013", "No direct APPS logins")
        else:
            self._vprint("  ebs_logins.csv not available, skipping ORA-USER-013")

        # ORA-USER-014  Users with SYSADMIN performing business transactions
        active_resps = self._get_active_user_resps()
        sysadmin_set = set(
            r["USER_NAME"] for r in active_resps
            if r.get("RESPONSIBILITY_NAME") == "System Administrator"
        )
        financial_keywords = ("Payable", "Receivable", "General Ledger",
                              "Purchasing")
        sysadmin_finance = set()
        for r in active_resps:
            if r["USER_NAME"] in sysadmin_set:
                rname = r.get("RESPONSIBILITY_NAME", "")
                if any(kw in rname for kw in financial_keywords):
                    sysadmin_finance.add(r["USER_NAME"])
        if sysadmin_finance:
            names = ", ".join(sorted(sysadmin_finance)[:10])
            self._add(Finding(
                "ORA-USER-014",
                "SysAdmin users with financial responsibilities",
                "User Security", "HIGH",
                "ebs_user_responsibilities.csv",
                f"SysAdmin + Finance ({len(sysadmin_finance)}): {names}",
                f"{len(sysadmin_finance)} user(s) hold both System Administrator "
                "and financial responsibilities.",
                "Separate IT admin and financial access.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-USER-014", "No SysAdmin users with financial roles")

        # ORA-USER-015  Concurrent login limit not enforced
        val = self._get_profile_value("CONCURRENT_LOGIN_LIMIT")
        if not val or val == "0":
            self._add(Finding(
                "ORA-USER-015", "Concurrent login limit not enforced",
                "User Security", "MEDIUM",
                "ebs_profile_options.csv",
                f"CONCURRENT_LOGIN_LIMIT = {val or 'NULL'}",
                "No limit on simultaneous logins per user account.",
                "Set CONCURRENT_LOGIN_LIMIT to restrict parallel sessions.",
                "CWE-400",
            ))
        else:
            self._pass("ORA-USER-015", "Concurrent login limit set")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 2 — Password & Authentication  (ORA-PWD-001 .. 006)
    # ═════════════════════════════════════════════════════════════════

    def _check_passwords(self):
        active_users = self._get_active_users()

        # ORA-PWD-001  Password never changed
        unchanged = [
            u for u in active_users
            if not u.get("PASSWORD_DATE")
            or u.get("PASSWORD_DATE") == u.get("CREATION_DATE")
        ]
        if unchanged:
            self._add(Finding(
                "ORA-PWD-001", "Password never changed since creation",
                "Password & Auth", "HIGH",
                "ebs_users.csv", f"Password unchanged: {len(unchanged)} users",
                f"{len(unchanged)} active user(s) have never changed their "
                "password.",
                "Enforce password change on first login.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-PWD-001", "All users have changed passwords")

        # ORA-PWD-002  Password older than 90 days
        old_pwd = [
            u for u in active_users
            if u.get("PASSWORD_DATE")
            and (self._days_ago(u["PASSWORD_DATE"]) or 0) > 90
        ]
        if old_pwd:
            self._add(Finding(
                "ORA-PWD-002", "Passwords older than 90 days",
                "Password & Auth", "MEDIUM",
                "ebs_users.csv", f"Password age > 90d: {len(old_pwd)} users",
                f"{len(old_pwd)} active user(s) have passwords older than "
                "90 days.",
                "Enforce a maximum password age of 60-90 days.",
                "CWE-262",
            ))
        else:
            self._pass("ORA-PWD-002", "Password age within acceptable range")

        # ORA-PWD-003  Failed login limit
        val = self._get_profile_value("SIGNON_PASSWORD_FAILURE_LIMIT")
        if not val or val == "0":
            self._add(Finding(
                "ORA-PWD-003", "Failed login limit not configured",
                "Password & Auth", "CRITICAL",
                "ebs_profile_options.csv",
                f"SIGNON_PASSWORD_FAILURE_LIMIT = {val or 'NULL'}",
                "Failed login limit is not set, allowing unlimited "
                "brute-force attempts.",
                "Set SIGNON_PASSWORD_FAILURE_LIMIT to 5 or less.",
                "CWE-307",
            ))
        else:
            try:
                if int(val) > 10:
                    self._add(Finding(
                        "ORA-PWD-003", "Failed login limit too high",
                        "Password & Auth", "MEDIUM",
                        "ebs_profile_options.csv",
                        f"SIGNON_PASSWORD_FAILURE_LIMIT = {val}",
                        f"Failed login limit is {val}, which may be too high.",
                        "Reduce to 5 or less.",
                        "CWE-307",
                    ))
                else:
                    self._pass("ORA-PWD-003", "Failed login limit configured")
            except ValueError:
                self._pass("ORA-PWD-003", "Failed login limit configured")

        # ORA-PWD-004  Minimum password length
        val = self._get_profile_value("SIGNON_PASSWORD_LENGTH")
        if not val:
            self._add(Finding(
                "ORA-PWD-004", "Minimum password length not set",
                "Password & Auth", "HIGH",
                "ebs_profile_options.csv",
                "SIGNON_PASSWORD_LENGTH = NULL",
                "No minimum password length is enforced.",
                "Set SIGNON_PASSWORD_LENGTH to 8 or higher.",
                "CWE-521",
            ))
        else:
            try:
                if int(val) < 8:
                    self._add(Finding(
                        "ORA-PWD-004", "Minimum password length too short",
                        "Password & Auth", "MEDIUM",
                        "ebs_profile_options.csv",
                        f"SIGNON_PASSWORD_LENGTH = {val}",
                        f"Minimum password length is {val}, below the "
                        "recommended 8 characters.",
                        "Increase to at least 8.",
                        "CWE-521",
                    ))
                else:
                    self._pass("ORA-PWD-004", "Password length acceptable")
            except ValueError:
                self._pass("ORA-PWD-004", "Password length configured")

        # ORA-PWD-005  Password complexity
        val = self._get_profile_value("SIGNON_PASSWORD_HARD_TO_GUESS")
        if not val or val.upper() != "Y":
            self._add(Finding(
                "ORA-PWD-005", "Password complexity not enforced",
                "Password & Auth", "HIGH",
                "ebs_profile_options.csv",
                f"SIGNON_PASSWORD_HARD_TO_GUESS = {val or 'NULL'}",
                "Password complexity is not enabled.",
                "Set SIGNON_PASSWORD_HARD_TO_GUESS to 'Y'.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-PWD-005", "Password complexity enforced")

        # ORA-PWD-006  Password reuse prevention
        val = self._get_profile_value("SIGNON_PASSWORD_NO_REUSE")
        if not val or val == "0":
            self._add(Finding(
                "ORA-PWD-006", "Password reuse not prevented",
                "Password & Auth", "MEDIUM",
                "ebs_profile_options.csv",
                f"SIGNON_PASSWORD_NO_REUSE = {val or 'NULL'}",
                "Password history is not enforced.",
                "Set SIGNON_PASSWORD_NO_REUSE to 6 or higher.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-PWD-006", "Password reuse prevention configured")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 3 — Profile Options  (ORA-PROF-001 .. 010)
    # ═════════════════════════════════════════════════════════════════

    def _check_profiles(self):

        # ORA-PROF-001  Session timeout
        val = self._get_profile_value("ICX_SESSION_TIMEOUT")
        if not val:
            self._add(Finding(
                "ORA-PROF-001", "Session timeout not configured",
                "Profile Options", "MEDIUM",
                "ebs_profile_options.csv",
                "ICX_SESSION_TIMEOUT = NULL",
                "No session timeout is configured.",
                "Set ICX_SESSION_TIMEOUT to 30 minutes or less.",
                "CWE-613",
            ))
        else:
            try:
                if int(val) > 60:
                    self._add(Finding(
                        "ORA-PROF-001", "Session timeout too long",
                        "Profile Options", "LOW",
                        "ebs_profile_options.csv",
                        f"ICX_SESSION_TIMEOUT = {val} min",
                        f"Session timeout is {val} minutes, exceeding the "
                        "recommended 30 minutes.",
                        "Reduce ICX_SESSION_TIMEOUT to 30 minutes or less.",
                        "CWE-613",
                    ))
                else:
                    self._pass("ORA-PROF-001", "Session timeout acceptable")
            except ValueError:
                self._pass("ORA-PROF-001", "Session timeout set")

        # ORA-PROF-002  Guest user password
        val = self._get_profile_value("GUEST_USER_PWD")
        if val and "ORACLE" in val.upper():
            self._add(Finding(
                "ORA-PROF-002", "Guest password contains default value",
                "Profile Options", "HIGH",
                "ebs_profile_options.csv",
                "GUEST_USER_PWD = <contains default>",
                "The GUEST_USER_PWD appears to contain the default password.",
                "Change the guest user password to a strong, unique value.",
                "CWE-798",
            ))
        else:
            self._pass("ORA-PROF-002", "Guest password changed from default")

        # ORA-PROF-003  Diagnostics enabled
        val = self._get_profile_value("FND_DIAGNOSTICS")
        if val and val.upper() == "Y":
            self._add(Finding(
                "ORA-PROF-003", "Diagnostics enabled in production",
                "Profile Options", "MEDIUM",
                "ebs_profile_options.csv",
                f"FND_DIAGNOSTICS = {val}",
                "Diagnostics are enabled, exposing internal data.",
                "Set FND_DIAGNOSTICS to 'N' in production.",
                "CWE-215",
            ))
        else:
            self._pass("ORA-PROF-003", "Diagnostics disabled")

        # ORA-PROF-004  Application logging
        val = self._get_profile_value("AFLOG_ENABLED")
        if val and val.upper() == "Y":
            self._add(Finding(
                "ORA-PROF-004", "Application logging enabled in production",
                "Profile Options", "LOW",
                "ebs_profile_options.csv",
                f"AFLOG_ENABLED = {val}",
                "Application logging is enabled, which may log sensitive data.",
                "Set AFLOG_ENABLED to 'N' unless actively debugging.",
                "CWE-532",
            ))
        else:
            self._pass("ORA-PROF-004", "Application logging disabled")

        # ORA-PROF-005  Servlet agent HTTPS
        val = self._get_profile_value("APPS_SERVLET_AGENT")
        if val and not val.lower().startswith("https"):
            self._add(Finding(
                "ORA-PROF-005", "Servlet agent not using HTTPS",
                "Profile Options", "HIGH",
                "ebs_profile_options.csv",
                f"APPS_SERVLET_AGENT = {val}",
                "The servlet agent URL does not use HTTPS.",
                "Configure APPS_SERVLET_AGENT to use https://.",
                "CWE-319",
            ))
        else:
            self._pass("ORA-PROF-005", "Servlet agent uses HTTPS")

        # ORA-PROF-006  Framework agent HTTPS
        val = self._get_profile_value("APPS_FRAMEWORK_AGENT")
        if val and not val.lower().startswith("https"):
            self._add(Finding(
                "ORA-PROF-006", "Framework agent not using HTTPS",
                "Profile Options", "HIGH",
                "ebs_profile_options.csv",
                f"APPS_FRAMEWORK_AGENT = {val}",
                "The OA Framework agent URL does not use HTTPS.",
                "Configure APPS_FRAMEWORK_AGENT to use https://.",
                "CWE-319",
            ))
        else:
            self._pass("ORA-PROF-006", "Framework agent uses HTTPS")

        # ORA-PROF-007  Sign-on notification
        val = self._get_profile_value("SIGN_ON_NOTIFICATION")
        if not val or val.upper() != "Y":
            self._add(Finding(
                "ORA-PROF-007", "Sign-on notification disabled",
                "Profile Options", "LOW",
                "ebs_profile_options.csv",
                f"SIGN_ON_NOTIFICATION = {val or 'NULL'}",
                "Users are not notified of previous login details.",
                "Set SIGN_ON_NOTIFICATION to 'Y'.",
            ))
        else:
            self._pass("ORA-PROF-007", "Sign-on notification enabled")

        # ORA-PROF-008  Concurrent session limit
        val = self._get_profile_value("ICX_LIMIT_CONNECT")
        if not val or val == "0":
            self._add(Finding(
                "ORA-PROF-008", "Concurrent session limit not set",
                "Profile Options", "MEDIUM",
                "ebs_profile_options.csv",
                f"ICX_LIMIT_CONNECT = {val or 'NULL'}",
                "No limit on concurrent sessions per user.",
                "Set ICX_LIMIT_CONNECT to restrict concurrent sessions.",
                "CWE-400",
            ))
        else:
            self._pass("ORA-PROF-008", "Concurrent session limit set")

        # ORA-PROF-009  OA Framework customization
        val = self._get_profile_value("FND_CUSTOM_OA_DEFINTION")
        if val and val.upper() == "Y":
            self._add(Finding(
                "ORA-PROF-009", "OA Framework customization enabled",
                "Profile Options", "LOW",
                "ebs_profile_options.csv",
                f"FND_CUSTOM_OA_DEFINTION = {val}",
                "OA Framework personalization is enabled.",
                "Set FND_CUSTOM_OA_DEFINTION to 'N' unless required.",
            ))
        else:
            self._pass("ORA-PROF-009", "OA customization disabled")

        # ORA-PROF-010  Sign-on audit level
        val = self._get_profile_value("SIGNONAUDIT:LEVEL")
        if not val:
            self._add(Finding(
                "ORA-PROF-010", "Sign-on audit level not configured",
                "Profile Options", "MEDIUM",
                "ebs_profile_options.csv",
                "SIGNONAUDIT:LEVEL = NULL",
                "Sign-on auditing is not configured.",
                "Set SIGNONAUDIT:LEVEL to 'C' or 'D'.",
                "CWE-778",
            ))
        elif val.upper() == "A":
            self._add(Finding(
                "ORA-PROF-010", "Sign-on audit level too low",
                "Profile Options", "LOW",
                "ebs_profile_options.csv",
                f"SIGNONAUDIT:LEVEL = {val}",
                "Sign-on audit level is at minimum.",
                "Increase SIGNONAUDIT:LEVEL to 'C' or 'D'.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-PROF-010", "Sign-on audit level acceptable")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 4 — Responsibility & Access  (ORA-ROLE-001 .. 006)
    # ═════════════════════════════════════════════════════════════════

    def _check_responsibilities(self):
        active_resps = self._get_active_user_resps()

        # ORA-ROLE-001  Users with System Administrator
        sysadmin_users = sorted(set(
            r["USER_NAME"] for r in active_resps
            if r.get("RESPONSIBILITY_NAME") == "System Administrator"
        ))
        cnt = len(sysadmin_users)
        if cnt > 3:
            names = ", ".join(sysadmin_users[:15])
            self._add(Finding(
                "ORA-ROLE-001", "Excessive System Administrator users",
                "Responsibility & Access", "CRITICAL",
                "ebs_user_responsibilities.csv",
                f"SysAdmin users ({cnt}): {names}",
                f"{cnt} users have the System Administrator responsibility.",
                "Limit to 2-3 designated administrators.",
                "CWE-269",
            ))
        elif cnt > 0:
            names = ", ".join(sysadmin_users)
            self._add(Finding(
                "ORA-ROLE-001", "System Administrator users",
                "Responsibility & Access", "INFO",
                "ebs_user_responsibilities.csv",
                f"SysAdmin users ({cnt}): {names}",
                f"{cnt} user(s) have the System Administrator responsibility.",
                "Review periodically.",
            ))
        else:
            self._pass("ORA-ROLE-001", "No System Administrator users found")

        # ORA-ROLE-002  Users with multiple sensitive responsibilities
        user_sensitive = {}
        for r in active_resps:
            rname = r.get("RESPONSIBILITY_NAME", "")
            if rname in self.SENSITIVE_RESPONSIBILITIES:
                user_sensitive.setdefault(r["USER_NAME"], set()).add(rname)

        multi = {u: rs for u, rs in user_sensitive.items() if len(rs) >= 3}
        if multi:
            details = "; ".join(
                f"{u}({len(rs)})" for u, rs in
                sorted(multi.items(), key=lambda x: -len(x[1]))[:10]
            )
            self._add(Finding(
                "ORA-ROLE-002", "Users with multiple sensitive responsibilities",
                "Responsibility & Access", "HIGH",
                "ebs_user_responsibilities.csv",
                f"Multi-sensitive ({len(multi)} users): {details}",
                f"{len(multi)} user(s) hold 3+ sensitive responsibilities.",
                "Remove unnecessary sensitive access.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-ROLE-002", "No users with excessive sensitive access")

        # ORA-ROLE-003  Sensitive responsibility with too many users
        for resp_name, risk in self.SENSITIVE_RESPONSIBILITIES.items():
            users_with_resp = set(
                r["USER_NAME"] for r in active_resps
                if r.get("RESPONSIBILITY_NAME") == resp_name
            )
            threshold = 5 if risk == "CRITICAL" else 10
            if len(users_with_resp) > threshold:
                self._add(Finding(
                    "ORA-ROLE-003",
                    f"Too many users on '{resp_name}'",
                    "Responsibility & Access", risk,
                    "ebs_user_responsibilities.csv",
                    f"'{resp_name}' assigned to {len(users_with_resp)} users "
                    f"(threshold: {threshold})",
                    f"The '{resp_name}' responsibility is assigned to "
                    f"{len(users_with_resp)} users.",
                    f"Reduce users with '{resp_name}'.",
                    "CWE-269",
                ))

        # ORA-ROLE-004  Responsibility assignments without end date
        all_resps = self._data.get("ebs_user_responsibilities", [])
        no_end = [
            r for r in all_resps
            if self._is_active(r, "USER_END_DATE")
            and not r.get("RESP_END_DATE")
        ]
        if len(no_end) > 100:
            self._add(Finding(
                "ORA-ROLE-004", "Responsibility assignments without end date",
                "Responsibility & Access", "LOW",
                "ebs_user_responsibilities.csv",
                f"No end date: {len(no_end)} assignments",
                f"{len(no_end)} active responsibility assignments have no "
                "end date.",
                "Set end dates on responsibility assignments.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-ROLE-004", "Responsibility end-date coverage acceptable")

        # ORA-ROLE-005  Inactive responsibilities still assigned
        resp_defs = self._data.get("ebs_responsibilities", [])
        ended_resps = {
            r.get("RESPONSIBILITY_NAME") for r in resp_defs
            if r.get("RESP_END_DATE")
            and not self._is_active(r, "RESP_END_DATE")
        }
        assigned_ended = [
            r for r in active_resps
            if r.get("RESPONSIBILITY_NAME") in ended_resps
        ]
        if assigned_ended:
            names = set(r["RESPONSIBILITY_NAME"] for r in assigned_ended)
            details = "; ".join(sorted(names)[:5])
            self._add(Finding(
                "ORA-ROLE-005", "Inactive responsibilities still assigned",
                "Responsibility & Access", "MEDIUM",
                "ebs_user_responsibilities.csv + ebs_responsibilities.csv",
                f"Inactive resps assigned: {details}",
                f"{len(names)} end-dated responsibility(ies) are still "
                "assigned to active users.",
                "Remove user assignments for decommissioned responsibilities.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-ROLE-005", "No inactive responsibilities assigned")

        # ORA-ROLE-006  Custom responsibilities with admin menu
        admin_menu_resps = [
            r for r in resp_defs
            if r.get("MENU_NAME", "")
            and ("SYSADMIN" in r.get("MENU_NAME", "").upper()
                 or "FND_NAVIGATE" in r.get("MENU_NAME", "").upper())
            and "System Admin" not in r.get("RESPONSIBILITY_NAME", "")
            and self._is_active(r, "RESP_END_DATE")
        ]
        if admin_menu_resps:
            names = ", ".join(
                r["RESPONSIBILITY_NAME"] for r in admin_menu_resps[:10]
            )
            self._add(Finding(
                "ORA-ROLE-006", "Custom responsibilities with admin menus",
                "Responsibility & Access", "HIGH",
                "ebs_responsibilities.csv",
                f"Admin-menu resps: {names}",
                f"{len(admin_menu_resps)} custom responsibility(ies) use "
                "system administration menus.",
                "Replace admin menus with purpose-built restricted menus.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-ROLE-006", "No custom resps with admin menus")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 5 — Segregation of Duties  (ORA-SOD-001 .. 006)
    # ═════════════════════════════════════════════════════════════════

    def _check_sod(self):
        active_resps = self._get_active_user_resps()

        # Build user -> set of responsibility names
        user_resps: dict = {}
        for r in active_resps:
            user_resps.setdefault(r["USER_NAME"], set()).add(
                r.get("RESPONSIBILITY_NAME", "")
            )

        for idx, (kw1, kw2, label, risk_desc) in enumerate(
            self.SOD_CONFLICTS, start=1
        ):
            rule_id = f"ORA-SOD-{idx:03d}"
            conflicts = []
            for user, resps in user_resps.items():
                has1 = any(kw1.upper() in r.upper() for r in resps)
                has2 = any(kw2.upper() in r.upper() for r in resps)
                if has1 and has2:
                    conflicts.append(user)

            if conflicts:
                users = ", ".join(sorted(conflicts)[:10])
                self._add(Finding(
                    rule_id, f"SoD conflict: {label}",
                    "Segregation of Duties", "HIGH",
                    "ebs_user_responsibilities.csv",
                    f"{label} conflict ({len(conflicts)} users): {users}",
                    f"{len(conflicts)} user(s) hold responsibilities in both "
                    f"conflicting areas. {risk_desc}.",
                    f"Remove one side of the {label} conflict or implement "
                    "compensating controls.",
                    "CWE-284",
                ))
            else:
                self._pass(rule_id, f"No {label} SoD conflicts")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 6 — Concurrent Programs  (ORA-CONC-001 .. 004)
    # ═════════════════════════════════════════════════════════════════

    def _check_concurrent(self):
        rga = self._data.get("ebs_request_group_access", [])
        programs = self._data.get("ebs_concurrent_programs", [])
        requests = self._data.get("ebs_concurrent_requests", [])

        # ORA-CONC-001  Dangerous programs in non-admin request groups
        dangerous_access = [
            r for r in rga
            if r.get("CONCURRENT_PROGRAM_NAME", "").upper()
               in self.DANGEROUS_PROGRAMS
            and "System Admin" not in r.get("REQUEST_GROUP_NAME", "")
        ]
        if dangerous_access:
            details = "; ".join(
                f"{r['CONCURRENT_PROGRAM_NAME']} -> {r['REQUEST_GROUP_NAME']}"
                for r in dangerous_access[:10]
            )
            self._add(Finding(
                "ORA-CONC-001", "Dangerous programs in non-admin request groups",
                "Concurrent Programs", "HIGH",
                "ebs_request_group_access.csv",
                f"Dangerous program access: {details}",
                f"{len(dangerous_access)} dangerous concurrent program(s) "
                "are accessible through non-admin request groups.",
                "Remove dangerous programs from non-admin request groups.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-001", "Dangerous programs properly restricted")

        # ORA-CONC-002  Host-based concurrent programs
        host_progs = [
            p for p in programs
            if p.get("EXECUTION_METHOD_CODE") == "H"
            and p.get("ENABLED_FLAG") == "Y"
        ]
        if host_progs:
            names = ", ".join(
                p["CONCURRENT_PROGRAM_NAME"] for p in host_progs[:10]
            )
            self._add(Finding(
                "ORA-CONC-002", "Host-based concurrent programs enabled",
                "Concurrent Programs", "MEDIUM",
                "ebs_concurrent_programs.csv",
                f"Host programs ({len(host_progs)}): {names}",
                f"{len(host_progs)} host-based concurrent program(s) can "
                "execute OS-level commands.",
                "Review and disable unnecessary host-based programs.",
                "CWE-78",
            ))
        else:
            self._pass("ORA-CONC-002", "No host-based programs")

        # ORA-CONC-003  Application-level request group access
        app_grants = [
            r for r in rga if r.get("REQUEST_UNIT_TYPE") == "A"
        ]
        if app_grants:
            self._add(Finding(
                "ORA-CONC-003", "Application-level request group access",
                "Concurrent Programs", "MEDIUM",
                "ebs_request_group_access.csv",
                f"Application-level grants: {len(app_grants)}",
                f"{len(app_grants)} request group entry(ies) grant access "
                "to ALL programs in an application.",
                "Replace with explicit program-level grants.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-003", "No application-level grants")

        # ORA-CONC-004  Programs running as privileged user
        priv_requests = [
            r for r in requests
            if r.get("USER_NAME", "").upper() in ("SYSADMIN", "AUTOINSTALL")
        ]
        if priv_requests:
            from collections import Counter
            user_counts = Counter(r["USER_NAME"] for r in priv_requests)
            details = "; ".join(
                f"{u}({c} requests)" for u, c in user_counts.most_common()
            )
            self._add(Finding(
                "ORA-CONC-004", "Programs running as privileged user",
                "Concurrent Programs", "MEDIUM",
                "ebs_concurrent_requests.csv",
                f"Privileged submissions: {details}",
                "Concurrent requests submitted under privileged accounts "
                "in the last 30 days.",
                "Run programs under individual named user accounts.",
                "CWE-250",
            ))
        else:
            self._pass("ORA-CONC-004", "No privileged user submissions")

        # ORA-CONC-005  Shell/host execution concurrent programs
        shell_progs = [
            p for p in programs
            if p.get("EXECUTION_METHOD_CODE") in ("H", "K")
            and p.get("ENABLED_FLAG") == "Y"
        ]
        if shell_progs:
            names = ", ".join(
                p["CONCURRENT_PROGRAM_NAME"] for p in shell_progs[:10]
            )
            self._add(Finding(
                "ORA-CONC-005",
                "Shell/host execution concurrent programs",
                "Concurrent Programs", "MEDIUM",
                "ebs_concurrent_programs.csv",
                f"Shell programs ({len(shell_progs)}): {names}",
                f"{len(shell_progs)} concurrent program(s) execute shell "
                "scripts or host commands.",
                "Review and restrict shell-based programs to admins only.",
                "CWE-78",
            ))
        elif programs:
            self._pass("ORA-CONC-005", "No shell execution programs found")

        # ORA-CONC-006  Security-sensitive programs broadly accessible
        sec_progs = {"FNDCPASS", "FNDSLOAD", "FNDSCARU", "FNDLOAD"}
        sec_access = [
            r for r in rga
            if r.get("CONCURRENT_PROGRAM_NAME", "").upper() in sec_progs
        ]
        if sec_access:
            details = "; ".join(
                f"{r['CONCURRENT_PROGRAM_NAME']} -> {r.get('REQUEST_GROUP_NAME', '?')}"
                for r in sec_access[:10]
            )
            self._add(Finding(
                "ORA-CONC-006",
                "Security-sensitive programs broadly accessible",
                "Concurrent Programs", "HIGH",
                "ebs_request_group_access.csv",
                f"Sensitive program access: {details}",
                "Security configuration programs are accessible through "
                "multiple request groups.",
                "Restrict to System Administrator request group only.",
                "CWE-269",
            ))
        elif rga:
            self._pass("ORA-CONC-006", "Security programs properly restricted")

        # ORA-CONC-007  Concurrent output directory configuration
        val = self._get_profile_value("APPLCSF")
        val2 = self._get_profile_value("APPLOUT")
        if val or val2:
            self._add(Finding(
                "ORA-CONC-007",
                "Concurrent output directory configuration",
                "Concurrent Programs", "INFO",
                "ebs_profile_options.csv",
                f"APPLCSF = {val or 'NULL'}, APPLOUT = {val2 or 'NULL'}",
                "Verify that output directories have restricted permissions.",
                "Ensure output directories have 700 permissions.",
            ))

        # ORA-CONC-008  FNDCPASS/FNDSCARU recent execution
        sec_requests = [
            r for r in requests
            if r.get("CONCURRENT_PROGRAM_NAME", "").upper()
               in ("FNDCPASS", "FNDSCARU")
        ]
        if sec_requests:
            self._add(Finding(
                "ORA-CONC-008",
                "Security programs executed recently",
                "Concurrent Programs", "MEDIUM",
                "ebs_concurrent_requests.csv",
                f"FNDCPASS/FNDSCARU executions: {len(sec_requests)}",
                f"{len(sec_requests)} execution(s) of password/user programs "
                "detected. Review for authorization.",
                "Verify each execution was authorized.",
                "CWE-269",
            ))
        elif requests:
            self._pass("ORA-CONC-008", "No recent security program executions")

        # ORA-CONC-009  Concurrent output file retention
        old_outputs = [
            r for r in requests
            if (self._days_ago(r.get("ACTUAL_START_DATE", "")) or 0) > 180
            and r.get("OUTFILE_NAME")
        ]
        if len(old_outputs) > 100:
            self._add(Finding(
                "ORA-CONC-009",
                "Old concurrent output files not purged",
                "Concurrent Programs", "LOW",
                "ebs_concurrent_requests.csv",
                f"Output files > 180 days: {len(old_outputs):,}",
                f"{len(old_outputs):,} old output files still exist.",
                "Schedule the Purge Concurrent Request program.",
                "CWE-532",
            ))
        elif requests:
            self._pass("ORA-CONC-009", "Output file retention acceptable")

        # ORA-CONC-010  Request group with ALL concurrent programs
        all_prog_grants = [
            r for r in rga if r.get("REQUEST_UNIT_TYPE") == "A"
        ]
        if all_prog_grants:
            self._add(Finding(
                "ORA-CONC-010",
                "Request groups with ALL-program access",
                "Concurrent Programs", "HIGH",
                "ebs_request_group_access.csv",
                f"ALL-program grants: {len(all_prog_grants)}",
                f"{len(all_prog_grants)} request group(s) grant access to ALL "
                "concurrent programs.",
                "Replace with explicit program-level entries.",
                "CWE-269",
            ))
        elif rga:
            self._pass("ORA-CONC-010", "No ALL-program request groups")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 7 — Audit Trail  (ORA-AUDIT-001 .. 005)
    # ═════════════════════════════════════════════════════════════════

    def _check_audit(self):

        # ORA-AUDIT-001  Audit trail enabled
        val = self._get_profile_value("AUDITTRAIL:ACTIVATE")
        if not val or val.upper() != "Y":
            self._add(Finding(
                "ORA-AUDIT-001", "EBS audit trail not enabled",
                "Audit Trail", "CRITICAL",
                "ebs_profile_options.csv",
                f"AUDITTRAIL:ACTIVATE = {val or 'NULL'}",
                "The Oracle EBS AuditTrail feature is not enabled.",
                "Set AUDITTRAIL:ACTIVATE to 'Y' at Site level.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-001", "Audit trail enabled")

        # ORA-AUDIT-002  Critical tables not audited
        audit_config = self._data.get("ebs_audit_config", [])
        audited_tables = {
            r["TABLE_NAME"] for r in audit_config
            if r.get("AUDIT_STATE", "").upper() == "E"
        }
        for table_name in self.CRITICAL_AUDIT_TABLES:
            desc = self.CRITICAL_AUDIT_TABLE_DESC.get(table_name, table_name)
            if table_name not in audited_tables:
                self._add(Finding(
                    "ORA-AUDIT-002",
                    f"Critical table not audited: {table_name}",
                    "Audit Trail", "HIGH",
                    "ebs_audit_config.csv",
                    f"{table_name} ({desc}) — not in active audit schema",
                    f"The {table_name} table ({desc}) is not being audited.",
                    f"Add {table_name} to an audit group and enable auditing.",
                    "CWE-778",
                ))

        # ORA-AUDIT-003  Database-level auditing
        val = self._get_db_param("audit_trail")
        if val and val.upper() in ("NONE", "FALSE"):
            self._add(Finding(
                "ORA-AUDIT-003", "Database auditing disabled",
                "Audit Trail", "HIGH",
                "db_parameters.csv",
                f"audit_trail = {val}",
                "Database-level auditing is disabled.",
                "Set audit_trail to 'DB' or 'DB,EXTENDED'.",
                "CWE-778",
            ))
        elif not self._data.get("db_parameters"):
            self._vprint("  db_parameters.csv not available, skipping ORA-AUDIT-003")
        else:
            self._pass("ORA-AUDIT-003", "Database auditing enabled")

        # ORA-AUDIT-004  Sign-on audit level
        val = self._get_profile_value("SIGNONAUDIT:LEVEL")
        if not val or val.upper() == "A":
            self._add(Finding(
                "ORA-AUDIT-004", "Sign-on audit level insufficient",
                "Audit Trail", "MEDIUM",
                "ebs_profile_options.csv",
                f"SIGNONAUDIT:LEVEL = {val or 'NULL'}",
                "Sign-on audit level is not configured or at minimum.",
                "Set SIGNONAUDIT:LEVEL to 'C' or 'D'.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-004", "Sign-on audit level configured")

        # ORA-AUDIT-005  Audit data retention
        old_data = self._data.get("ebs_login_audit_old", [])
        if old_data:
            try:
                cnt = int(old_data[0].get("OLD_RECORD_COUNT", "0"))
                if cnt > 100000:
                    self._add(Finding(
                        "ORA-AUDIT-005", "Audit data retention review needed",
                        "Audit Trail", "LOW",
                        "ebs_login_audit_old.csv",
                        f"Audit records older than 1 year: {cnt:,}",
                        f"{cnt:,} audit records older than 365 days.",
                        "Implement audit data archival and purge strategy.",
                    ))
                else:
                    self._pass("ORA-AUDIT-005", "Audit data volume acceptable")
            except (ValueError, IndexError):
                self._pass("ORA-AUDIT-005", "Could not parse audit data count")
        else:
            self._vprint("  ebs_login_audit_old.csv not available, skipping")

        # ORA-AUDIT-006  Profile option change auditing
        audit_config = self._data.get("ebs_audit_config", [])
        prof_audited = any(
            r.get("TABLE_NAME") == "FND_PROFILE_OPTION_VALUES"
            and r.get("AUDIT_STATE", "").upper() == "E"
            for r in audit_config
        )
        if audit_config and not prof_audited:
            self._add(Finding(
                "ORA-AUDIT-006",
                "Profile option changes not audited",
                "Audit Trail", "HIGH",
                "ebs_audit_config.csv",
                "FND_PROFILE_OPTION_VALUES not in active audit schema",
                "Changes to security-critical profile options are not tracked.",
                "Add FND_PROFILE_OPTION_VALUES to an audit group.",
                "CWE-778",
            ))
        elif prof_audited:
            self._pass("ORA-AUDIT-006", "Profile option changes audited")

        # ORA-AUDIT-007  Responsibility assignment changes not tracked
        resp_audited = any(
            r.get("TABLE_NAME") == "FND_USER_RESP_GROUPS_DIRECT"
            and r.get("AUDIT_STATE", "").upper() == "E"
            for r in audit_config
        )
        if audit_config and not resp_audited:
            self._add(Finding(
                "ORA-AUDIT-007",
                "Responsibility assignment changes not audited",
                "Audit Trail", "HIGH",
                "ebs_audit_config.csv",
                "FND_USER_RESP_GROUPS_DIRECT not in active audit schema",
                "Granting or revoking responsibilities is not tracked.",
                "Add FND_USER_RESP_GROUPS_DIRECT to an audit group.",
                "CWE-778",
            ))
        elif resp_audited:
            self._pass("ORA-AUDIT-007", "Responsibility changes audited")

        # ORA-AUDIT-008  FND_USER modification audit
        user_audited = any(
            r.get("TABLE_NAME") == "FND_USER"
            and r.get("AUDIT_STATE", "").upper() == "E"
            for r in audit_config
        )
        if audit_config and not user_audited:
            self._add(Finding(
                "ORA-AUDIT-008",
                "User account changes not audited",
                "Audit Trail", "HIGH",
                "ebs_audit_config.csv",
                "FND_USER not in active audit schema",
                "Changes to user accounts are not tracked in the audit trail.",
                "Add FND_USER to an audit group and enable auditing.",
                "CWE-778",
            ))
        elif user_audited:
            self._pass("ORA-AUDIT-008", "User account changes audited")

        # ORA-AUDIT-009  Unified Audit policies (12c+)
        unified_policies = self._data.get("db_unified_audit", [])
        if unified_policies:
            self._pass("ORA-AUDIT-009",
                        f"Unified Audit policies: {len(unified_policies)}")
        elif self._data.get("db_parameters"):
            # Only flag if we have DB data but no unified audit
            self._add(Finding(
                "ORA-AUDIT-009",
                "No Unified Audit policies enabled",
                "Audit Trail", "MEDIUM",
                "db_unified_audit.csv",
                "Unified Audit policies: 0",
                "No Unified Audit policies are enabled.",
                "Enable Unified Auditing and configure policies.",
                "CWE-778",
            ))
        else:
            self._vprint("  db_unified_audit.csv not available, skipping")

        # ORA-AUDIT-010  Audit log retention (skip in offline — age calc unreliable)
        # Covered by ORA-AUDIT-005 which checks >1 year old records
        self._vprint("  ORA-AUDIT-010: Retention check deferred to live scanner")

        # ORA-AUDIT-011  Financial table WHO columns
        # Cannot verify without actual table data; skip in offline mode
        self._vprint("  ORA-AUDIT-011: WHO columns check requires live access")

        # ORA-AUDIT-012  Concurrent request history retention
        requests = self._data.get("ebs_concurrent_requests", [])
        old_requests = [
            r for r in requests
            if (self._days_ago(r.get("ACTUAL_START_DATE", "")) or 0) > 365
        ]
        if len(old_requests) > 500:
            self._add(Finding(
                "ORA-AUDIT-012",
                "Concurrent request history needs purging",
                "Audit Trail", "LOW",
                "ebs_concurrent_requests.csv",
                f"Completed requests > 1 year old: {len(old_requests):,}",
                f"{len(old_requests):,} old concurrent request records found.",
                "Run the Purge Concurrent Request program.",
            ))
        elif requests:
            self._pass("ORA-AUDIT-012", "Concurrent request history acceptable")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 8 — Database Security  (ORA-DB-001 .. 010)
    # ═════════════════════════════════════════════════════════════════

    def _check_database(self):
        db_users = self._data.get("db_users", [])
        db_role_privs = self._data.get("db_role_privs", [])
        db_tab_privs = self._data.get("db_tab_privs", [])

        if not db_users and not db_role_privs and not db_tab_privs:
            self._vprint("  No db_*.csv files found, skipping database checks")
            return

        # ORA-DB-001  Default database accounts not locked
        unlocked_defaults = [
            u for u in db_users
            if u.get("USERNAME", "").upper() in self.DEFAULT_DB_ACCOUNTS
            and u.get("ACCOUNT_STATUS", "").upper() not in (
                "LOCKED", "EXPIRED & LOCKED", "EXPIRED(GRACE)")
        ]
        if unlocked_defaults:
            names = ", ".join(
                f"{u['USERNAME']}({u.get('ACCOUNT_STATUS', '?')})"
                for u in unlocked_defaults
            )
            self._add(Finding(
                "ORA-DB-001", "Default database accounts not locked",
                "Database Security", "HIGH",
                "db_users.csv", f"Unlocked defaults: {names}",
                f"{len(unlocked_defaults)} default database account(s) are "
                "not locked.",
                "Lock and expire all default accounts not operationally "
                "required.",
                "CWE-798",
            ))
        else:
            self._pass("ORA-DB-001", "Default DB accounts locked")

        # ORA-DB-002  PUBLIC has EXECUTE on sensitive packages
        public_exec = [
            p for p in db_tab_privs
            if p.get("GRANTEE") == "PUBLIC"
            and p.get("PRIVILEGE") == "EXECUTE"
            and p.get("TABLE_NAME", "").upper() in self.SENSITIVE_PACKAGES
        ]
        if public_exec:
            pkgs = ", ".join(p["TABLE_NAME"] for p in public_exec)
            self._add(Finding(
                "ORA-DB-002", "PUBLIC has EXECUTE on sensitive packages",
                "Database Security", "HIGH",
                "db_tab_privs.csv",
                f"PUBLIC EXECUTE: {pkgs}",
                f"PUBLIC has EXECUTE on {len(public_exec)} sensitive package(s).",
                "Revoke EXECUTE from PUBLIC on sensitive packages.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-002", "PUBLIC does not have dangerous EXECUTE")

        # ORA-DB-003  Excessive DBA role grants
        dba_grants = [
            r for r in db_role_privs
            if r.get("GRANTED_ROLE") == "DBA"
            and r.get("GRANTEE", "").upper() not in ("SYS", "SYSTEM")
        ]
        if dba_grants:
            grantees = ", ".join(
                r["GRANTEE"] +
                (" [WITH ADMIN]" if r.get("ADMIN_OPTION") == "YES" else "")
                for r in dba_grants
            )
            self._add(Finding(
                "ORA-DB-003", "Excessive DBA role grants",
                "Database Security", "CRITICAL",
                "db_role_privs.csv",
                f"DBA grantees: {grantees}",
                f"{len(dba_grants)} non-default schema(s) have the DBA role.",
                "Revoke DBA and create custom roles with minimum privileges.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-003", "No excessive DBA grants")

        # ORA-DB-004  UTL_FILE_DIR
        val = self._get_db_param("utl_file_dir")
        if val and val.strip() not in ("", "NONE"):
            severity = "CRITICAL" if ("*" in val or val.strip() == "/") \
                else "MEDIUM"
            self._add(Finding(
                "ORA-DB-004", "UTL_FILE_DIR parameter set",
                "Database Security", severity,
                "db_parameters.csv",
                f"utl_file_dir = {val}",
                "UTL_FILE_DIR can allow file system access.",
                "Remove or restrict utl_file_dir. Use Directory objects.",
                "CWE-732",
            ))
        else:
            self._pass("ORA-DB-004", "UTL_FILE_DIR not set or restricted")

        # ORA-DB-005  Remote OS authentication
        val = self._get_db_param("remote_os_authent")
        if val and val.upper() == "TRUE":
            self._add(Finding(
                "ORA-DB-005", "Remote OS authentication enabled",
                "Database Security", "CRITICAL",
                "db_parameters.csv",
                f"remote_os_authent = {val}",
                "Remote OS authentication allows any client to authenticate "
                "as an OS-authenticated user.",
                "Set remote_os_authent to FALSE.",
                "CWE-287",
            ))
        else:
            self._pass("ORA-DB-005", "Remote OS auth disabled")

        # ORA-DB-006  Database links
        db_links = self._data.get("db_links", [])
        if db_links:
            links = "; ".join(
                f"{r.get('OWNER','?')}.{r.get('DB_LINK','?')}"
                for r in db_links[:10]
            )
            self._add(Finding(
                "ORA-DB-006", "Database links detected",
                "Database Security", "MEDIUM",
                "db_links.csv",
                f"DB links ({len(db_links)}): {links}",
                f"{len(db_links)} database link(s) exist.",
                "Review and remove unused links.",
                "CWE-522",
            ))
        else:
            self._pass("ORA-DB-006", "No database links found")

        # ORA-DB-007  Sensitive package grants to non-DBA schemas
        non_dba_exec = [
            p for p in db_tab_privs
            if p.get("PRIVILEGE") == "EXECUTE"
            and p.get("TABLE_NAME", "").upper() in (
                "UTL_FILE", "UTL_HTTP", "UTL_TCP",
                "UTL_SMTP", "DBMS_SQL", "DBMS_JAVA")
            and p.get("GRANTEE", "").upper() not in (
                "SYS", "SYSTEM", "PUBLIC", "APPS", "APPLSYS", "DBA")
        ]
        if non_dba_exec:
            details = "; ".join(
                f"{p['GRANTEE']}->{p['TABLE_NAME']}"
                for p in non_dba_exec[:10]
            )
            self._add(Finding(
                "ORA-DB-007", "Sensitive package grants to non-DBA schemas",
                "Database Security", "MEDIUM",
                "db_tab_privs.csv",
                f"Package grants: {details}",
                f"{len(non_dba_exec)} non-DBA schema(s) have EXECUTE on "
                "sensitive packages.",
                "Review and revoke unnecessary grants.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-007", "No unexpected package grants")

        # ORA-DB-008  Open non-EBS database accounts
        excluded = {
            "SYS", "SYSTEM", "APPS", "APPLSYS", "APPLSYSPUB",
            "CTXSYS", "MDSYS", "XDB", "WMSYS", "DBSNMP", "ANONYMOUS",
        }
        open_accts = [
            u for u in db_users
            if u.get("ACCOUNT_STATUS", "").upper() == "OPEN"
            and u.get("USERNAME", "").upper() not in excluded
            and not u.get("USERNAME", "").upper().startswith("APEX_")
            and not u.get("USERNAME", "").upper().startswith("FLOWS_")
        ]
        if len(open_accts) > 20:
            names = ", ".join(u["USERNAME"] for u in open_accts[:15])
            self._add(Finding(
                "ORA-DB-008", "Excessive open database accounts",
                "Database Security", "MEDIUM",
                "db_users.csv",
                f"Open accounts ({len(open_accts)}): {names} ...",
                f"{len(open_accts)} non-system database accounts are OPEN.",
                "Review and lock accounts that don't need direct DB access.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-DB-008", "Open account count acceptable")

        # ORA-DB-009  Case-sensitive logon
        val = self._get_db_param("sec_case_sensitive_logon")
        if val and val.upper() == "FALSE":
            self._add(Finding(
                "ORA-DB-009", "Case-sensitive logon disabled",
                "Database Security", "MEDIUM",
                "db_parameters.csv",
                f"sec_case_sensitive_logon = {val}",
                "Case-sensitive password matching is disabled.",
                "Set sec_case_sensitive_logon to TRUE.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-DB-009", "Case-sensitive logon enabled")

        # ORA-DB-010  Password verify function in DEFAULT profile
        db_profiles = self._data.get("db_profiles", [])
        pvf = [
            r for r in db_profiles
            if r.get("PROFILE", "").upper() == "DEFAULT"
            and r.get("RESOURCE_NAME", "").upper() == "PASSWORD_VERIFY_FUNCTION"
        ]
        if pvf:
            val = pvf[0].get("LIMIT_VALUE", "")
            if not val or val.upper() in ("NULL", "UNLIMITED"):
                self._add(Finding(
                    "ORA-DB-010",
                    "Password verify function not set in DEFAULT profile",
                    "Database Security", "HIGH",
                    "db_profiles.csv",
                    f"PASSWORD_VERIFY_FUNCTION = {val or 'NULL'}",
                    "The DEFAULT profile does not enforce a password verify "
                    "function.",
                    "Set PASSWORD_VERIFY_FUNCTION to ORA12C_VERIFY_FUNCTION.",
                    "CWE-521",
                ))
            else:
                self._pass("ORA-DB-010", "Password verify function configured")
        elif db_profiles:
            self._pass("ORA-DB-010", "Could not find DEFAULT profile entry")
        else:
            self._vprint("  db_profiles.csv not available, skipping ORA-DB-010")

        # ORA-DB-011  Network encryption not enforced
        val = self._get_db_param("sqlnet.encryption_server")
        if val and val.upper() in ("REQUIRED", "REQUESTED"):
            self._pass("ORA-DB-011", "Network encryption configured")
        elif self._data.get("db_parameters"):
            self._add(Finding(
                "ORA-DB-011", "Network encryption not enforced",
                "Database Security", "HIGH",
                "db_parameters.csv",
                f"sqlnet.encryption_server = {val or 'NOT SET'}",
                "Database network encryption is not enforced.",
                "Set SQLNET.ENCRYPTION_SERVER = REQUIRED in sqlnet.ora.",
                "CWE-319",
            ))
        else:
            self._vprint("  db_parameters.csv not available, skipping ORA-DB-011")

        # ORA-DB-012  O7_DICTIONARY_ACCESSIBILITY enabled
        val = self._get_db_param("o7_dictionary_accessibility")
        if val and val.upper() == "TRUE":
            self._add(Finding(
                "ORA-DB-012", "O7_DICTIONARY_ACCESSIBILITY enabled",
                "Database Security", "HIGH",
                "db_parameters.csv",
                f"o7_dictionary_accessibility = {val}",
                "Users with SELECT ANY TABLE can read data dictionary tables.",
                "Set O7_DICTIONARY_ACCESSIBILITY to FALSE.",
                "CWE-269",
            ))
        elif self._data.get("db_parameters"):
            self._pass("ORA-DB-012", "O7_DICTIONARY_ACCESSIBILITY disabled")

        # ORA-DB-013  SELECT ANY TABLE grants
        db_sys_privs = self._data.get("db_sys_privs", [])
        excluded_grantees = {
            "SYS", "SYSTEM", "DBA", "EXP_FULL_DATABASE",
            "IMP_FULL_DATABASE", "DATAPUMP_EXP_FULL_DATABASE",
            "DATAPUMP_IMP_FULL_DATABASE", "SELECT_CATALOG_ROLE",
        }
        sat_grants = [
            r for r in db_sys_privs
            if r.get("PRIVILEGE", "").upper() == "SELECT ANY TABLE"
            and r.get("GRANTEE", "").upper() not in excluded_grantees
        ]
        if sat_grants:
            grantees = ", ".join(r["GRANTEE"] for r in sat_grants[:10])
            self._add(Finding(
                "ORA-DB-013", "SELECT ANY TABLE grants detected",
                "Database Security", "HIGH",
                "db_sys_privs.csv",
                f"SELECT ANY TABLE grantees ({len(sat_grants)}): {grantees}",
                f"{len(sat_grants)} non-default schema(s) have SELECT ANY TABLE.",
                "Revoke and grant SELECT on specific tables only.",
                "CWE-269",
            ))
        elif db_sys_privs:
            self._pass("ORA-DB-013", "No unexpected SELECT ANY TABLE grants")
        else:
            self._vprint("  db_sys_privs.csv not available, skipping ORA-DB-013")

        # ORA-DB-014  ALTER SYSTEM privilege grants
        alt_sys = [
            r for r in db_sys_privs
            if r.get("PRIVILEGE", "").upper() == "ALTER SYSTEM"
            and r.get("GRANTEE", "").upper() not in ("SYS", "SYSTEM", "DBA")
        ]
        if alt_sys:
            grantees = ", ".join(r["GRANTEE"] for r in alt_sys[:10])
            self._add(Finding(
                "ORA-DB-014", "ALTER SYSTEM privilege grants",
                "Database Security", "CRITICAL",
                "db_sys_privs.csv",
                f"ALTER SYSTEM grantees: {grantees}",
                f"{len(alt_sys)} non-DBA schema(s) have ALTER SYSTEM.",
                "Revoke ALTER SYSTEM from non-DBA schemas.",
                "CWE-269",
            ))
        elif db_sys_privs:
            self._pass("ORA-DB-014", "No unexpected ALTER SYSTEM grants")

        # ORA-DB-015  SYSDBA session audit
        val = self._get_db_param("audit_sys_operations")
        if val and val.upper() == "FALSE":
            self._add(Finding(
                "ORA-DB-015", "SYSDBA session auditing disabled",
                "Database Security", "HIGH",
                "db_parameters.csv",
                f"audit_sys_operations = {val}",
                "SYSDBA/SYSOPER operations are not being audited.",
                "Set audit_sys_operations to TRUE.",
                "CWE-778",
            ))
        elif self._data.get("db_parameters"):
            self._pass("ORA-DB-015", "SYSDBA session auditing enabled")

        # ORA-DB-016  Database login rate limiting
        val = self._get_db_param("sec_max_failed_login_attempts")
        if val and val != "0":
            self._pass("ORA-DB-016", "DB login rate limiting configured")
        elif self._data.get("db_parameters"):
            self._add(Finding(
                "ORA-DB-016",
                "Database login rate limiting not configured",
                "Database Security", "MEDIUM",
                "db_parameters.csv",
                f"sec_max_failed_login_attempts = {val or 'NOT SET'}",
                "Database-level login rate limiting is not configured.",
                "Set SEC_MAX_FAILED_LOGIN_ATTEMPTS to a value like 10.",
                "CWE-307",
            ))

        # ORA-DB-017  Database Vault status
        db_dv_status = self._data.get("db_dv_status", [])
        if db_dv_status:
            dv_val = db_dv_status[0].get("STATUS", "")
            if dv_val and dv_val.upper() == "TRUE":
                self._pass("ORA-DB-017", "Database Vault enabled")
            else:
                self._add(Finding(
                    "ORA-DB-017", "Database Vault not enabled",
                    "Database Security", "MEDIUM",
                    "db_dv_status.csv",
                    f"Database Vault status: {dv_val or 'disabled'}",
                    "Oracle Database Vault is not enabled.",
                    "Enable Database Vault to protect the APPS schema.",
                    "CWE-269",
                ))
        else:
            self._vprint("  db_dv_status.csv not available, skipping ORA-DB-017")

        # ORA-DB-018  Fine-Grained Auditing policies
        db_fga = self._data.get("db_fga_policies", [])
        enabled_fga = [r for r in db_fga if r.get("ENABLED", "").upper() == "YES"]
        if db_fga and not enabled_fga:
            self._add(Finding(
                "ORA-DB-018", "No Fine-Grained Audit policies enabled",
                "Database Security", "MEDIUM",
                "db_fga_policies.csv",
                "FGA policies enabled: 0",
                "No Fine-Grained Auditing policies are active.",
                "Create FGA policies for PII and financial columns.",
                "CWE-778",
            ))
        elif enabled_fga:
            self._pass("ORA-DB-018", f"FGA policies active: {len(enabled_fga)}")
        else:
            self._vprint("  db_fga_policies.csv not available, skipping ORA-DB-018")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 9 — Patching & Versions  (ORA-PATCH-001 .. 004)
    # ═════════════════════════════════════════════════════════════════

    def _check_patching(self):

        # ORA-PATCH-001  EBS version
        if self._ebs_version:
            major = self._ebs_version.split(".")[0]
            if major == "11":
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version end-of-life",
                    "Patching & Versions", "CRITICAL",
                    "instance_info.csv",
                    f"EBS Release: {self._ebs_version}",
                    f"Oracle EBS {self._ebs_version} is past end of support.",
                    "Plan migration to EBS 12.2.x.",
                ))
            elif self._ebs_version.startswith("12.1"):
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version nearing end-of-life",
                    "Patching & Versions", "HIGH",
                    "instance_info.csv",
                    f"EBS Release: {self._ebs_version}",
                    f"Oracle EBS {self._ebs_version} is in Extended Support.",
                    "Plan migration to EBS 12.2.x.",
                ))
            elif self._ebs_version.startswith("12.2"):
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version information",
                    "Patching & Versions", "INFO",
                    "instance_info.csv",
                    f"EBS Release: {self._ebs_version}",
                    f"Oracle EBS {self._ebs_version} is under active support.",
                    "Continue applying quarterly CPU patches.",
                ))
            else:
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version unrecognized",
                    "Patching & Versions", "MEDIUM",
                    "instance_info.csv",
                    f"EBS Release: {self._ebs_version}",
                    f"EBS release '{self._ebs_version}' is not recognized.",
                    "Verify the EBS version and support status.",
                ))

        # ORA-PATCH-002  Last patch applied
        patches = self._data.get("ebs_patches", [])
        if patches:
            latest = patches[0]  # sorted by date desc in export
            bug = latest.get("BUG_NUMBER", "?")
            dt = latest.get("LAST_UPDATE_DATE", "?")
            self._add(Finding(
                "ORA-PATCH-002", "Last applied patch",
                "Patching & Versions", "INFO",
                "ebs_patches.csv",
                f"Last patch: {bug} on {dt}",
                f"Most recently applied patch: {bug} ({dt}).",
                "Ensure quarterly CPU patches are applied within 90 days.",
            ))
        else:
            self._add(Finding(
                "ORA-PATCH-002", "No patch history found",
                "Patching & Versions", "HIGH",
                "ebs_patches.csv",
                "ebs_patches.csv empty or not provided",
                "No patch history could be found.",
                "Verify patches via adpatch/adop.",
            ))

        # ORA-PATCH-003  Database version
        if self._db_version:
            if "11g" in self._db_version or "11.2" in self._db_version:
                self._add(Finding(
                    "ORA-PATCH-003", "Database version end-of-life",
                    "Patching & Versions", "CRITICAL",
                    "instance_info.csv",
                    f"DB: {self._db_version}",
                    "Oracle Database 11g is past end of support.",
                    "Upgrade to Oracle Database 19c LTS or later.",
                ))
            elif "12c" in self._db_version or "12.1" in self._db_version:
                self._add(Finding(
                    "ORA-PATCH-003", "Database version nearing end-of-life",
                    "Patching & Versions", "HIGH",
                    "instance_info.csv",
                    f"DB: {self._db_version}",
                    "Oracle Database 12c is in Extended Support.",
                    "Plan upgrade to Oracle Database 19c LTS or later.",
                ))
            else:
                self._add(Finding(
                    "ORA-PATCH-003", "Database version information",
                    "Patching & Versions", "INFO",
                    "instance_info.csv",
                    f"DB: {self._db_version}",
                    f"Database version: {self._db_version}.",
                    "Continue applying quarterly database CPU patches.",
                ))

        # ORA-PATCH-004  Patch count in last 6 months
        recent = [
            p for p in patches
            if p.get("LAST_UPDATE_DATE")
            and (self._days_ago(p["LAST_UPDATE_DATE"]) or 999) <= 180
        ]
        if patches and not recent:
            self._add(Finding(
                "ORA-PATCH-004", "No patches applied in 6 months",
                "Patching & Versions", "HIGH",
                "ebs_patches.csv",
                "Patches in last 180 days: 0",
                "No patches applied in the last 6 months.",
                "Apply the latest quarterly CPU and recommended patches.",
                "CWE-1104",
            ))
        elif recent:
            self._add(Finding(
                "ORA-PATCH-004", "Patch activity summary",
                "Patching & Versions", "INFO",
                "ebs_patches.csv",
                f"Patches in last 180 days: {len(recent)}",
                f"{len(recent)} patch(es) applied in the last 6 months.",
                "Continue regular patching cadence.",
            ))

    # ═════════════════════════════════════════════════════════════════
    # Check Group 10 — Workflow & Approvals  (ORA-WF-001 .. 004)
    # ═════════════════════════════════════════════════════════════════

    def _check_workflow(self):
        components = self._data.get("ebs_workflow_components", [])
        stuck = self._data.get("ebs_workflow_stuck", [])
        errors = self._data.get("ebs_workflow_errors", [])

        # ORA-WF-001  Stuck workflow items
        stuck_gt100 = [
            r for r in stuck
            if int(r.get("ITEM_COUNT", "0") or "0") > 100
        ]
        if stuck_gt100:
            total = sum(int(r.get("ITEM_COUNT", "0") or "0") for r in stuck_gt100)
            details = "; ".join(
                f"{r.get('ITEM_TYPE','?')}({r.get('ITEM_COUNT','?')})"
                for r in stuck_gt100[:10]
            )
            self._add(Finding(
                "ORA-WF-001", "Stuck workflow items detected",
                "Workflow & Approvals", "MEDIUM",
                "ebs_workflow_stuck.csv",
                f"Stuck items ({total:,}): {details}",
                f"{total:,} workflow item(s) have been open > 30 days.",
                "Investigate and resolve stuck workflow items.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-WF-001", "No stuck workflow items")

        # ORA-WF-002  Notification mailer status
        mailers = [
            c for c in components
            if c.get("COMPONENT_TYPE") == "WF_MAILER"
        ]
        for m in mailers:
            status = m.get("COMPONENT_STATUS", "UNKNOWN")
            name = m.get("COMPONENT_NAME", "Mailer")
            if status not in ("RUNNING", "STARTED"):
                self._add(Finding(
                    "ORA-WF-002", "Workflow mailer not running",
                    "Workflow & Approvals", "MEDIUM",
                    "ebs_workflow_components.csv",
                    f"{name} status: {status}",
                    f"Workflow Notification Mailer '{name}' is '{status}'.",
                    "Start the mailer from the OAM console.",
                ))
            else:
                self._pass("ORA-WF-002", f"Mailer '{name}' is running")

        # ORA-WF-003  Workflow errors in last 30 days
        if errors:
            try:
                cnt = int(errors[0].get("ERROR_COUNT_30D", "0") or "0")
                if cnt > 50:
                    self._add(Finding(
                        "ORA-WF-003", "Workflow activity errors in last 30 days",
                        "Workflow & Approvals", "MEDIUM",
                        "ebs_workflow_errors.csv",
                        f"Errored activities (30d): {cnt:,}",
                        f"{cnt:,} workflow activity(ies) have errored.",
                        "Review and address root causes.",
                    ))
                else:
                    self._pass("ORA-WF-003", "Workflow error count acceptable")
            except (ValueError, IndexError):
                self._pass("ORA-WF-003", "Could not parse error count")
        else:
            self._vprint("  ebs_workflow_errors.csv not available, skipping")

        # ORA-WF-004  Background engine status
        agents = [
            c for c in components
            if "AGENT" in c.get("COMPONENT_TYPE", "").upper()
            or "Background" in c.get("COMPONENT_NAME", "")
        ]
        stopped = [
            c for c in agents
            if c.get("COMPONENT_STATUS") not in ("RUNNING", "STARTED")
        ]
        if stopped:
            details = "; ".join(
                f"{c['COMPONENT_NAME']}={c['COMPONENT_STATUS']}"
                for c in stopped
            )
            self._add(Finding(
                "ORA-WF-004", "Workflow background engine not running",
                "Workflow & Approvals", "LOW",
                "ebs_workflow_components.csv",
                f"Stopped engines: {details}",
                "Workflow background engines are not running.",
                "Start workflow engines from the OAM console.",
            ))
        elif agents:
            self._pass("ORA-WF-004", "Background engines running")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 11 — Application Configuration  (ORA-APP-001 .. 015)
    # ═════════════════════════════════════════════════════════════════

    def _check_app_config(self):
        active_resps = self._get_active_user_resps()

        # ORA-APP-001  Document sequencing not enabled (SOX)
        val = self._get_profile_value("UNIQUE:SEQ_NUMBERS")
        if not val or val.upper() not in ("A", "P"):
            self._add(Finding(
                "ORA-APP-001",
                "Document sequencing not enabled",
                "Application Configuration", "HIGH",
                "ebs_profile_options.csv",
                f"UNIQUE:SEQ_NUMBERS = {val or 'NULL'}",
                "Document sequencing is not enabled. SOX requires sequential "
                "numbering for financial documents.",
                "Set UNIQUE:SEQ_NUMBERS to 'A' (Always Used) at Site level.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-APP-001", "Document sequencing enabled")

        # ORA-APP-002  Financial approval limits
        approval_limits = self._data.get("ebs_approval_limits", [])
        unlimited = [
            r for r in approval_limits
            if r.get("AMOUNT_LIMIT")
            and self._safe_float(r["AMOUNT_LIMIT"]) > 999999999
        ]
        if unlimited:
            names = ", ".join(
                r.get("USER_NAME", "?") for r in unlimited[:10]
            )
            self._add(Finding(
                "ORA-APP-002",
                "Users with unlimited financial approval limits",
                "Application Configuration", "HIGH",
                "ebs_approval_limits.csv",
                f"Unlimited approvers ({len(unlimited)}): {names}",
                f"{len(unlimited)} user(s) have effectively unlimited "
                "approval limits.",
                "Set appropriate limits based on job role.",
                "CWE-269",
            ))
        elif approval_limits:
            self._pass("ORA-APP-002", "Approval limits within bounds")
        else:
            self._vprint("  ebs_approval_limits.csv not available, skipping")

        # ORA-APP-003  Invoice holds not configured
        hold_codes = self._data.get("ebs_hold_codes", [])
        active_holds = [
            h for h in hold_codes
            if h.get("HOLD_TYPE") == "SUPPLY"
            and self._is_active(h, "INACTIVE_DATE")
        ]
        if hold_codes and not active_holds:
            self._add(Finding(
                "ORA-APP-003",
                "No active AP invoice hold codes configured",
                "Application Configuration", "MEDIUM",
                "ebs_hold_codes.csv",
                "Active supply hold codes: 0",
                "No active invoice hold codes are configured.",
                "Configure hold codes for invoice validation.",
                "CWE-284",
            ))
        elif active_holds:
            self._pass("ORA-APP-003", f"Invoice hold codes active: {len(active_holds)}")
        else:
            self._vprint("  ebs_hold_codes.csv not available, skipping")

        # ORA-APP-004  Period open/close access too broad
        gl_users = set()
        for r in active_resps:
            rname = r.get("RESPONSIBILITY_NAME", "")
            if "General Ledger" in rname or "GL Super" in rname:
                gl_users.add(r["USER_NAME"])
        if len(gl_users) > 10:
            names = ", ".join(sorted(gl_users)[:10])
            self._add(Finding(
                "ORA-APP-004",
                "Too many users with GL period access",
                "Application Configuration", "HIGH",
                "ebs_user_responsibilities.csv",
                f"GL users ({len(gl_users)}): {names} ...",
                f"{len(gl_users)} users have GL responsibilities.",
                "Restrict to designated financial controllers.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-APP-004", "GL period access appropriately limited")

        # ORA-APP-005  Lookup values not frozen
        lookup_types = self._data.get("ebs_lookup_types", [])
        critical_lookups = {
            "YES_NO", "APPROVAL STATUS", "HOLD_STATUS",
            "PAYMENT METHOD", "AP_HOLD_CODE", "INVOICE TYPE",
            "CURRENCY_CODE", "JOURNAL_TYPE",
        }
        unfrozen = [
            r for r in lookup_types
            if r.get("LOOKUP_TYPE", "").upper() in critical_lookups
            and r.get("CUSTOMIZATION_LEVEL", "").upper() == "U"
        ]
        if unfrozen:
            types = ", ".join(r["LOOKUP_TYPE"] for r in unfrozen[:8])
            self._add(Finding(
                "ORA-APP-005",
                "Critical lookup types not frozen",
                "Application Configuration", "MEDIUM",
                "ebs_lookup_types.csv",
                f"Unfrozen lookups: {types}",
                f"{len(unfrozen)} critical lookup type(s) allow user-level "
                "customization.",
                "Set CUSTOMIZATION_LEVEL to 'S' (System).",
                "CWE-284",
            ))
        elif lookup_types:
            self._pass("ORA-APP-005", "Critical lookups properly restricted")
        else:
            self._vprint("  ebs_lookup_types.csv not available, skipping")

        # ORA-APP-006  Flexfield security rules
        flex_rules = self._data.get("ebs_flex_rules", [])
        if self._data.get("ebs_flex_rules") is not None and not flex_rules:
            self._add(Finding(
                "ORA-APP-006",
                "No flexfield security rules defined",
                "Application Configuration", "MEDIUM",
                "ebs_flex_rules.csv",
                "Flexfield security rules: none",
                "No flexfield value security rules are defined.",
                "Define rules to restrict cost center/account access.",
                "CWE-269",
            ))
        elif flex_rules:
            self._pass("ORA-APP-006", f"Flexfield rules: {len(flex_rules)}")
        else:
            self._vprint("  ebs_flex_rules.csv not available, skipping")

        # ORA-APP-007  OAF personalization unrestricted
        val = self._get_profile_value("FND_CUSTOM_OA_DEFINTION")
        val2 = self._get_profile_value("PERSONALIZE_SELF_SERVICE_DEFN")
        if (val and val.upper() == "Y") or (val2 and val2.upper() == "Y"):
            self._add(Finding(
                "ORA-APP-007",
                "OA Framework personalization unrestricted",
                "Application Configuration", "LOW",
                "ebs_profile_options.csv",
                f"FND_CUSTOM_OA_DEFINTION={val or 'NULL'}, "
                f"PERSONALIZE_SELF_SERVICE_DEFN={val2 or 'NULL'}",
                "OA Framework personalization is enabled.",
                "Set both to 'N' in production.",
            ))
        else:
            self._pass("ORA-APP-007", "OAF personalization restricted")

        # ORA-APP-008  Attachment storage directory
        val = self._get_profile_value("FND_ATTACHMENT_STORAGE")
        if val and val.upper() == "FILE":
            self._add(Finding(
                "ORA-APP-008",
                "Attachments stored on file system",
                "Application Configuration", "MEDIUM",
                "ebs_profile_options.csv",
                f"FND_ATTACHMENT_STORAGE = {val}",
                "Attachments are stored on the file system.",
                "Verify directory permissions are restricted (750).",
                "CWE-732",
            ))
        else:
            self._pass("ORA-APP-008", "Attachment storage acceptable")

        # ORA-APP-009  Alert configuration for security events
        alerts = self._data.get("ebs_alerts", [])
        sec_alerts = [
            a for a in alerts
            if a.get("ENABLED_FLAG") == "Y"
            and any(kw in a.get("ALERT_NAME", "").upper()
                    for kw in ("SECURITY", "LOGIN", "PASSWORD", "SYSADMIN"))
        ]
        if alerts and not sec_alerts:
            self._add(Finding(
                "ORA-APP-009",
                "No security alerts configured",
                "Application Configuration", "MEDIUM",
                "ebs_alerts.csv",
                "Active security alerts: 0",
                "No alert rules are configured for security events.",
                "Create alerts for failed logins, privilege changes, etc.",
                "CWE-778",
            ))
        elif sec_alerts:
            self._pass("ORA-APP-009", f"Security alerts: {len(sec_alerts)}")
        else:
            self._vprint("  ebs_alerts.csv not available, skipping")

        # ORA-APP-010  Function security — unregistered functions
        functions = self._data.get("ebs_form_functions", [])
        unattached = [
            f for f in functions
            if f.get("TYPE") == "WWW"
            and f.get("ATTACHED_TO_MENU", "").upper() == "N"
            and (self._days_ago(f.get("CREATION_DATE", "")) or 999) <= 365
        ]
        if len(unattached) > 20:
            self._add(Finding(
                "ORA-APP-010",
                "Unregistered web functions detected",
                "Application Configuration", "HIGH",
                "ebs_form_functions.csv",
                f"Unattached functions (recent): {len(unattached)}",
                f"{len(unattached)} recent web functions not on any menu.",
                "Review and disable unattached functions.",
                "CWE-284",
            ))
        elif functions:
            self._pass("ORA-APP-010", "Function security acceptable")
        else:
            self._vprint("  ebs_form_functions.csv not available, skipping")

        # ORA-APP-011  Multi-Org security not enforced
        val = self._get_profile_value("MO:SECURITY_PROFILE")
        val2 = self._get_profile_value("XLA_MO_SECURITY_PROFILE_LEVEL")
        if not val and not val2:
            self._add(Finding(
                "ORA-APP-011",
                "Multi-Org security profile not configured",
                "Application Configuration", "HIGH",
                "ebs_profile_options.csv",
                f"MO:SECURITY_PROFILE = {val or 'NULL'}",
                "Multi-Org security not set. Users may access all org data.",
                "Configure MO:SECURITY_PROFILE per responsibility.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-APP-011", "Multi-Org security configured")

        # ORA-APP-012  Descriptive flexfield PII exposure
        dff_config = self._data.get("ebs_dff_config", [])
        pii_tables = {
            "PER_ALL_PEOPLE_F", "HZ_PARTIES", "AP_SUPPLIERS",
            "HR_ALL_ORGANIZATION_UNITS",
        }
        unprotected = [
            d for d in dff_config
            if d.get("APPLICATION_TABLE_NAME", "").upper() in pii_tables
            and d.get("PROTECTED_FLAG", "").upper() == "N"
        ]
        if unprotected:
            self._add(Finding(
                "ORA-APP-012",
                "Unprotected DFFs on PII tables",
                "Application Configuration", "MEDIUM",
                "ebs_dff_config.csv",
                f"Unprotected DFFs on PII tables: {len(unprotected)}",
                f"{len(unprotected)} DFF(s) on PII tables are not protected.",
                "Set PROTECTED_FLAG = 'Y' for DFFs on PII tables.",
                "CWE-284",
            ))
        elif dff_config:
            self._pass("ORA-APP-012", "PII table DFFs protected")
        else:
            self._vprint("  ebs_dff_config.csv not available, skipping")

        # ORA-APP-013  Self-service modules exposed
        ss_keywords = ("iSupplier", "iRecruitment", "Self-Service",
                       "Internet Expenses")
        ss_resps = {}
        for r in active_resps:
            rname = r.get("RESPONSIBILITY_NAME", "")
            if any(kw in rname for kw in ss_keywords):
                ss_resps.setdefault(rname, set()).add(r["USER_NAME"])
        if ss_resps:
            details = "; ".join(
                f"{k}({len(v)})" for k, v in
                sorted(ss_resps.items(), key=lambda x: -len(x[1]))[:5]
            )
            self._add(Finding(
                "ORA-APP-013",
                "External self-service modules active",
                "Application Configuration", "MEDIUM",
                "ebs_user_responsibilities.csv",
                f"Self-service resps: {details}",
                f"{len(ss_resps)} external-facing self-service resp(s) active.",
                "Review assignments; ensure SSO/MFA protection.",
            ))
        else:
            self._pass("ORA-APP-013", "No external self-service modules")

        # ORA-APP-014  XML Gateway trading partners
        xml_tp = self._data.get("ebs_xml_gateway", [])
        external_tp = [
            t for t in xml_tp
            if t.get("PARTY_TYPE", "").upper() == "E"
        ]
        if external_tp:
            self._add(Finding(
                "ORA-APP-014",
                "XML Gateway trading partners configured",
                "Application Configuration", "MEDIUM",
                "ebs_xml_gateway.csv",
                f"External trading partners: {len(external_tp)}",
                f"{len(external_tp)} external trading partner(s) configured.",
                "Review partners; ensure encrypted transport and input validation.",
                "CWE-611",
            ))
        elif xml_tp:
            self._pass("ORA-APP-014", "No external XML Gateway partners")
        else:
            self._vprint("  ebs_xml_gateway.csv not available, skipping")

        # ORA-APP-015  Integration Repository services
        irep = self._data.get("ebs_irep_services", [])
        public_svcs = [
            s for s in irep
            if s.get("DEPLOYED_FLAG", "").upper() == "Y"
            and s.get("SCOPE_TYPE", "").upper() == "PUBLIC"
        ]
        if len(public_svcs) > 50:
            self._add(Finding(
                "ORA-APP-015",
                "Excessive public Integration Repository services",
                "Application Configuration", "HIGH",
                "ebs_irep_services.csv",
                f"Public deployed services: {len(public_svcs)}",
                f"{len(public_svcs)} IREP services are publicly deployed.",
                "Undeploy unnecessary services; set scope to PRIVATE.",
                "CWE-284",
            ))
        elif public_svcs:
            self._add(Finding(
                "ORA-APP-015",
                "Integration Repository services deployed",
                "Application Configuration", "INFO",
                "ebs_irep_services.csv",
                f"Public deployed services: {len(public_svcs)}",
                f"{len(public_svcs)} IREP service(s) are publicly deployed.",
                "Periodically review deployed services.",
            ))
        elif irep:
            self._pass("ORA-APP-015", "No public IREP services")
        else:
            self._vprint("  ebs_irep_services.csv not available, skipping")

    # ═════════════════════════════════════════════════════════════════
    # Summary / Filter / Report
    # ═════════════════════════════════════════════════════════════════

    def summary(self):
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity):
        threshold = self.SEVERITY_ORDER.get(min_severity, 5)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 5) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'=' * 72}{R}")
        print(f"{B}  Oracle EBS Offline Security Audit v{VERSION}  —  Scan Report{R}")
        print(f"  Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Data Source: {self.data_dir}")
        if self._instance_name:
            print(f"  Instance   : {self._instance_name} @ {self._host_name}")
        if self._ebs_version:
            print(f"  EBS Release: {self._ebs_version}")
        if self._db_version:
            print(f"  Database   : {self._db_version}")
        print(f"  Ref Date   : {self.ref_date}")
        print(f"  Findings   : {len(self.findings)}")
        print(f"{B}{'=' * 72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                self.SEVERITY_ORDER.get(f.severity, 5),
                f.category, f.rule_id,
            ),
        )

        for f in sorted_findings:
            sc = self.SEVERITY_COLOR.get(f.severity, "")
            print(f"{sc}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Source  : {f.source}")
            print(f"  Context : {f.context}")
            if f.cwe:
                print(f"  CWE     : {f.cwe}")
            print(f"  Issue   : {f.description}")
            print(f"  Fix     : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'=' * 72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    # ─── JSON ─────────────────────────────────────────────────────────

    def save_json(self, path):
        report = {
            "scanner": "oracle_ebs_offline_scanner",
            "version": VERSION,
            "generated": datetime.datetime.now().isoformat(),
            "data_source": self.data_dir,
            "instance": self._instance_name,
            "host": self._host_name,
            "ebs_version": self._ebs_version,
            "db_version": self._db_version,
            "reference_date": str(self.ref_date),
            "findings_count": len(self.findings),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    # ─── HTML ─────────────────────────────────────────────────────────

    def save_html(self, path):
        esc = html_mod.escape
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_style = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
            "INFO":     "background:#7f8c8d;color:#fff",
        }
        row_style = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
            "INFO":     "border-left:4px solid #7f8c8d",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                self.SEVERITY_ORDER.get(f.severity, 5),
                f.category, f.rule_id,
            ),
        )

        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;'
                f'font-size:0.8em;font-weight:bold">{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;'
                f'font-size:0.9em">{esc(f.rule_id)}</td>'
                f'<td style="padding:10px 14px;color:#a9b1d6">'
                f'{esc(f.category)}</td>'
                f'<td style="padding:10px 14px;font-weight:bold;color:#cdd6f4">'
                f'{esc(f.name)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;'
                f'font-size:0.85em;color:#89b4fa">{esc(f.source)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;'
                f'font-size:0.82em;color:#a6e3a1">'
                f'{esc(f.context or "")}</td>'
                f'<td style="padding:10px 14px;color:#cdd6f4">'
                f'{esc(f.cwe)}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" '
                f'data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="7" style="padding:6px 14px 14px 14px">'
                f'<div style="color:#bac2de;font-size:0.88em;margin-bottom:4px">'
                f'<b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#89dceb;font-size:0.88em">'
                f'<b>Fix:</b> {esc(f.recommendation)}</div>'
                f'</td></tr>'
            )

        categories = sorted({f.category for f in self.findings})
        cat_options = "".join(
            f'<option value="{esc(c)}">{esc(c)}</option>' for c in categories
        )

        html_content = textwrap.dedent(f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle EBS Offline Security Audit Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif;
          background: #1a1b2e; color: #cdd6f4; }}
  header {{ background: linear-gradient(135deg,#c0392b 0%,#1a1b2e 100%);
            padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #fff;
               margin-bottom: 8px; }}
  header .meta {{ color: #b0c4de; font-size: 0.95em; margin: 3px 0; }}
  .chips {{ padding: 20px 36px; background: #181825;
            border-bottom: 1px solid #313244;
            display: flex; flex-wrap: wrap; gap: 10px;
            align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e;
              display: flex; gap: 12px; flex-wrap: wrap;
              border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #c0392b; color: #fff; padding: 12px 14px;
        text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.1); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px;
                  color: #a6e3a1; font-size: 1.2em; }}
</style>
</head>
<body>
<header>
  <h1>Oracle EBS Offline Security Audit Report</h1>
  <p class="meta">Scanner: Oracle EBS Offline Scanner v{esc(VERSION)}</p>
  <p class="meta">Data Source: {esc(self.data_dir)}</p>
  <p class="meta">Instance: {esc(self._instance_name)} @ {esc(self._host_name)}</p>
  <p class="meta">EBS Release: {esc(self._ebs_version)}</p>
  <p class="meta">Database: {esc(self._db_version)}</p>
  <p class="meta">Reference Date: {esc(str(self.ref_date))}</p>
  <p class="meta">Generated: {esc(now)}</p>
  <p class="meta">Total Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
  <label>Severity:</label>
  {chip_html}
</div>
<div class="filters">
  <select id="sevFilter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option>CRITICAL</option><option>HIGH</option>
    <option>MEDIUM</option><option>LOW</option><option>INFO</option>
  </select>
  <select id="catFilter" onchange="applyFilters()">
    <option value="">All Categories</option>
    {cat_options}
  </select>
  <input type="text" id="txtFilter" placeholder="Search ..."
         oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
""")
        if not self.findings:
            html_content += (
                '<div class="no-findings">'
                "No findings — Oracle EBS data is clean!</div>\n"
            )
        else:
            html_content += (
                '<table id="ft">\n<thead><tr>\n'
                "  <th>Severity</th><th>Rule ID</th><th>Category</th>"
                "<th>Finding</th>\n"
                "  <th>Source</th><th>Context</th><th>CWE</th>\n"
                f"</tr></thead>\n<tbody>{rows_html}</tbody>\n</table>\n"
            )

        html_content += textwrap.dedent("""\
</div>
<script>
function applyFilters(){
  var sv=document.getElementById('sevFilter').value.toUpperCase();
  var ca=document.getElementById('catFilter').value.toLowerCase();
  var tx=document.getElementById('txtFilter').value.toLowerCase();
  document.querySelectorAll('#ft tbody tr').forEach(function(r){
    var rs=(r.getAttribute('data-severity')||'').toUpperCase();
    var rc=(r.getAttribute('data-category')||'').toLowerCase();
    var rt=r.textContent.toLowerCase();
    r.style.display=(!sv||rs===sv)&&(!ca||rc.includes(ca))&&(!tx||rt.includes(tx))?'':'none';
  });
}
</script>
</body>
</html>
""")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ─────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="oracle_ebs_offline_scanner",
        description=(
            f"Oracle EBS Offline Security Audit Scanner v{VERSION} — "
            "Analyze CSV exports from Oracle EBS databases without "
            "requiring live database access (125 checks, zero dependencies)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Workflow:
              1. Run the SQL queries in  export_ebs_audit_data.sql  against
                 your Oracle EBS database (connect as APPS).
              2. Export each result set to the named CSV file.
              3. Place all CSV files in a single directory.
              4. Run this scanner against that directory.

            Example:
              python oracle_ebs_offline_scanner.py ./ebs_export/
              python oracle_ebs_offline_scanner.py ./ebs_export/ \\
                  --json report.json --html report.html --severity HIGH

            Required CSV files (4):
              instance_info.csv            ebs_users.csv
              ebs_user_responsibilities.csv ebs_profile_options.csv

            Optional CSV files (16):
              ebs_responsibilities.csv     ebs_concurrent_programs.csv
              ebs_request_group_access.csv ebs_concurrent_requests.csv
              ebs_audit_config.csv         ebs_patches.csv
              ebs_workflow_components.csv  ebs_workflow_stuck.csv
              ebs_workflow_errors.csv      ebs_login_audit_old.csv
              db_users.csv                 db_role_privs.csv
              db_tab_privs.csv             db_links.csv
              db_profiles.csv              db_parameters.csv
        """),
    )

    parser.add_argument(
        "data_dir",
        help="Directory containing the exported CSV files",
    )
    parser.add_argument(
        "--ref-date",
        metavar="YYYY-MM-DD",
        help="Reference date for age calculations (default: today). "
             "Use the date the data was exported.",
    )
    parser.add_argument(
        "--severity",
        default="INFO",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity to report (default: INFO)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings as JSON to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as self-contained HTML to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (loaded files, passed checks, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"oracle_ebs_offline_scanner v{VERSION}",
    )

    args = parser.parse_args()

    if not os.path.isdir(args.data_dir):
        parser.error(f"Data directory not found: {args.data_dir}")

    ref_date = None
    if args.ref_date:
        try:
            ref_date = datetime.datetime.strptime(
                args.ref_date, "%Y-%m-%d"
            ).date()
        except ValueError:
            parser.error(f"Invalid date format: {args.ref_date} (use YYYY-MM-DD)")

    print(f"[*] Oracle EBS Offline Security Audit Scanner v{VERSION}")

    scanner = OracleEBSOfflineScanner(
        data_dir=args.data_dir,
        verbose=args.verbose,
        ref_date=ref_date,
    )

    if not scanner.load_data():
        print("[!] Cannot proceed — required CSV files are missing.",
              file=sys.stderr)
        sys.exit(2)

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()
