#!/usr/bin/env python3
"""
Oracle E-Business Suite Security Audit Scanner v1.2.0

Connects to an Oracle EBS database and performs 125 security audit checks
across user management, access controls, profile options, segregation
of duties, database hardening, patching, and more.

Dependency: oracledb  (pip install oracledb)
Usage:
    python oracle_ebs_scanner.py --host HOST --port 1521 --service ORCL --user APPS
    python oracle_ebs_scanner.py --dsn "host:port/service" --user APPS --json out.json

Copyright (c) 2025 — MIT License
"""

import argparse
import datetime
import html as html_mod
import json
import os
import sys
import getpass
import textwrap

try:
    import oracledb
except ImportError:
    print(
        "ERROR: 'oracledb' package is required.\n"
        "  Install with:  pip install oracledb",
        file=sys.stderr,
    )
    sys.exit(2)

__version__ = "1.2.0"
VERSION = __version__

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
        self.source = source            # SQL query / table / API endpoint
        self.context = context          # key = value or affected entity
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe

    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}


# ─────────────────────────────────────────────────────────────────────────
# Oracle EBS Scanner
# ─────────────────────────────────────────────────────────────────────────

class OracleEBSScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
        "INFO":     "\033[97m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    # ── Default / seeded EBS accounts that should be end-dated ────────

    DEFAULT_ACCOUNTS = (
        "SYSADMIN", "GUEST", "OPERATIONS", "INITIAL_SETUP",
        "ANONYMOUS", "AUTOINSTALL", "WIZARD", "IBEGUEST",
        "ASADMIN", "ASGADMIN", "FEEDER SYSTEM",
        "IRC_EMP_GUEST", "IRC_EXT_GUEST", "SYSADMIN1",
    )

    # ── Sensitive responsibilities and their risk level ───────────────

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

    # ── Segregation-of-Duties conflict pairs ─────────────────────────

    SOD_CONFLICTS = [
        ("%Payable%",       "%Receivable%",      "AP/AR",
         "Can create payable invoices and receive AR payments"),
        ("%Payable%",       "%Purchasing%",       "AP/PO",
         "Can create POs and approve AP invoices"),
        ("%General Ledger%","%Payable%",          "GL/AP",
         "Can post journals and manage payables"),
        ("%Purchasing%",    "%Inventory%",        "PO/INV",
         "Can order goods and receive inventory"),
        ("%System Admin%",  "%Payable%",          "Admin/AP",
         "Can create users and process payments"),
        ("%Human Resource%","%Payable%",          "HR/AP",
         "Can maintain employees and process payments"),
        # ── Phase 1 additions ────────────────────────────────────────
        ("%Receivable%",    "%Cash Management%",  "AR/CM",
         "Can create customer receipts and reconcile bank statements"),
        ("%General Ledger%","%Journal%",          "GL/JE",
         "Can create and post journal entries without independent review"),
        ("%Purchasing%",    "%Receiving%",        "PO/RECV",
         "Can create purchase orders and confirm receipt of goods"),
        ("%Inventory%",     "%Inventory%Adjust%", "INV/ADJ",
         "Can adjust inventory quantities and approve adjustments"),
        ("%Fixed Asset%",   "%Fixed Asset%",      "FA/FA",
         "Can add assets and retire or transfer them"),
        ("%Cash Management%","%Cash Management%", "CM/RECON",
         "Can enter bank statements and reconcile accounts"),
        ("%Human Resource%","%Payroll%",          "HR/PAY",
         "Can create employees and process payroll runs"),
        ("%Payable%",       "%Supplier%",         "AP/VENDOR",
         "Can create vendors and approve supplier payments"),
        ("%Purchasing%",    "%Buyer%",            "PO/BUYER",
         "Can act as buyer and approve own purchase orders"),
        ("%General Ledger%","%Period%",           "GL/PERIOD",
         "Can open/close accounting periods and post journals"),
        ("%Payable%",       "%Hold%",             "AP/HOLD",
         "Can place and release invoice holds and approve payments"),
        ("%Order Management%","%Receivable%",     "OM/AR",
         "Can enter sales orders and post receivable receipts"),
        ("%Purchasing%",    "%General Ledger%",   "PO/GL",
         "Can create purchasing commitments and post GL journals"),
        ("%System Admin%",  "%General Ledger%",   "Admin/GL",
         "Can administer system and post financial transactions"),
    ]

    # ── Critical tables that must have audit trail enabled ────────────

    CRITICAL_AUDIT_TABLES = [
        ("FND",   "FND_USER",                       "User account master"),
        ("FND",   "FND_USER_RESP_GROUPS_DIRECT",    "User-responsibility assignments"),
        ("SQLAP", "AP_CHECKS_ALL",                  "AP payment checks"),
        ("SQLAP", "AP_INVOICES_ALL",                "AP invoices"),
        ("SQLAP", "AP_INVOICE_DISTRIBUTIONS_ALL",   "AP invoice distributions"),
        ("SQLGL", "GL_JE_HEADERS",                  "GL journal headers"),
        ("SQLGL", "GL_JE_LINES",                    "GL journal lines"),
        ("PO",    "PO_HEADERS_ALL",                 "Purchase orders"),
        ("PO",    "PO_REQUISITION_HEADERS_ALL",     "Purchase requisitions"),
        ("AR",    "AR_CASH_RECEIPTS_ALL",           "AR cash receipts"),
        ("INV",   "MTL_MATERIAL_TRANSACTIONS",      "Inventory transactions"),
        ("PER",   "PER_ALL_PEOPLE_F",               "Employee master"),
        ("PAY",   "PAY_ELEMENT_ENTRIES_F",          "Payroll element entries"),
    ]

    # ── Security-critical profile options ─────────────────────────────

    SECURITY_PROFILES = [
        # (profile_name, expected, description, severity_if_fail, cwe)
        ("SIGNON_PASSWORD_LENGTH",       ">=8",     "Minimum password length",          "HIGH",     "CWE-521"),
        ("SIGNON_PASSWORD_HARD_TO_GUESS","Y",       "Password complexity enforcement",  "HIGH",     "CWE-521"),
        ("SIGNON_PASSWORD_NO_REUSE",     ">=6",     "Password history count",           "MEDIUM",   "CWE-521"),
        ("SIGNON_PASSWORD_FAILURE_LIMIT",">=3",     "Failed login attempt limit",       "CRITICAL", "CWE-307"),
        ("ICX_SESSION_TIMEOUT",          "<=30",    "Session timeout (minutes)",        "MEDIUM",   "CWE-613"),
        ("GUEST_USER_PWD",               "NOT_DEFAULT", "Guest password not default",   "HIGH",     "CWE-798"),
        ("FND_DIAGNOSTICS",              "N",       "Diagnostics disabled",             "MEDIUM",   "CWE-215"),
        ("AFLOG_ENABLED",                "N",       "Application logging disabled",     "LOW",      "CWE-532"),
        ("APPS_SERVLET_AGENT",           "HTTPS",   "Servlet agent uses HTTPS",         "HIGH",     "CWE-319"),
        ("APPS_FRAMEWORK_AGENT",         "HTTPS",   "Framework agent uses HTTPS",       "HIGH",     "CWE-319"),
        ("FND_CUSTOM_OA_DEFINTION",      "N",       "OA customization disabled",        "LOW",      ""),
        ("SIGN_ON_NOTIFICATION",         "Y",       "Login notification enabled",       "LOW",      ""),
        ("ICX_LIMIT_CONNECT",            ">=1",     "Concurrent session limit set",     "MEDIUM",   "CWE-400"),
        ("SIGNONAUDIT:LEVEL",            ">=C",     "Sign-on audit level (A-D)",        "MEDIUM",   "CWE-778"),
    ]

    # ── Dangerous concurrent programs ─────────────────────────────────

    DANGEROUS_PROGRAMS = (
        "FNDCPASS", "FNDSLOAD", "FNDLOAD", "WFLOAD", "CONCSUB",
        "FNDSCARU", "FNDMDGEN", "AABORDFR", "XLOLOAD",
    )

    # ── Default Oracle DB accounts ────────────────────────────────────

    DEFAULT_DB_ACCOUNTS = (
        "SYS", "SYSTEM", "DBSNMP", "SCOTT", "OUTLN", "MDSYS",
        "ORDSYS", "CTXSYS", "DSSYS", "PERFSTAT", "WKPROXY",
        "WKSYS", "WK_TEST", "XDB", "WMSYS", "DIP", "EXFSYS",
    )

    # ── Sensitive Oracle packages ─────────────────────────────────────

    SENSITIVE_PACKAGES = (
        "UTL_FILE", "UTL_HTTP", "UTL_SMTP", "UTL_TCP", "UTL_INADDR",
        "DBMS_SQL", "DBMS_JAVA", "DBMS_BACKUP_RESTORE",
        "DBMS_SYS_SQL", "DBMS_RANDOM", "DBMS_LOB",
        "DBMS_ADVISOR", "DBMS_OBFUSCATION_TOOLKIT",
    )

    # ─────────────────────────────────────────────────────────────────
    # Init
    # ─────────────────────────────────────────────────────────────────

    def __init__(self, dsn, user, password, verbose=False):
        self.dsn = dsn
        self.user = user
        self.password = password
        self.verbose = verbose
        self.findings: list = []
        self.conn = None
        self._ebs_version = ""
        self._db_version = ""
        self._instance_name = ""
        self._host_name = ""
        self._checks_run = 0
        self._checks_passed = 0

    # ─────────────────────────────────────────────────────────────────
    # Connection
    # ─────────────────────────────────────────────────────────────────

    def connect(self):
        """Establish connection to the Oracle EBS database."""
        self._vprint(f"Connecting to {self.dsn} as {self.user} ...")
        try:
            self.conn = oracledb.connect(
                user=self.user, password=self.password, dsn=self.dsn,
            )
            self._vprint("Connected successfully.")
            self._gather_instance_info()
            return True
        except oracledb.Error as e:
            self._warn(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Close the database connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    # ─────────────────────────────────────────────────────────────────
    # Query helpers
    # ─────────────────────────────────────────────────────────────────

    def _query(self, sql, params=None):
        """Execute SQL and return list of dicts."""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, params or [])
            cols = [c[0] for c in cur.description] if cur.description else []
            rows = cur.fetchall()
            cur.close()
            return [dict(zip(cols, row)) for row in rows]
        except oracledb.Error as e:
            self._vprint(f"  Query error: {e}")
            return []

    def _scalar(self, sql, params=None):
        """Execute SQL and return the first column of the first row."""
        try:
            cur = self.conn.cursor()
            cur.execute(sql, params or [])
            row = cur.fetchone()
            cur.close()
            return row[0] if row else None
        except oracledb.Error as e:
            self._vprint(f"  Query error: {e}")
            return None

    def _count(self, sql, params=None):
        """Execute a COUNT query and return the integer result."""
        val = self._scalar(sql, params)
        return int(val) if val is not None else 0

    # ─────────────────────────────────────────────────────────────────
    # Logging helpers
    # ─────────────────────────────────────────────────────────────────

    def _add(self, finding):
        self.findings.append(finding)

    def _vprint(self, msg):
        if self.verbose:
            print(f"  [v] {msg}")

    def _warn(self, msg):
        print(f"  [!] {msg}", file=sys.stderr)

    def _pass(self, check_id, name):
        self._checks_passed += 1
        self._vprint(f"  PASS  {check_id}: {name}")

    # ─────────────────────────────────────────────────────────────────
    # Instance info
    # ─────────────────────────────────────────────────────────────────

    def _gather_instance_info(self):
        """Collect database and EBS version information."""
        row = self._query("SELECT BANNER FROM V$VERSION WHERE ROWNUM = 1")
        if row:
            self._db_version = row[0].get("BANNER", "Unknown")
            self._vprint(f"DB Version : {self._db_version}")

        row = self._query(
            "SELECT INSTANCE_NAME, HOST_NAME FROM V$INSTANCE WHERE ROWNUM = 1"
        )
        if row:
            self._instance_name = row[0].get("INSTANCE_NAME", "Unknown")
            self._host_name = row[0].get("HOST_NAME", "Unknown")
            self._vprint(f"Instance   : {self._instance_name} @ {self._host_name}")

        row = self._query(
            "SELECT RELEASE_NAME FROM FND_PRODUCT_GROUPS WHERE ROWNUM = 1"
        )
        if row:
            self._ebs_version = row[0].get("RELEASE_NAME", "Unknown")
            self._vprint(f"EBS Release: {self._ebs_version}")

    # ─────────────────────────────────────────────────────────────────
    # Profile option helper
    # ─────────────────────────────────────────────────────────────────

    def _get_profile_value(self, profile_name, level_id=10001):
        """Get a profile option value at the specified level (default: Site=10001)."""
        return self._scalar(
            "SELECT fpov.PROFILE_OPTION_VALUE "
            "FROM FND_PROFILE_OPTION_VALUES fpov "
            "JOIN FND_PROFILE_OPTIONS fpo "
            "  ON fpov.PROFILE_OPTION_ID = fpo.PROFILE_OPTION_ID "
            "WHERE fpo.PROFILE_OPTION_NAME = :1 "
            "  AND fpov.LEVEL_ID = :2 "
            "  AND ROWNUM = 1",
            [profile_name, level_id],
        )

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

        self._checks_run = sum(1 for _ in groups)

    # ═════════════════════════════════════════════════════════════════
    # Check Group 1 — User Account Security  (ORA-USER-001 .. 008)
    # ═════════════════════════════════════════════════════════════════

    def _check_users(self):

        # ORA-USER-001  Default / seeded accounts still active
        placeholders = ", ".join(f":{i}" for i in range(len(self.DEFAULT_ACCOUNTS)))
        rows = self._query(
            f"SELECT USER_NAME, "
            f"  TO_CHAR(START_DATE,'YYYY-MM-DD') AS START_DT, "
            f"  TO_CHAR(LAST_LOGON_DATE,'YYYY-MM-DD') AS LAST_LOGIN "
            f"FROM FND_USER "
            f"WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            f"  AND USER_NAME IN ({placeholders}) "
            f"ORDER BY USER_NAME",
            list(self.DEFAULT_ACCOUNTS),
        )
        if rows:
            names = ", ".join(r["USER_NAME"] for r in rows)
            self._add(Finding(
                "ORA-USER-001", "Default accounts still active",
                "User Security", "HIGH",
                "FND_USER", f"Active defaults: {names}",
                f"{len(rows)} default/seeded EBS account(s) remain active. "
                "These accounts are well-known targets for attackers.",
                "End-date or disable all default EBS accounts that are not "
                "operationally required. Review SYSADMIN access separately.",
                "CWE-798",
            ))
        else:
            self._pass("ORA-USER-001", "No active default accounts")

        # ORA-USER-002  Inactive users (no login > 90 days) still active
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND LAST_LOGON_DATE < SYSDATE - 90"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-002", "Inactive users not disabled",
                "User Security", "MEDIUM",
                "FND_USER", f"Inactive > 90 days: {cnt} users",
                f"{cnt} active user(s) have not logged in for more than 90 days.",
                "Review and end-date accounts that are no longer in use. "
                "Implement an automated account recertification process.",
                "CWE-285",
            ))
        else:
            self._pass("ORA-USER-002", "No stale inactive users")

        # ORA-USER-003  Users without an end date
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE END_DATE IS NULL "
            "  AND USER_NAME NOT IN ('SYSADMIN','AUTOINSTALL')"
        )
        if cnt > 20:
            self._add(Finding(
                "ORA-USER-003", "Users without end date",
                "User Security", "LOW",
                "FND_USER", f"No end date: {cnt} users",
                f"{cnt} user accounts have no end date set, meaning they never "
                "expire automatically.",
                "Set end dates on user accounts aligned with contract or "
                "employment end dates.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-003", "User end-date coverage acceptable")

        # ORA-USER-004  Orphan accounts (no employee link)
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE EMPLOYEE_ID IS NULL "
            "  AND PERSON_PARTY_ID IS NULL "
            "  AND (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND USER_NAME NOT IN ("
            "    'SYSADMIN','GUEST','AUTOINSTALL','ANONYMOUS',"
            "    'IBEGUEST','INITIAL_SETUP','WIZARD')"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-004", "Orphan accounts without employee link",
                "User Security", "MEDIUM",
                "FND_USER", f"Orphan accounts: {cnt}",
                f"{cnt} active user(s) have no link to an employee or person "
                "record, making accountability difficult.",
                "Link user accounts to HR person records or end-date accounts "
                "that are no longer needed.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-004", "No orphan accounts")

        # ORA-USER-005  Terminated employees with active EBS accounts
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER fu "
            "JOIN PER_ALL_PEOPLE_F papf ON fu.EMPLOYEE_ID = papf.PERSON_ID "
            "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND SYSDATE BETWEEN papf.EFFECTIVE_START_DATE "
            "      AND papf.EFFECTIVE_END_DATE "
            "  AND papf.CURRENT_EMPLOYEE_FLAG IS NULL"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-005", "Terminated employees with active accounts",
                "User Security", "CRITICAL",
                "FND_USER + PER_ALL_PEOPLE_F",
                f"Terminated but active: {cnt} users",
                f"{cnt} user(s) linked to terminated employees still have "
                "active EBS accounts.",
                "Immediately end-date accounts for terminated employees. "
                "Implement automated termination feed from HR to FND_USER.",
                "CWE-285",
            ))
        else:
            self._pass("ORA-USER-005", "No terminated employees with active accounts")

        # ORA-USER-006  Shared / generic accounts detected
        rows = self._query(
            "SELECT USER_NAME, DESCRIPTION FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND (UPPER(USER_NAME) LIKE '%SHARED%' "
            "    OR UPPER(USER_NAME) LIKE '%GENERIC%' "
            "    OR UPPER(USER_NAME) LIKE '%TEMPUSER%' "
            "    OR UPPER(USER_NAME) LIKE '%TESTUSER%' "
            "    OR UPPER(DESCRIPTION) LIKE '%SHARED%' "
            "    OR UPPER(DESCRIPTION) LIKE '%GENERIC%') "
            "ORDER BY USER_NAME"
        )
        if rows:
            names = ", ".join(r["USER_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-USER-006", "Shared or generic accounts detected",
                "User Security", "HIGH",
                "FND_USER", f"Shared/generic: {names}",
                f"{len(rows)} account(s) appear to be shared or generic based "
                "on naming conventions. Shared accounts prevent accountability.",
                "Replace shared accounts with individual named accounts. "
                "If service accounts are needed, restrict them to "
                "non-interactive responsibilities.",
                "CWE-287",
            ))
        else:
            self._pass("ORA-USER-006", "No shared/generic accounts")

        # ORA-USER-007  Users who have never logged in
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND LAST_LOGON_DATE IS NULL "
            "  AND CREATION_DATE < SYSDATE - 30"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-007", "Users never logged in",
                "User Security", "LOW",
                "FND_USER", f"Never logged in: {cnt} users",
                f"{cnt} active account(s) created more than 30 days ago have "
                "never been used.",
                "Review and end-date unused accounts. They represent "
                "unnecessary attack surface.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-007", "No unused never-logged-in accounts")

        # ORA-USER-008  Total active user count review
        total = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE END_DATE IS NULL OR END_DATE > SYSDATE"
        )
        self._add(Finding(
            "ORA-USER-008", "Active user population summary",
            "User Security", "INFO",
            "FND_USER", f"Total active users: {total}",
            f"The EBS instance has {total} active user accounts.",
            "Periodically review the user population to ensure it aligns "
            "with the actual workforce and licensed seat count.",
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
                    "FND_PROFILE_OPTION_VALUES",
                    f"SELF_REGISTRATION_ENABLED = Y, APPROVAL = {approval or 'NULL'}",
                    "Self-service user registration is enabled without an "
                    "approval workflow. Anyone can create an EBS account.",
                    "Disable self-service registration or enable the approval "
                    "workflow via SELF_REGISTRATION_APPROVAL = 'Y'.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"APPS_SSO = {val or 'NULL'}",
                "Oracle EBS is using local authentication instead of SSO/OAM. "
                "Local auth lacks MFA support and centralised credential control.",
                "Integrate Oracle Access Manager (OAM) or another SSO provider "
                "to enable MFA and centralised identity management.",
                "CWE-308",
            ))
        else:
            self._pass("ORA-USER-010", "SSO/External authentication configured")

        # ORA-USER-011  User accounts created recently without HR link
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND CREATION_DATE > SYSDATE - 30 "
            "  AND EMPLOYEE_ID IS NULL "
            "  AND PERSON_PARTY_ID IS NULL "
            "  AND USER_NAME NOT IN ("
            "    'SYSADMIN','GUEST','AUTOINSTALL','ANONYMOUS',"
            "    'IBEGUEST','INITIAL_SETUP','WIZARD')"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-011",
                "Recent accounts created without HR link",
                "User Security", "MEDIUM",
                "FND_USER",
                f"New unlinked accounts (30d): {cnt}",
                f"{cnt} user account(s) created in the last 30 days have no "
                "link to an employee or person record, suggesting they may "
                "have been created outside the normal provisioning process.",
                "Review recently created accounts and ensure they follow the "
                "approved user provisioning workflow with HR linkage.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-USER-011", "Recent accounts properly linked")

        # ORA-USER-012  Password hash algorithm strength
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND ENCRYPTED_USER_PASSWORD IS NOT NULL "
            "  AND LENGTH(ENCRYPTED_USER_PASSWORD) < 40"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-012", "Weak password hashes detected",
                "User Security", "HIGH",
                "FND_USER",
                f"Weak hashes: {cnt} users",
                f"{cnt} active user(s) appear to have passwords stored with "
                "a legacy hash algorithm (short hash length).",
                "Force password resets for affected users to upgrade to the "
                "current hashing algorithm. Apply the latest EBS security patches.",
                "CWE-916",
            ))
        else:
            self._pass("ORA-USER-012", "Password hash lengths acceptable")

        # ORA-USER-013  APPS schema direct login detection
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_LOGINS "
            "WHERE START_TIME > SYSDATE - 30 "
            "  AND LOGIN_TYPE = 'FORM' "
            "  AND LOGIN_NAME = 'APPS'"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-USER-013", "Direct APPS schema login detected",
                "User Security", "HIGH",
                "FND_LOGINS",
                f"APPS logins (30d): {cnt}",
                f"{cnt} direct login(s) using the APPS database account "
                "detected in the last 30 days. The APPS schema has full "
                "access to all EBS data.",
                "Restrict APPS schema access to application tier connections only. "
                "Implement proxy authentication for developers needing DB access.",
                "CWE-250",
            ))
        else:
            self._pass("ORA-USER-013", "No direct APPS logins")

        # ORA-USER-014  Users with SYSADMIN performing business transactions
        rows = self._query(
            "SELECT DISTINCT fu.USER_NAME "
            "FROM FND_USER fu "
            "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
            "  ON fu.USER_ID = furg.USER_ID "
            "JOIN FND_RESPONSIBILITY_TL frt "
            "  ON furg.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
            "  AND furg.RESPONSIBILITY_APPLICATION_ID = frt.APPLICATION_ID "
            "  AND frt.LANGUAGE = 'US' "
            "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
            "  AND frt.RESPONSIBILITY_NAME = 'System Administrator' "
            "  AND fu.USER_ID IN ("
            "    SELECT DISTINCT furg2.USER_ID "
            "    FROM FND_USER_RESP_GROUPS_DIRECT furg2 "
            "    JOIN FND_RESPONSIBILITY_TL frt2 "
            "      ON furg2.RESPONSIBILITY_ID = frt2.RESPONSIBILITY_ID "
            "      AND furg2.RESPONSIBILITY_APPLICATION_ID = frt2.APPLICATION_ID "
            "      AND frt2.LANGUAGE = 'US' "
            "    WHERE (furg2.END_DATE IS NULL OR furg2.END_DATE > SYSDATE) "
            "      AND (frt2.RESPONSIBILITY_NAME LIKE '%Payable%' "
            "        OR frt2.RESPONSIBILITY_NAME LIKE '%Receivable%' "
            "        OR frt2.RESPONSIBILITY_NAME LIKE '%General Ledger%' "
            "        OR frt2.RESPONSIBILITY_NAME LIKE '%Purchasing%') "
            "  ) "
            "ORDER BY fu.USER_NAME"
        )
        if rows:
            names = ", ".join(r["USER_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-USER-014",
                "SysAdmin users with financial responsibilities",
                "User Security", "HIGH",
                "FND_USER_RESP_GROUPS_DIRECT",
                f"SysAdmin + Finance ({len(rows)}): {names}",
                f"{len(rows)} user(s) hold both System Administrator and "
                "financial responsibilities. IT administrators should not "
                "perform business transactions.",
                "Remove financial responsibilities from IT admin accounts or "
                "remove SysAdmin from users who need financial access.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"CONCURRENT_LOGIN_LIMIT = {val or 'NULL'}",
                "No limit on simultaneous logins per user account. Compromised "
                "credentials can be used from multiple locations simultaneously.",
                "Set CONCURRENT_LOGIN_LIMIT to restrict parallel sessions per user.",
                "CWE-400",
            ))
        else:
            self._pass("ORA-USER-015", "Concurrent login limit set")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 2 — Password & Authentication  (ORA-PWD-001 .. 006)
    # ═════════════════════════════════════════════════════════════════

    def _check_passwords(self):

        # ORA-PWD-001  Password never changed since creation
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND (PASSWORD_DATE IS NULL "
            "    OR PASSWORD_DATE = CREATION_DATE)"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-PWD-001", "Password never changed since creation",
                "Password & Auth", "HIGH",
                "FND_USER", f"Password unchanged: {cnt} users",
                f"{cnt} active user(s) have never changed their password from "
                "the initial value set at account creation.",
                "Enforce password change on first login. Review and force "
                "password resets for affected accounts.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-PWD-001", "All users have changed passwords")

        # ORA-PWD-002  Password older than 90 days
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER "
            "WHERE (END_DATE IS NULL OR END_DATE > SYSDATE) "
            "  AND PASSWORD_DATE IS NOT NULL "
            "  AND PASSWORD_DATE < SYSDATE - 90"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-PWD-002", "Passwords older than 90 days",
                "Password & Auth", "MEDIUM",
                "FND_USER", f"Password age > 90d: {cnt} users",
                f"{cnt} active user(s) have passwords that are more than "
                "90 days old.",
                "Enforce a maximum password age policy of 60-90 days via "
                "the SIGNON_PASSWORD_LIFE profile option.",
                "CWE-262",
            ))
        else:
            self._pass("ORA-PWD-002", "Password age within acceptable range")

        # ORA-PWD-003  Failed login limit (profile option)
        val = self._get_profile_value("SIGNON_PASSWORD_FAILURE_LIMIT")
        if val is None or val == "" or val == "0":
            self._add(Finding(
                "ORA-PWD-003", "Failed login limit not configured",
                "Password & Auth", "CRITICAL",
                "FND_PROFILE_OPTION_VALUES",
                f"SIGNON_PASSWORD_FAILURE_LIMIT = {val or 'NULL'}",
                "The failed login attempt limit is not set or is zero, "
                "allowing unlimited brute-force attempts.",
                "Set SIGNON_PASSWORD_FAILURE_LIMIT to 5 or less at Site level.",
                "CWE-307",
            ))
        else:
            try:
                if int(val) > 10:
                    self._add(Finding(
                        "ORA-PWD-003", "Failed login limit too high",
                        "Password & Auth", "MEDIUM",
                        "FND_PROFILE_OPTION_VALUES",
                        f"SIGNON_PASSWORD_FAILURE_LIMIT = {val}",
                        f"Failed login limit is set to {val}, which may be "
                        "too permissive for brute-force protection.",
                        "Reduce SIGNON_PASSWORD_FAILURE_LIMIT to 5 or less.",
                        "CWE-307",
                    ))
                else:
                    self._pass("ORA-PWD-003", "Failed login limit configured")
            except ValueError:
                self._pass("ORA-PWD-003", "Failed login limit configured")

        # ORA-PWD-004  Minimum password length
        val = self._get_profile_value("SIGNON_PASSWORD_LENGTH")
        if val is None or val == "":
            self._add(Finding(
                "ORA-PWD-004", "Minimum password length not set",
                "Password & Auth", "HIGH",
                "FND_PROFILE_OPTION_VALUES",
                "SIGNON_PASSWORD_LENGTH = NULL",
                "No minimum password length is enforced, allowing single-"
                "character passwords.",
                "Set SIGNON_PASSWORD_LENGTH to 8 or higher at Site level.",
                "CWE-521",
            ))
        else:
            try:
                if int(val) < 8:
                    self._add(Finding(
                        "ORA-PWD-004", "Minimum password length too short",
                        "Password & Auth", "MEDIUM",
                        "FND_PROFILE_OPTION_VALUES",
                        f"SIGNON_PASSWORD_LENGTH = {val}",
                        f"Minimum password length is {val}, which is below "
                        "the recommended minimum of 8 characters.",
                        "Increase SIGNON_PASSWORD_LENGTH to at least 8.",
                        "CWE-521",
                    ))
                else:
                    self._pass("ORA-PWD-004", "Password length acceptable")
            except ValueError:
                self._pass("ORA-PWD-004", "Password length configured")

        # ORA-PWD-005  Password complexity
        val = self._get_profile_value("SIGNON_PASSWORD_HARD_TO_GUESS")
        if val is None or val.upper() != "Y":
            self._add(Finding(
                "ORA-PWD-005", "Password complexity not enforced",
                "Password & Auth", "HIGH",
                "FND_PROFILE_OPTION_VALUES",
                f"SIGNON_PASSWORD_HARD_TO_GUESS = {val or 'NULL'}",
                "Password complexity (hard-to-guess) is not enabled. Users "
                "can set trivially simple passwords.",
                "Set SIGNON_PASSWORD_HARD_TO_GUESS to 'Y' at Site level.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-PWD-005", "Password complexity enforced")

        # ORA-PWD-006  Password reuse prevention
        val = self._get_profile_value("SIGNON_PASSWORD_NO_REUSE")
        if val is None or val == "" or val == "0":
            self._add(Finding(
                "ORA-PWD-006", "Password reuse not prevented",
                "Password & Auth", "MEDIUM",
                "FND_PROFILE_OPTION_VALUES",
                f"SIGNON_PASSWORD_NO_REUSE = {val or 'NULL'}",
                "Password history is not enforced, allowing users to "
                "reuse previous passwords immediately.",
                "Set SIGNON_PASSWORD_NO_REUSE to 6 or higher at Site level.",
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
        if val is None or val == "":
            self._add(Finding(
                "ORA-PROF-001", "Session timeout not configured",
                "Profile Options", "MEDIUM",
                "FND_PROFILE_OPTION_VALUES",
                "ICX_SESSION_TIMEOUT = NULL",
                "No session timeout is configured. Idle sessions remain "
                "active indefinitely, increasing hijacking risk.",
                "Set ICX_SESSION_TIMEOUT to 30 minutes or less at Site level.",
                "CWE-613",
            ))
        else:
            try:
                if int(val) > 60:
                    self._add(Finding(
                        "ORA-PROF-001", "Session timeout too long",
                        "Profile Options", "LOW",
                        "FND_PROFILE_OPTION_VALUES",
                        f"ICX_SESSION_TIMEOUT = {val} min",
                        f"Session timeout is set to {val} minutes, which "
                        "exceeds the recommended maximum of 30 minutes.",
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
                "FND_PROFILE_OPTION_VALUES",
                "GUEST_USER_PWD = <contains default>",
                "The GUEST_USER_PWD profile option appears to contain the "
                "default Oracle-supplied password.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"FND_DIAGNOSTICS = {val}",
                "FND_DIAGNOSTICS is enabled, exposing internal diagnostic "
                "data that could aid attackers.",
                "Set FND_DIAGNOSTICS to 'N' at Site level in production.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"AFLOG_ENABLED = {val}",
                "Application framework logging is enabled, which may write "
                "sensitive data to log files.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"APPS_SERVLET_AGENT = {val}",
                "The servlet agent URL does not use HTTPS, exposing "
                "session cookies and credentials in transit.",
                "Configure APPS_SERVLET_AGENT to use an https:// URL.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"APPS_FRAMEWORK_AGENT = {val}",
                "The OA Framework agent URL does not use HTTPS.",
                "Configure APPS_FRAMEWORK_AGENT to use an https:// URL.",
                "CWE-319",
            ))
        else:
            self._pass("ORA-PROF-006", "Framework agent uses HTTPS")

        # ORA-PROF-007  Sign-on notification
        val = self._get_profile_value("SIGN_ON_NOTIFICATION")
        if val is None or val.upper() != "Y":
            self._add(Finding(
                "ORA-PROF-007", "Sign-on notification disabled",
                "Profile Options", "LOW",
                "FND_PROFILE_OPTION_VALUES",
                f"SIGN_ON_NOTIFICATION = {val or 'NULL'}",
                "Users are not notified of previous login details, reducing "
                "ability to detect unauthorized access.",
                "Set SIGN_ON_NOTIFICATION to 'Y' at Site level.",
            ))
        else:
            self._pass("ORA-PROF-007", "Sign-on notification enabled")

        # ORA-PROF-008  Concurrent session limit
        val = self._get_profile_value("ICX_LIMIT_CONNECT")
        if val is None or val == "" or val == "0":
            self._add(Finding(
                "ORA-PROF-008", "Concurrent session limit not set",
                "Profile Options", "MEDIUM",
                "FND_PROFILE_OPTION_VALUES",
                f"ICX_LIMIT_CONNECT = {val or 'NULL'}",
                "No limit on concurrent sessions per user. An attacker "
                "with stolen credentials can establish parallel sessions.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"FND_CUSTOM_OA_DEFINTION = {val}",
                "OA Framework personalization is enabled, which could allow "
                "unauthorized UI modifications.",
                "Set FND_CUSTOM_OA_DEFINTION to 'N' unless actively required.",
            ))
        else:
            self._pass("ORA-PROF-009", "OA customization disabled")

        # ORA-PROF-010  Sign-on audit level
        val = self._get_profile_value("SIGNONAUDIT:LEVEL")
        if val is None or val == "":
            self._add(Finding(
                "ORA-PROF-010", "Sign-on audit level not configured",
                "Profile Options", "MEDIUM",
                "FND_PROFILE_OPTION_VALUES",
                "SIGNONAUDIT:LEVEL = NULL",
                "Sign-on auditing is not configured. User login and "
                "navigation activity is not being tracked.",
                "Set SIGNONAUDIT:LEVEL to 'C' (form) or 'D' (responsibility) "
                "at Site level for adequate audit coverage.",
                "CWE-778",
            ))
        elif val.upper() in ("A",):
            self._add(Finding(
                "ORA-PROF-010", "Sign-on audit level too low",
                "Profile Options", "LOW",
                "FND_PROFILE_OPTION_VALUES",
                f"SIGNONAUDIT:LEVEL = {val}",
                "Sign-on audit level is set to 'A' (none/login only), "
                "which provides minimal audit coverage.",
                "Increase SIGNONAUDIT:LEVEL to 'C' or 'D' for form and "
                "responsibility-level auditing.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-PROF-010", "Sign-on audit level acceptable")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 4 — Responsibility & Access  (ORA-ROLE-001 .. 006)
    # ═════════════════════════════════════════════════════════════════

    def _check_responsibilities(self):

        # ORA-ROLE-001  Users with System Administrator responsibility
        rows = self._query(
            "SELECT fu.USER_NAME "
            "FROM FND_USER fu "
            "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
            "  ON fu.USER_ID = furg.USER_ID "
            "JOIN FND_RESPONSIBILITY_TL frt "
            "  ON furg.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
            "  AND furg.RESPONSIBILITY_APPLICATION_ID = frt.APPLICATION_ID "
            "  AND frt.LANGUAGE = 'US' "
            "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
            "  AND frt.RESPONSIBILITY_NAME = 'System Administrator' "
            "ORDER BY fu.USER_NAME"
        )
        cnt = len(rows)
        if cnt > 3:
            names = ", ".join(r["USER_NAME"] for r in rows[:15])
            self._add(Finding(
                "ORA-ROLE-001", "Excessive System Administrator users",
                "Responsibility & Access", "CRITICAL",
                "FND_USER_RESP_GROUPS_DIRECT",
                f"SysAdmin users ({cnt}): {names}",
                f"{cnt} users have the System Administrator responsibility. "
                "This grants full EBS configuration access and should be "
                "limited to 2-3 designated administrators.",
                "Remove System Administrator from all users except designated "
                "EBS administrators. Use least-privilege custom responsibilities.",
                "CWE-269",
            ))
        elif cnt > 0:
            names = ", ".join(r["USER_NAME"] for r in rows)
            self._add(Finding(
                "ORA-ROLE-001", "System Administrator users",
                "Responsibility & Access", "INFO",
                "FND_USER_RESP_GROUPS_DIRECT",
                f"SysAdmin users ({cnt}): {names}",
                f"{cnt} user(s) have the System Administrator responsibility.",
                "Review periodically to ensure only authorized admins retain access.",
            ))
        else:
            self._pass("ORA-ROLE-001", "No System Administrator users found")

        # ORA-ROLE-002  Users with multiple sensitive responsibilities
        sensitive_patterns = [
            f"frt.RESPONSIBILITY_NAME = '{name}'"
            for name in self.SENSITIVE_RESPONSIBILITIES
        ]
        where_clause = " OR ".join(sensitive_patterns)
        rows = self._query(
            "SELECT fu.USER_NAME, COUNT(DISTINCT frt.RESPONSIBILITY_NAME) AS RESP_CNT "
            "FROM FND_USER fu "
            "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
            "  ON fu.USER_ID = furg.USER_ID "
            "JOIN FND_RESPONSIBILITY_TL frt "
            "  ON furg.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
            "  AND furg.RESPONSIBILITY_APPLICATION_ID = frt.APPLICATION_ID "
            "  AND frt.LANGUAGE = 'US' "
            f"WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            f"  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
            f"  AND ({where_clause}) "
            "GROUP BY fu.USER_NAME "
            "HAVING COUNT(DISTINCT frt.RESPONSIBILITY_NAME) >= 3 "
            "ORDER BY RESP_CNT DESC"
        )
        if rows:
            details = "; ".join(
                f"{r['USER_NAME']}({r['RESP_CNT']})" for r in rows[:10]
            )
            self._add(Finding(
                "ORA-ROLE-002", "Users with multiple sensitive responsibilities",
                "Responsibility & Access", "HIGH",
                "FND_USER_RESP_GROUPS_DIRECT",
                f"Multi-sensitive ({len(rows)} users): {details}",
                f"{len(rows)} user(s) hold 3 or more sensitive responsibilities, "
                "violating least-privilege principles.",
                "Review responsibility assignments and remove unnecessary "
                "sensitive access. Apply role-based access aligned with job duties.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-ROLE-002", "No users with excessive sensitive access")

        # ORA-ROLE-003  Sensitive responsibility with too many users
        for resp_name, risk in self.SENSITIVE_RESPONSIBILITIES.items():
            cnt = self._count(
                "SELECT COUNT(DISTINCT fu.USER_ID) "
                "FROM FND_USER fu "
                "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
                "  ON fu.USER_ID = furg.USER_ID "
                "JOIN FND_RESPONSIBILITY_TL frt "
                "  ON furg.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
                "  AND furg.RESPONSIBILITY_APPLICATION_ID = frt.APPLICATION_ID "
                "  AND frt.LANGUAGE = 'US' "
                "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
                "  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
                "  AND frt.RESPONSIBILITY_NAME = :1",
                [resp_name],
            )
            threshold = 5 if risk == "CRITICAL" else 10
            if cnt > threshold:
                self._add(Finding(
                    "ORA-ROLE-003",
                    f"Too many users on '{resp_name}'",
                    "Responsibility & Access", risk,
                    "FND_USER_RESP_GROUPS_DIRECT",
                    f"'{resp_name}' assigned to {cnt} users (threshold: {threshold})",
                    f"The '{resp_name}' responsibility is assigned to {cnt} "
                    f"users, exceeding the recommended threshold of {threshold}.",
                    f"Review and reduce the number of users with '{resp_name}'. "
                    "Create restricted custom responsibilities where possible.",
                    "CWE-269",
                ))

        # ORA-ROLE-004  Responsibility assignments without end date
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_USER_RESP_GROUPS_DIRECT furg "
            "JOIN FND_USER fu ON furg.USER_ID = fu.USER_ID "
            "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND furg.END_DATE IS NULL"
        )
        if cnt > 100:
            self._add(Finding(
                "ORA-ROLE-004", "Responsibility assignments without end date",
                "Responsibility & Access", "LOW",
                "FND_USER_RESP_GROUPS_DIRECT",
                f"No end date: {cnt} assignments",
                f"{cnt} active responsibility assignments have no end date.",
                "Set end dates on responsibility assignments, especially for "
                "sensitive responsibilities and temporary access.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-ROLE-004", "Responsibility end-date coverage acceptable")

        # ORA-ROLE-005  Inactive responsibilities still assigned
        rows = self._query(
            "SELECT DISTINCT frt.RESPONSIBILITY_NAME, "
            "  COUNT(DISTINCT fu.USER_ID) AS USER_CNT "
            "FROM FND_RESPONSIBILITY fr "
            "JOIN FND_RESPONSIBILITY_TL frt "
            "  ON fr.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
            "  AND fr.APPLICATION_ID = frt.APPLICATION_ID "
            "  AND frt.LANGUAGE = 'US' "
            "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
            "  ON fr.RESPONSIBILITY_ID = furg.RESPONSIBILITY_ID "
            "  AND fr.APPLICATION_ID = furg.RESPONSIBILITY_APPLICATION_ID "
            "JOIN FND_USER fu ON furg.USER_ID = fu.USER_ID "
            "WHERE fr.END_DATE IS NOT NULL AND fr.END_DATE < SYSDATE "
            "  AND (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
            "GROUP BY frt.RESPONSIBILITY_NAME "
            "ORDER BY USER_CNT DESC"
        )
        if rows:
            details = "; ".join(
                f"{r['RESPONSIBILITY_NAME']}({r['USER_CNT']})" for r in rows[:5]
            )
            self._add(Finding(
                "ORA-ROLE-005", "Inactive responsibilities still assigned",
                "Responsibility & Access", "MEDIUM",
                "FND_RESPONSIBILITY + FND_USER_RESP_GROUPS_DIRECT",
                f"Inactive resps assigned: {details}",
                f"{len(rows)} end-dated responsibility(ies) are still assigned "
                "to active users.",
                "Remove user assignments for responsibilities that have been "
                "end-dated or decommissioned.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-ROLE-005", "No inactive responsibilities assigned")

        # ORA-ROLE-006  Custom responsibilities with admin menu
        rows = self._query(
            "SELECT DISTINCT frt.RESPONSIBILITY_NAME "
            "FROM FND_RESPONSIBILITY fr "
            "JOIN FND_RESPONSIBILITY_TL frt "
            "  ON fr.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
            "  AND fr.APPLICATION_ID = frt.APPLICATION_ID "
            "  AND frt.LANGUAGE = 'US' "
            "WHERE fr.MENU_ID IN ("
            "  SELECT MENU_ID FROM FND_MENUS "
            "  WHERE MENU_NAME LIKE '%SYSADMIN%' "
            "    OR MENU_NAME LIKE '%FND_NAVIGATE%') "
            "AND frt.RESPONSIBILITY_NAME NOT LIKE '%System Admin%' "
            "AND (fr.END_DATE IS NULL OR fr.END_DATE > SYSDATE) "
            "ORDER BY frt.RESPONSIBILITY_NAME"
        )
        if rows:
            names = ", ".join(r["RESPONSIBILITY_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-ROLE-006", "Custom responsibilities with admin menus",
                "Responsibility & Access", "HIGH",
                "FND_RESPONSIBILITY + FND_MENUS",
                f"Admin-menu resps: {names}",
                f"{len(rows)} custom responsibility(ies) use system "
                "administration menus, potentially granting unintended "
                "admin access.",
                "Review and replace admin menus in custom responsibilities "
                "with purpose-built restricted menus.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-ROLE-006", "No custom resps with admin menus")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 5 — Segregation of Duties  (ORA-SOD-001 .. 006)
    # ═════════════════════════════════════════════════════════════════

    def _check_sod(self):
        for idx, (pat1, pat2, label, risk_desc) in enumerate(
            self.SOD_CONFLICTS, start=1
        ):
            rule_id = f"ORA-SOD-{idx:03d}"
            rows = self._query(
                "SELECT DISTINCT fu.USER_NAME, "
                "  frt1.RESPONSIBILITY_NAME AS RESP1, "
                "  frt2.RESPONSIBILITY_NAME AS RESP2 "
                "FROM FND_USER fu "
                "JOIN FND_USER_RESP_GROUPS_DIRECT furg1 "
                "  ON fu.USER_ID = furg1.USER_ID "
                "JOIN FND_USER_RESP_GROUPS_DIRECT furg2 "
                "  ON fu.USER_ID = furg2.USER_ID "
                "JOIN FND_RESPONSIBILITY_TL frt1 "
                "  ON furg1.RESPONSIBILITY_ID = frt1.RESPONSIBILITY_ID "
                "  AND furg1.RESPONSIBILITY_APPLICATION_ID = frt1.APPLICATION_ID "
                "  AND frt1.LANGUAGE = 'US' "
                "JOIN FND_RESPONSIBILITY_TL frt2 "
                "  ON furg2.RESPONSIBILITY_ID = frt2.RESPONSIBILITY_ID "
                "  AND furg2.RESPONSIBILITY_APPLICATION_ID = frt2.APPLICATION_ID "
                "  AND frt2.LANGUAGE = 'US' "
                "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
                "  AND (furg1.END_DATE IS NULL OR furg1.END_DATE > SYSDATE) "
                "  AND (furg2.END_DATE IS NULL OR furg2.END_DATE > SYSDATE) "
                "  AND frt1.RESPONSIBILITY_NAME LIKE :1 "
                "  AND frt2.RESPONSIBILITY_NAME LIKE :2 "
                "  AND furg1.RESPONSIBILITY_ID != furg2.RESPONSIBILITY_ID "
                "ORDER BY fu.USER_NAME",
                [pat1, pat2],
            )
            if rows:
                users = ", ".join(
                    sorted(set(r["USER_NAME"] for r in rows))[:10]
                )
                self._add(Finding(
                    rule_id, f"SoD conflict: {label}",
                    "Segregation of Duties", "HIGH",
                    "FND_USER_RESP_GROUPS_DIRECT",
                    f"{label} conflict ({len(rows)} user-pairs): {users}",
                    f"{len(rows)} user(s) hold responsibilities in both "
                    f"conflicting areas. {risk_desc}.",
                    f"Remove one side of the {label} conflict for each "
                    "affected user or implement compensating controls "
                    "(approval workflows, periodic review).",
                    "CWE-284",
                ))
            else:
                self._pass(rule_id, f"No {label} SoD conflicts")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 6 — Concurrent Programs  (ORA-CONC-001 .. 004)
    # ═════════════════════════════════════════════════════════════════

    def _check_concurrent(self):

        # ORA-CONC-001  Dangerous programs accessible to non-admin request groups
        placeholders = ", ".join(f":{i}" for i in range(len(self.DANGEROUS_PROGRAMS)))
        rows = self._query(
            f"SELECT DISTINCT fcp.CONCURRENT_PROGRAM_NAME, "
            f"  frg.REQUEST_GROUP_NAME "
            f"FROM FND_CONCURRENT_PROGRAMS fcp "
            f"JOIN FND_REQUEST_GROUP_UNITS frgu "
            f"  ON fcp.CONCURRENT_PROGRAM_ID = frgu.REQUEST_UNIT_ID "
            f"  AND fcp.APPLICATION_ID = frgu.UNIT_APPLICATION_ID "
            f"  AND frgu.REQUEST_UNIT_TYPE = 'P' "
            f"JOIN FND_REQUEST_GROUPS frg "
            f"  ON frgu.REQUEST_GROUP_ID = frg.REQUEST_GROUP_ID "
            f"  AND frgu.APPLICATION_ID = frg.APPLICATION_ID "
            f"WHERE fcp.CONCURRENT_PROGRAM_NAME IN ({placeholders}) "
            f"  AND frg.REQUEST_GROUP_NAME NOT LIKE '%System Admin%' "
            f"ORDER BY fcp.CONCURRENT_PROGRAM_NAME",
            list(self.DANGEROUS_PROGRAMS),
        )
        if rows:
            details = "; ".join(
                f"{r['CONCURRENT_PROGRAM_NAME']} -> {r['REQUEST_GROUP_NAME']}"
                for r in rows[:10]
            )
            self._add(Finding(
                "ORA-CONC-001", "Dangerous programs in non-admin request groups",
                "Concurrent Programs", "HIGH",
                "FND_REQUEST_GROUP_UNITS",
                f"Dangerous program access: {details}",
                f"{len(rows)} dangerous concurrent program(s) (e.g., FNDCPASS, "
                "FNDLOAD) are accessible through non-admin request groups.",
                "Remove dangerous programs from non-admin request groups. "
                "Restrict access to System Administrator only.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-001", "Dangerous programs properly restricted")

        # ORA-CONC-002  Host-based concurrent programs
        rows = self._query(
            "SELECT CONCURRENT_PROGRAM_NAME, "
            "  EXECUTION_METHOD_CODE "
            "FROM FND_CONCURRENT_PROGRAMS "
            "WHERE EXECUTION_METHOD_CODE = 'H' "
            "  AND ENABLED_FLAG = 'Y' "
            "ORDER BY CONCURRENT_PROGRAM_NAME"
        )
        if rows:
            names = ", ".join(r["CONCURRENT_PROGRAM_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-CONC-002", "Host-based concurrent programs enabled",
                "Concurrent Programs", "MEDIUM",
                "FND_CONCURRENT_PROGRAMS",
                f"Host programs ({len(rows)}): {names}",
                f"{len(rows)} host-based concurrent program(s) can execute "
                "OS-level commands on the application server.",
                "Review and disable unnecessary host-based programs. "
                "Ensure remaining host programs are restricted to "
                "authorized request groups.",
                "CWE-78",
            ))
        else:
            self._pass("ORA-CONC-002", "No host-based programs")

        # ORA-CONC-003  Programs with application-level request group (unrestricted)
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_REQUEST_GROUP_UNITS "
            "WHERE REQUEST_UNIT_TYPE = 'A'"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-CONC-003", "Application-level request group access",
                "Concurrent Programs", "MEDIUM",
                "FND_REQUEST_GROUP_UNITS",
                f"Application-level grants: {cnt}",
                f"{cnt} request group entry(ies) grant access to ALL programs "
                "in an application, bypassing individual program controls.",
                "Replace application-level grants with explicit program-level "
                "grants in request groups.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-003", "No application-level request group grants")

        # ORA-CONC-004  Concurrent manager running programs as privileged user
        rows = self._query(
            "SELECT DISTINCT fcr.REQUESTED_BY, fu.USER_NAME, "
            "  COUNT(*) AS REQ_CNT "
            "FROM FND_CONCURRENT_REQUESTS fcr "
            "JOIN FND_USER fu ON fcr.REQUESTED_BY = fu.USER_ID "
            "WHERE fcr.PHASE_CODE = 'C' "
            "  AND fcr.ACTUAL_START_DATE > SYSDATE - 30 "
            "  AND fu.USER_NAME IN ('SYSADMIN','AUTOINSTALL') "
            "GROUP BY fcr.REQUESTED_BY, fu.USER_NAME "
            "ORDER BY REQ_CNT DESC"
        )
        if rows:
            details = "; ".join(
                f"{r['USER_NAME']}({r['REQ_CNT']} requests)" for r in rows
            )
            self._add(Finding(
                "ORA-CONC-004", "Programs running as privileged user",
                "Concurrent Programs", "MEDIUM",
                "FND_CONCURRENT_REQUESTS",
                f"Privileged submissions: {details}",
                "Concurrent requests are being submitted under privileged "
                "accounts (SYSADMIN/AUTOINSTALL) in the last 30 days.",
                "Run concurrent programs under individual named user accounts "
                "rather than shared admin accounts.",
                "CWE-250",
            ))
        else:
            self._pass("ORA-CONC-004", "No privileged user program submissions")

        # ORA-CONC-005  Shell script concurrent programs
        rows = self._query(
            "SELECT CONCURRENT_PROGRAM_NAME, USER_CONCURRENT_PROGRAM_NAME "
            "FROM FND_CONCURRENT_PROGRAMS_TL fcpt "
            "JOIN FND_CONCURRENT_PROGRAMS fcp "
            "  ON fcpt.CONCURRENT_PROGRAM_ID = fcp.CONCURRENT_PROGRAM_ID "
            "  AND fcpt.APPLICATION_ID = fcp.APPLICATION_ID "
            "WHERE fcp.EXECUTION_METHOD_CODE IN ('H', 'K') "
            "  AND fcp.ENABLED_FLAG = 'Y' "
            "  AND fcpt.LANGUAGE = 'US' "
            "ORDER BY fcp.CONCURRENT_PROGRAM_NAME"
        )
        if rows:
            names = ", ".join(r["CONCURRENT_PROGRAM_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-CONC-005",
                "Shell/host execution concurrent programs",
                "Concurrent Programs", "MEDIUM",
                "FND_CONCURRENT_PROGRAMS",
                f"Shell programs ({len(rows)}): {names}",
                f"{len(rows)} concurrent program(s) execute shell scripts or "
                "host commands on the application server. These can be used "
                "for OS-level command injection.",
                "Review each shell-based program for necessity. Restrict "
                "access via request groups to authorized administrators only.",
                "CWE-78",
            ))
        else:
            self._pass("ORA-CONC-005", "No shell execution programs found")

        # ORA-CONC-006  Programs accessing sensitive security tables
        rows = self._query(
            "SELECT DISTINCT fcp.CONCURRENT_PROGRAM_NAME, "
            "  frg.REQUEST_GROUP_NAME "
            "FROM FND_CONCURRENT_PROGRAMS fcp "
            "JOIN FND_REQUEST_GROUP_UNITS frgu "
            "  ON fcp.CONCURRENT_PROGRAM_ID = frgu.REQUEST_UNIT_ID "
            "  AND fcp.APPLICATION_ID = frgu.UNIT_APPLICATION_ID "
            "  AND frgu.REQUEST_UNIT_TYPE = 'P' "
            "JOIN FND_REQUEST_GROUPS frg "
            "  ON frgu.REQUEST_GROUP_ID = frg.REQUEST_GROUP_ID "
            "  AND frgu.APPLICATION_ID = frg.APPLICATION_ID "
            "WHERE fcp.CONCURRENT_PROGRAM_NAME IN ("
            "  'FNDCPASS','FNDSLOAD','FNDSCARU','FNDLOAD') "
            "  AND fcp.ENABLED_FLAG = 'Y' "
            "ORDER BY fcp.CONCURRENT_PROGRAM_NAME"
        )
        if rows:
            details = "; ".join(
                f"{r['CONCURRENT_PROGRAM_NAME']} -> {r['REQUEST_GROUP_NAME']}"
                for r in rows[:10]
            )
            self._add(Finding(
                "ORA-CONC-006",
                "Security-sensitive programs broadly accessible",
                "Concurrent Programs", "HIGH",
                "FND_REQUEST_GROUP_UNITS",
                f"Sensitive program access: {details}",
                "Programs that modify security configuration (FNDCPASS, "
                "FNDSLOAD, FNDSCARU, FNDLOAD) are accessible through "
                "multiple request groups.",
                "Restrict these programs to the System Administrator "
                "request group only.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-006", "Security programs properly restricted")

        # ORA-CONC-007  Concurrent output file directory permissions
        val = self._get_profile_value("APPLCSF")
        val2 = self._get_profile_value("APPLOUT")
        if val or val2:
            self._add(Finding(
                "ORA-CONC-007",
                "Concurrent output directory configuration",
                "Concurrent Programs", "INFO",
                "FND_PROFILE_OPTION_VALUES",
                f"APPLCSF = {val or 'NULL'}, APPLOUT = {val2 or 'NULL'}",
                "Concurrent program output files may contain sensitive data. "
                "Verify that output directories have restricted permissions.",
                "Ensure concurrent output directories ($APPLCSF/$APPLOUT) "
                "have permissions restricted to the applmgr user only (700).",
            ))
        else:
            self._pass("ORA-CONC-007", "Output directory check skipped")

        # ORA-CONC-008  FNDCPASS/FNDSCARU recent execution
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_CONCURRENT_REQUESTS fcr "
            "JOIN FND_CONCURRENT_PROGRAMS fcp "
            "  ON fcr.CONCURRENT_PROGRAM_ID = fcp.CONCURRENT_PROGRAM_ID "
            "  AND fcr.PROGRAM_APPLICATION_ID = fcp.APPLICATION_ID "
            "WHERE fcp.CONCURRENT_PROGRAM_NAME IN ('FNDCPASS','FNDSCARU') "
            "  AND fcr.PHASE_CODE = 'C' "
            "  AND fcr.ACTUAL_START_DATE > SYSDATE - 30"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-CONC-008",
                "Security programs executed recently",
                "Concurrent Programs", "MEDIUM",
                "FND_CONCURRENT_REQUESTS",
                f"FNDCPASS/FNDSCARU executions (30d): {cnt}",
                f"{cnt} execution(s) of password change or user maintenance "
                "programs detected in the last 30 days. These should be "
                "reviewed for authorization.",
                "Verify each execution was authorized and logged. Review "
                "who submitted these requests and why.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-008", "No recent security program executions")

        # ORA-CONC-009  Concurrent manager output file retention
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_CONCURRENT_REQUESTS "
            "WHERE PHASE_CODE = 'C' "
            "  AND ACTUAL_START_DATE < SYSDATE - 180 "
            "  AND OUTFILE_NAME IS NOT NULL"
        )
        if cnt > 10000:
            self._add(Finding(
                "ORA-CONC-009",
                "Old concurrent output files not purged",
                "Concurrent Programs", "LOW",
                "FND_CONCURRENT_REQUESTS",
                f"Output files > 180 days: {cnt:,}",
                f"{cnt:,} concurrent request output files older than 6 months "
                "still exist. Old output files may contain sensitive data.",
                "Schedule the 'Purge Concurrent Request and/or Manager Data' "
                "program to clean up old output files.",
                "CWE-532",
            ))
        else:
            self._pass("ORA-CONC-009", "Output file retention acceptable")

        # ORA-CONC-010  Request group with ALL concurrent programs
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_REQUEST_GROUP_UNITS "
            "WHERE REQUEST_UNIT_TYPE = 'A' "
            "  AND REQUEST_GROUP_ID IN ("
            "    SELECT frg.REQUEST_GROUP_ID FROM FND_REQUEST_GROUPS frg "
            "    JOIN FND_RESPONSIBILITY fr "
            "      ON frg.REQUEST_GROUP_ID = fr.REQUEST_GROUP_ID "
            "      AND frg.APPLICATION_ID = fr.GROUP_APPLICATION_ID "
            "    WHERE fr.END_DATE IS NULL OR fr.END_DATE > SYSDATE)"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-CONC-010",
                "Active responsibilities with ALL-program request groups",
                "Concurrent Programs", "HIGH",
                "FND_REQUEST_GROUP_UNITS",
                f"Active ALL-program grants: {cnt}",
                f"{cnt} active responsibility(ies) have request groups that "
                "grant access to ALL concurrent programs in an application.",
                "Replace ALL-program grants with explicit program-level "
                "entries in request groups.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-CONC-010", "No active ALL-program request groups")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 7 — Audit Trail  (ORA-AUDIT-001 .. 005)
    # ═════════════════════════════════════════════════════════════════

    def _check_audit(self):

        # ORA-AUDIT-001  Audit trail enabled (profile option)
        val = self._get_profile_value("AUDITTRAIL:ACTIVATE")
        if val is None or val.upper() != "Y":
            self._add(Finding(
                "ORA-AUDIT-001", "EBS audit trail not enabled",
                "Audit Trail", "CRITICAL",
                "FND_PROFILE_OPTION_VALUES",
                f"AUDITTRAIL:ACTIVATE = {val or 'NULL'}",
                "The Oracle EBS AuditTrail feature is not enabled at Site "
                "level. Changes to critical tables are not being tracked.",
                "Set AUDITTRAIL:ACTIVATE to 'Y' at Site level and run "
                "the AuditTrail Update Tables concurrent program.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-001", "Audit trail enabled")

        # ORA-AUDIT-002  Critical tables not in audit configuration
        for _, table_name, description in self.CRITICAL_AUDIT_TABLES:
            cnt = self._count(
                "SELECT COUNT(*) FROM FND_AUDIT_TABLES fat "
                "JOIN FND_AUDIT_SCHEMAS fas "
                "  ON fat.AUDIT_SCHEMA_ID = fas.AUDIT_SCHEMA_ID "
                "WHERE fat.TABLE_NAME = :1 "
                "  AND fas.STATE = 'E'",
                [table_name],
            )
            if cnt == 0:
                self._add(Finding(
                    "ORA-AUDIT-002",
                    f"Critical table not audited: {table_name}",
                    "Audit Trail", "HIGH",
                    "FND_AUDIT_TABLES",
                    f"{table_name} ({description}) — not in active audit schema",
                    f"The {table_name} table ({description}) is not included "
                    "in an enabled audit schema. Changes will not be tracked.",
                    f"Add {table_name} to an audit group and enable auditing "
                    "via the AuditTrail Update Tables program.",
                    "CWE-778",
                ))

        # ORA-AUDIT-003  Database-level auditing
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'audit_trail'"
        )
        if val and val.upper() in ("NONE", "FALSE"):
            self._add(Finding(
                "ORA-AUDIT-003", "Database auditing disabled",
                "Audit Trail", "HIGH",
                "V$PARAMETER",
                f"audit_trail = {val}",
                "Database-level auditing is disabled. Privileged operations "
                "and DDL changes are not being recorded.",
                "Set audit_trail to 'DB' or 'DB,EXTENDED' and restart the "
                "database instance.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-003", "Database auditing enabled")

        # ORA-AUDIT-004  Sign-on audit level (checked also in profiles but
        #                separate audit-focused finding)
        val = self._get_profile_value("SIGNONAUDIT:LEVEL")
        if val is None or val == "" or val.upper() == "A":
            self._add(Finding(
                "ORA-AUDIT-004", "Sign-on audit level insufficient",
                "Audit Trail", "MEDIUM",
                "FND_PROFILE_OPTION_VALUES",
                f"SIGNONAUDIT:LEVEL = {val or 'NULL'}",
                "Sign-on audit level is not configured or is at the "
                "minimum level. User navigation and form access is not tracked.",
                "Set SIGNONAUDIT:LEVEL to 'C' (form level) or 'D' "
                "(responsibility level) at Site level.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-004", "Sign-on audit level configured")

        # ORA-AUDIT-005  Audit data volume / retention review
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_LOGIN_RESP_ACTIONS "
            "WHERE LOGIN_ID IN ("
            "  SELECT LOGIN_ID FROM FND_LOGINS "
            "  WHERE START_TIME < SYSDATE - 365)"
        )
        if cnt > 100000:
            self._add(Finding(
                "ORA-AUDIT-005", "Audit data retention review needed",
                "Audit Trail", "LOW",
                "FND_LOGINS + FND_LOGIN_RESP_ACTIONS",
                f"Audit records older than 1 year: {cnt:,}",
                f"There are {cnt:,} audit records older than 365 days. "
                "Large audit tables can impact performance.",
                "Implement an audit data archival and purge strategy. "
                "Archive records older than the retention period.",
            ))
        else:
            self._pass("ORA-AUDIT-005", "Audit data volume acceptable")

        # ORA-AUDIT-006  Profile option change auditing
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_AUDIT_TABLES fat "
            "JOIN FND_AUDIT_SCHEMAS fas "
            "  ON fat.AUDIT_SCHEMA_ID = fas.AUDIT_SCHEMA_ID "
            "WHERE fat.TABLE_NAME = 'FND_PROFILE_OPTION_VALUES' "
            "  AND fas.STATE = 'E'"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-AUDIT-006",
                "Profile option changes not audited",
                "Audit Trail", "HIGH",
                "FND_AUDIT_TABLES",
                "FND_PROFILE_OPTION_VALUES not in active audit schema",
                "Changes to security-critical profile options (passwords, "
                "session timeouts, audit levels) are not being tracked.",
                "Add FND_PROFILE_OPTION_VALUES to an audit group and enable.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-006", "Profile option changes audited")

        # ORA-AUDIT-007  Responsibility assignment changes not tracked
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_AUDIT_TABLES fat "
            "JOIN FND_AUDIT_SCHEMAS fas "
            "  ON fat.AUDIT_SCHEMA_ID = fas.AUDIT_SCHEMA_ID "
            "WHERE fat.TABLE_NAME = 'FND_USER_RESP_GROUPS_DIRECT' "
            "  AND fas.STATE = 'E'"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-AUDIT-007",
                "Responsibility assignment changes not audited",
                "Audit Trail", "HIGH",
                "FND_AUDIT_TABLES",
                "FND_USER_RESP_GROUPS_DIRECT not in active audit schema",
                "Granting or revoking responsibilities is not tracked. "
                "Unauthorized privilege escalation may go undetected.",
                "Add FND_USER_RESP_GROUPS_DIRECT to an audit group.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-007", "Responsibility changes audited")

        # ORA-AUDIT-008  FND_USER modification audit
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_AUDIT_TABLES fat "
            "JOIN FND_AUDIT_SCHEMAS fas "
            "  ON fat.AUDIT_SCHEMA_ID = fas.AUDIT_SCHEMA_ID "
            "WHERE fat.TABLE_NAME = 'FND_USER' "
            "  AND fas.STATE = 'E'"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-AUDIT-008",
                "User account changes not audited",
                "Audit Trail", "HIGH",
                "FND_AUDIT_TABLES",
                "FND_USER not in active audit schema",
                "Changes to user accounts (creation, password resets, "
                "end-dating) are not being tracked in the audit trail.",
                "Add FND_USER to an audit group and enable auditing.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-008", "User account changes audited")

        # ORA-AUDIT-009  Unified Audit policies (12c+)
        cnt = self._count(
            "SELECT COUNT(*) FROM AUDIT_UNIFIED_ENABLED_POLICIES"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-AUDIT-009",
                "No Unified Audit policies enabled",
                "Audit Trail", "MEDIUM",
                "AUDIT_UNIFIED_ENABLED_POLICIES",
                "Unified Audit policies: 0",
                "No Unified Audit policies are enabled. Modern Oracle databases "
                "(12c+) should use Unified Auditing for comprehensive coverage.",
                "Enable Unified Auditing and configure policies for privilege use, "
                "DDL, and login events.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-009", f"Unified Audit policies active: {cnt}")

        # ORA-AUDIT-010  Audit log retention compliance
        # Check if any audit data older than 7 years exists (SOX max)
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_LOGINS "
            "WHERE START_TIME < SYSDATE - 2555"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-AUDIT-010",
                "Audit data exceeds 7-year retention",
                "Audit Trail", "LOW",
                "FND_LOGINS",
                f"Records older than 7 years: {cnt:,}",
                f"{cnt:,} audit records are older than 7 years. While SOX "
                "requires 7-year retention, very old data should be archived "
                "to maintain performance.",
                "Archive audit data older than the retention period to "
                "external storage. Purge from active tables.",
            ))
        else:
            self._pass("ORA-AUDIT-010", "Audit data retention within bounds")

        # ORA-AUDIT-011  Financial table WHO columns populated
        # Check if critical financial tables have CREATED_BY/LAST_UPDATED_BY
        cnt = self._count(
            "SELECT COUNT(*) FROM AP_INVOICES_ALL "
            "WHERE CREATED_BY IS NULL "
            "  AND CREATION_DATE > SYSDATE - 90 "
            "  AND ROWNUM <= 1"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-AUDIT-011",
                "Financial records missing WHO column data",
                "Audit Trail", "MEDIUM",
                "AP_INVOICES_ALL",
                "Records with NULL CREATED_BY found in last 90 days",
                "Financial transaction records are missing WHO column data "
                "(CREATED_BY, LAST_UPDATED_BY), preventing accountability.",
                "Investigate why WHO columns are not populated. Ensure all "
                "interfaces and APIs populate standard WHO columns.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-AUDIT-011", "Financial WHO columns populated")

        # ORA-AUDIT-012  Concurrent request history retention
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_CONCURRENT_REQUESTS "
            "WHERE PHASE_CODE = 'C' "
            "  AND ACTUAL_START_DATE < SYSDATE - 365"
        )
        if cnt > 500000:
            self._add(Finding(
                "ORA-AUDIT-012",
                "Concurrent request history needs purging",
                "Audit Trail", "LOW",
                "FND_CONCURRENT_REQUESTS",
                f"Completed requests > 1 year old: {cnt:,}",
                f"{cnt:,} completed concurrent request records are older than "
                "1 year. Excessive history impacts performance.",
                "Run the 'Purge Concurrent Request and/or Manager Data' "
                "program to archive old request history.",
            ))
        else:
            self._pass("ORA-AUDIT-012", "Concurrent request history acceptable")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 8 — Database Security  (ORA-DB-001 .. 010)
    # ═════════════════════════════════════════════════════════════════

    def _check_database(self):

        # ORA-DB-001  Default / unlocked database accounts
        placeholders = ", ".join(
            f":{i}" for i in range(len(self.DEFAULT_DB_ACCOUNTS))
        )
        rows = self._query(
            f"SELECT USERNAME, ACCOUNT_STATUS "
            f"FROM DBA_USERS "
            f"WHERE USERNAME IN ({placeholders}) "
            f"  AND ACCOUNT_STATUS NOT IN "
            f"    ('LOCKED','EXPIRED & LOCKED','EXPIRED(GRACE)') "
            f"ORDER BY USERNAME",
            list(self.DEFAULT_DB_ACCOUNTS),
        )
        if rows:
            names = ", ".join(
                f"{r['USERNAME']}({r['ACCOUNT_STATUS']})" for r in rows
            )
            self._add(Finding(
                "ORA-DB-001", "Default database accounts not locked",
                "Database Security", "HIGH",
                "DBA_USERS", f"Unlocked defaults: {names}",
                f"{len(rows)} default database account(s) are not locked. "
                "Attackers commonly target default accounts.",
                "Lock and expire all default database accounts that are "
                "not operationally required.",
                "CWE-798",
            ))
        else:
            self._pass("ORA-DB-001", "Default DB accounts locked")

        # ORA-DB-002  PUBLIC role has dangerous EXECUTE privileges
        placeholders = ", ".join(
            f":{i}" for i in range(len(self.SENSITIVE_PACKAGES))
        )
        rows = self._query(
            f"SELECT TABLE_NAME, PRIVILEGE "
            f"FROM DBA_TAB_PRIVS "
            f"WHERE GRANTEE = 'PUBLIC' "
            f"  AND PRIVILEGE = 'EXECUTE' "
            f"  AND TABLE_NAME IN ({placeholders}) "
            f"ORDER BY TABLE_NAME",
            list(self.SENSITIVE_PACKAGES),
        )
        if rows:
            pkgs = ", ".join(r["TABLE_NAME"] for r in rows)
            self._add(Finding(
                "ORA-DB-002", "PUBLIC has EXECUTE on sensitive packages",
                "Database Security", "HIGH",
                "DBA_TAB_PRIVS",
                f"PUBLIC EXECUTE: {pkgs}",
                f"The PUBLIC role has EXECUTE privileges on {len(rows)} "
                "sensitive package(s) that can access the file system, "
                "network, or execute arbitrary SQL.",
                "Revoke EXECUTE on sensitive packages from PUBLIC and grant "
                "only to specific schemas that require them.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-002", "PUBLIC does not have dangerous EXECUTE")

        # ORA-DB-003  Excessive DBA role grants
        rows = self._query(
            "SELECT GRANTEE, ADMIN_OPTION "
            "FROM DBA_ROLE_PRIVS "
            "WHERE GRANTED_ROLE = 'DBA' "
            "  AND GRANTEE NOT IN ('SYS','SYSTEM') "
            "ORDER BY GRANTEE"
        )
        if rows:
            grantees = ", ".join(
                f"{r['GRANTEE']}" +
                (" [WITH ADMIN]" if r.get("ADMIN_OPTION") == "YES" else "")
                for r in rows
            )
            self._add(Finding(
                "ORA-DB-003", "Excessive DBA role grants",
                "Database Security", "CRITICAL",
                "DBA_ROLE_PRIVS",
                f"DBA grantees: {grantees}",
                f"{len(rows)} non-default schema(s) have the DBA role. "
                "The DBA role grants unrestricted database access.",
                "Revoke the DBA role from application schemas and create "
                "custom roles with minimum required privileges.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-003", "No excessive DBA grants")

        # ORA-DB-004  UTL_FILE_DIR parameter
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'utl_file_dir'"
        )
        if val and val.strip() not in ("", "NONE"):
            if "*" in val or val.strip() == "/":
                severity = "CRITICAL"
            else:
                severity = "MEDIUM"
            self._add(Finding(
                "ORA-DB-004", "UTL_FILE_DIR parameter set",
                "Database Security", severity,
                "V$PARAMETER",
                f"utl_file_dir = {val}",
                "The utl_file_dir parameter specifies directories accessible "
                "to UTL_FILE. A broad setting can allow file system access.",
                "Remove or restrict utl_file_dir. Use Oracle Directory "
                "objects instead for controlled file access.",
                "CWE-732",
            ))
        else:
            self._pass("ORA-DB-004", "UTL_FILE_DIR not set or restricted")

        # ORA-DB-005  Remote OS authentication
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'remote_os_authent'"
        )
        if val and val.upper() == "TRUE":
            self._add(Finding(
                "ORA-DB-005", "Remote OS authentication enabled",
                "Database Security", "CRITICAL",
                "V$PARAMETER",
                f"remote_os_authent = {val}",
                "Remote OS authentication is enabled. Any client can "
                "authenticate as an OS-authenticated database user by "
                "setting the OS username on the client.",
                "Set remote_os_authent to FALSE and restart the database.",
                "CWE-287",
            ))
        else:
            self._pass("ORA-DB-005", "Remote OS auth disabled")

        # ORA-DB-006  Database links
        rows = self._query(
            "SELECT OWNER, DB_LINK, HOST, "
            "  TO_CHAR(CREATED,'YYYY-MM-DD') AS CREATED_DT "
            "FROM DBA_DB_LINKS "
            "ORDER BY OWNER, DB_LINK"
        )
        if rows:
            links = "; ".join(
                f"{r['OWNER']}.{r['DB_LINK']}" for r in rows[:10]
            )
            self._add(Finding(
                "ORA-DB-006", "Database links detected",
                "Database Security", "MEDIUM",
                "DBA_DB_LINKS",
                f"DB links ({len(rows)}): {links}",
                f"{len(rows)} database link(s) exist. Database links may "
                "store embedded credentials and extend the attack surface.",
                "Review all database links. Remove unused links and ensure "
                "remaining links use current-user authentication where possible.",
                "CWE-522",
            ))
        else:
            self._pass("ORA-DB-006", "No database links found")

        # ORA-DB-007  Sensitive package EXECUTE grants to non-DBA schemas
        rows = self._query(
            "SELECT GRANTEE, TABLE_NAME, PRIVILEGE "
            "FROM DBA_TAB_PRIVS "
            "WHERE PRIVILEGE = 'EXECUTE' "
            "  AND TABLE_NAME IN ('UTL_FILE','UTL_HTTP','UTL_TCP',"
            "    'UTL_SMTP','DBMS_SQL','DBMS_JAVA') "
            "  AND GRANTEE NOT IN ('SYS','SYSTEM','PUBLIC',"
            "    'APPS','APPLSYS','DBA') "
            "ORDER BY TABLE_NAME, GRANTEE"
        )
        if rows:
            details = "; ".join(
                f"{r['GRANTEE']}->{r['TABLE_NAME']}" for r in rows[:10]
            )
            self._add(Finding(
                "ORA-DB-007", "Sensitive package grants to non-DBA schemas",
                "Database Security", "MEDIUM",
                "DBA_TAB_PRIVS",
                f"Package grants: {details}",
                f"{len(rows)} non-DBA schema(s) have EXECUTE on sensitive "
                "packages that can access the network or file system.",
                "Review and revoke unnecessary EXECUTE grants on UTL_*, "
                "DBMS_SQL, and DBMS_JAVA packages.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-007", "No unexpected package grants")

        # ORA-DB-008  Open (non-locked) non-EBS database accounts
        rows = self._query(
            "SELECT USERNAME, ACCOUNT_STATUS, PROFILE "
            "FROM DBA_USERS "
            "WHERE ACCOUNT_STATUS = 'OPEN' "
            "  AND USERNAME NOT IN ("
            "    'SYS','SYSTEM','APPS','APPLSYS','APPLSYSPUB',"
            "    'CTXSYS','MDSYS','XDB','WMSYS','DBSNMP',"
            "    'ANONYMOUS') "
            "  AND USERNAME NOT LIKE 'APEX_%' "
            "  AND USERNAME NOT LIKE 'FLOWS_%' "
            "ORDER BY USERNAME"
        )
        if len(rows) > 20:
            names = ", ".join(r["USERNAME"] for r in rows[:15])
            self._add(Finding(
                "ORA-DB-008", "Excessive open database accounts",
                "Database Security", "MEDIUM",
                "DBA_USERS",
                f"Open accounts ({len(rows)}): {names} ...",
                f"{len(rows)} non-system database accounts are in OPEN status.",
                "Review and lock database accounts that do not need direct "
                "database connectivity.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-DB-008", "Open account count acceptable")

        # ORA-DB-009  Case-sensitive logon
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER "
            "WHERE NAME = 'sec_case_sensitive_logon'"
        )
        if val and val.upper() == "FALSE":
            self._add(Finding(
                "ORA-DB-009", "Case-sensitive logon disabled",
                "Database Security", "MEDIUM",
                "V$PARAMETER",
                f"sec_case_sensitive_logon = {val}",
                "Case-sensitive password matching is disabled, reducing "
                "the effective password complexity.",
                "Set sec_case_sensitive_logon to TRUE.",
                "CWE-521",
            ))
        else:
            self._pass("ORA-DB-009", "Case-sensitive logon enabled")

        # ORA-DB-010  Password verify function in DEFAULT profile
        rows = self._query(
            "SELECT LIMIT FROM DBA_PROFILES "
            "WHERE PROFILE = 'DEFAULT' "
            "  AND RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'"
        )
        if rows:
            val = rows[0].get("LIMIT", "NULL")
            if val in ("NULL", "UNLIMITED", None, ""):
                self._add(Finding(
                    "ORA-DB-010",
                    "Password verify function not set in DEFAULT profile",
                    "Database Security", "HIGH",
                    "DBA_PROFILES",
                    f"PASSWORD_VERIFY_FUNCTION = {val}",
                    "The DEFAULT database profile does not enforce a password "
                    "verify function. DB users can set trivial passwords.",
                    "Set PASSWORD_VERIFY_FUNCTION to ORA12C_VERIFY_FUNCTION "
                    "or a custom function in the DEFAULT profile.",
                    "CWE-521",
                ))
            else:
                self._pass("ORA-DB-010", "Password verify function configured")
        else:
            self._pass("ORA-DB-010", "Could not check DEFAULT profile")

        # ORA-DB-011  Network encryption not enforced
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER "
            "WHERE NAME = 'sqlnet.encryption_server'"
        )
        # Also check via sqlnet parameter table if v$parameter doesn't have it
        if not val:
            val = self._scalar(
                "SELECT VALUE FROM V$PARAMETER "
                "WHERE NAME LIKE '%encryption%' AND ROWNUM = 1"
            )
        if val and val.upper() in ("REQUIRED", "REQUESTED"):
            self._pass("ORA-DB-011", "Network encryption configured")
        else:
            self._add(Finding(
                "ORA-DB-011", "Network encryption not enforced",
                "Database Security", "HIGH",
                "V$PARAMETER",
                f"sqlnet.encryption_server = {val or 'NOT SET'}",
                "Database network encryption is not enforced. Data in transit "
                "between application and database tiers may be intercepted.",
                "Set SQLNET.ENCRYPTION_SERVER = REQUIRED in sqlnet.ora and "
                "configure AES256 encryption algorithm.",
                "CWE-319",
            ))

        # ORA-DB-012  O7_DICTIONARY_ACCESSIBILITY enabled
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER "
            "WHERE NAME = 'o7_dictionary_accessibility'"
        )
        if val and val.upper() == "TRUE":
            self._add(Finding(
                "ORA-DB-012", "O7_DICTIONARY_ACCESSIBILITY enabled",
                "Database Security", "HIGH",
                "V$PARAMETER",
                f"o7_dictionary_accessibility = {val}",
                "Users with SELECT ANY TABLE can read data dictionary tables "
                "including password hashes and security configuration.",
                "Set O7_DICTIONARY_ACCESSIBILITY to FALSE.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-012", "O7_DICTIONARY_ACCESSIBILITY disabled")

        # ORA-DB-013  SELECT ANY TABLE grants
        rows = self._query(
            "SELECT GRANTEE FROM DBA_SYS_PRIVS "
            "WHERE PRIVILEGE = 'SELECT ANY TABLE' "
            "  AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','EXP_FULL_DATABASE',"
            "    'IMP_FULL_DATABASE','DATAPUMP_EXP_FULL_DATABASE',"
            "    'DATAPUMP_IMP_FULL_DATABASE','SELECT_CATALOG_ROLE') "
            "ORDER BY GRANTEE"
        )
        if rows:
            grantees = ", ".join(r["GRANTEE"] for r in rows[:10])
            self._add(Finding(
                "ORA-DB-013", "SELECT ANY TABLE grants detected",
                "Database Security", "HIGH",
                "DBA_SYS_PRIVS",
                f"SELECT ANY TABLE grantees ({len(rows)}): {grantees}",
                f"{len(rows)} non-default schema(s) have SELECT ANY TABLE, "
                "granting read access to every table in the database.",
                "Revoke SELECT ANY TABLE and grant SELECT on specific "
                "required tables only.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-013", "No unexpected SELECT ANY TABLE grants")

        # ORA-DB-014  ALTER SYSTEM privilege grants
        rows = self._query(
            "SELECT GRANTEE FROM DBA_SYS_PRIVS "
            "WHERE PRIVILEGE = 'ALTER SYSTEM' "
            "  AND GRANTEE NOT IN ('SYS','SYSTEM','DBA') "
            "ORDER BY GRANTEE"
        )
        if rows:
            grantees = ", ".join(r["GRANTEE"] for r in rows[:10])
            self._add(Finding(
                "ORA-DB-014", "ALTER SYSTEM privilege grants",
                "Database Security", "CRITICAL",
                "DBA_SYS_PRIVS",
                f"ALTER SYSTEM grantees: {grantees}",
                f"{len(rows)} non-DBA schema(s) have ALTER SYSTEM, which can "
                "change database parameters, flush caches, and kill sessions.",
                "Revoke ALTER SYSTEM from non-DBA schemas immediately.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-DB-014", "No unexpected ALTER SYSTEM grants")

        # ORA-DB-015  SYSDBA session audit
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER "
            "WHERE NAME = 'audit_sys_operations'"
        )
        if val and val.upper() == "FALSE":
            self._add(Finding(
                "ORA-DB-015", "SYSDBA session auditing disabled",
                "Database Security", "HIGH",
                "V$PARAMETER",
                f"audit_sys_operations = {val}",
                "Operations performed as SYSDBA/SYSOPER are not being audited. "
                "Privileged DBA actions cannot be traced.",
                "Set audit_sys_operations to TRUE and restart the database.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-DB-015", "SYSDBA session auditing enabled")

        # ORA-DB-016  Database listener security
        # Check via V$LISTENER_NETWORK or detect via parameter
        val = self._scalar(
            "SELECT VALUE FROM V$PARAMETER "
            "WHERE NAME = 'local_listener'"
        )
        # We can't directly query listener config from DB; check what we can
        val2 = self._scalar(
            "SELECT VALUE FROM V$PARAMETER "
            "WHERE NAME = 'sec_max_failed_login_attempts'"
        )
        if val2 and val2 != "0":
            self._pass("ORA-DB-016", "DB login rate limiting configured")
        else:
            self._add(Finding(
                "ORA-DB-016",
                "Database login rate limiting not configured",
                "Database Security", "MEDIUM",
                "V$PARAMETER",
                f"sec_max_failed_login_attempts = {val2 or 'NOT SET'}",
                "Database-level login rate limiting is not configured. "
                "Brute-force attacks against database accounts are not throttled.",
                "Set SEC_MAX_FAILED_LOGIN_ATTEMPTS to a value like 10.",
                "CWE-307",
            ))

        # ORA-DB-017  Database Vault status check
        rows = self._query(
            "SELECT * FROM DBA_DV_STATUS WHERE ROWNUM = 1"
        )
        if rows:
            dv_value = rows[0].get("STATUS", "")
            if dv_value and dv_value.upper() == "TRUE":
                self._pass("ORA-DB-017", "Database Vault enabled")
            else:
                self._add(Finding(
                    "ORA-DB-017", "Database Vault not enabled",
                    "Database Security", "MEDIUM",
                    "DBA_DV_STATUS",
                    f"Database Vault status: {dv_value or 'disabled'}",
                    "Oracle Database Vault is not enabled. Privileged users "
                    "(SYS, SYSTEM) can access application data in the APPS schema.",
                    "Enable Database Vault to protect the APPS schema from "
                    "privileged database user access.",
                    "CWE-269",
                ))
        else:
            self._vprint("  DBA_DV_STATUS not available (DB Vault not installed)")

        # ORA-DB-018  Fine-Grained Auditing on sensitive columns
        cnt = self._count(
            "SELECT COUNT(*) FROM DBA_AUDIT_POLICIES "
            "WHERE ENABLED = 'YES'"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-DB-018", "No Fine-Grained Audit policies enabled",
                "Database Security", "MEDIUM",
                "DBA_AUDIT_POLICIES",
                "FGA policies enabled: 0",
                "No Fine-Grained Auditing (FGA) policies are active. "
                "Column-level access to PII and financial data is not tracked.",
                "Create FGA policies for sensitive columns in PER_ALL_PEOPLE_F, "
                "AP_CHECKS_ALL, FND_USER, and HZ_PARTIES.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-DB-018", f"FGA policies active: {cnt}")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 9 — Patching & Versions  (ORA-PATCH-001 .. 004)
    # ═════════════════════════════════════════════════════════════════

    def _check_patching(self):

        # ORA-PATCH-001  EBS version end-of-life check
        if self._ebs_version:
            major = self._ebs_version.split(".")[0] if self._ebs_version else ""
            if major == "11":
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version end-of-life",
                    "Patching & Versions", "CRITICAL",
                    "FND_PRODUCT_GROUPS",
                    f"EBS Release: {self._ebs_version}",
                    f"Oracle EBS {self._ebs_version} is past end of "
                    "Premier Support and may no longer receive security patches.",
                    "Plan migration to EBS 12.2.x which is under active support.",
                ))
            elif self._ebs_version.startswith("12.1"):
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version nearing end-of-life",
                    "Patching & Versions", "HIGH",
                    "FND_PRODUCT_GROUPS",
                    f"EBS Release: {self._ebs_version}",
                    f"Oracle EBS {self._ebs_version} is in Extended Support. "
                    "Security patches may require additional fees.",
                    "Plan migration to EBS 12.2.x for continued Premier Support.",
                ))
            elif self._ebs_version.startswith("12.2"):
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version information",
                    "Patching & Versions", "INFO",
                    "FND_PRODUCT_GROUPS",
                    f"EBS Release: {self._ebs_version}",
                    f"Oracle EBS {self._ebs_version} is under active support.",
                    "Continue applying quarterly CPU patches.",
                ))
            else:
                self._add(Finding(
                    "ORA-PATCH-001", "EBS version unrecognized",
                    "Patching & Versions", "MEDIUM",
                    "FND_PRODUCT_GROUPS",
                    f"EBS Release: {self._ebs_version}",
                    f"EBS release '{self._ebs_version}' is not recognized. "
                    "Unable to determine support status.",
                    "Verify the EBS version and confirm it is under active support.",
                ))
        else:
            self._warn("Could not determine EBS version for patch check")

        # ORA-PATCH-002  Last patch applied (AD_BUGS)
        row = self._query(
            "SELECT BUG_NUMBER, "
            "  TO_CHAR(LAST_UPDATE_DATE,'YYYY-MM-DD') AS APPLIED_DT "
            "FROM AD_BUGS "
            "ORDER BY LAST_UPDATE_DATE DESC "
            "FETCH FIRST 1 ROWS ONLY"
        )
        if row:
            last_patch = row[0].get("BUG_NUMBER", "?")
            last_date = row[0].get("APPLIED_DT", "?")
            self._add(Finding(
                "ORA-PATCH-002", "Last applied patch",
                "Patching & Versions", "INFO",
                "AD_BUGS",
                f"Last patch: {last_patch} on {last_date}",
                f"The most recently applied patch is {last_patch} "
                f"(applied {last_date}).",
                "Ensure quarterly CPU patches are applied within 90 days "
                "of release.",
            ))
        else:
            self._add(Finding(
                "ORA-PATCH-002", "No patch history found",
                "Patching & Versions", "HIGH",
                "AD_BUGS",
                "AD_BUGS table empty or inaccessible",
                "No patch application history could be found in AD_BUGS.",
                "Verify that patches have been applied using adpatch/adop "
                "and that the AD_BUGS table is accessible.",
            ))

        # ORA-PATCH-003  Database version check
        if self._db_version:
            if "11g" in self._db_version or "11.2" in self._db_version:
                self._add(Finding(
                    "ORA-PATCH-003", "Database version end-of-life",
                    "Patching & Versions", "CRITICAL",
                    "V$VERSION",
                    f"DB: {self._db_version}",
                    "Oracle Database 11g is past end of Extended Support "
                    "and no longer receives security patches.",
                    "Upgrade to Oracle Database 19c LTS or later.",
                ))
            elif "12c" in self._db_version or "12.1" in self._db_version:
                self._add(Finding(
                    "ORA-PATCH-003", "Database version nearing end-of-life",
                    "Patching & Versions", "HIGH",
                    "V$VERSION",
                    f"DB: {self._db_version}",
                    "Oracle Database 12c is in Extended Support.",
                    "Plan upgrade to Oracle Database 19c LTS or later.",
                ))
            else:
                self._add(Finding(
                    "ORA-PATCH-003", "Database version information",
                    "Patching & Versions", "INFO",
                    "V$VERSION",
                    f"DB: {self._db_version}",
                    f"Database version: {self._db_version}.",
                    "Continue applying quarterly database CPU patches.",
                ))
        else:
            self._warn("Could not determine database version")

        # ORA-PATCH-004  Patch count in last 6 months
        cnt = self._count(
            "SELECT COUNT(*) FROM AD_BUGS "
            "WHERE LAST_UPDATE_DATE > SYSDATE - 180"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-PATCH-004", "No patches applied in 6 months",
                "Patching & Versions", "HIGH",
                "AD_BUGS",
                "Patches in last 180 days: 0",
                "No EBS patches have been applied in the last 6 months. "
                "The system may be missing critical security fixes.",
                "Apply the latest quarterly CPU and recommended patch bundles.",
                "CWE-1104",
            ))
        else:
            self._add(Finding(
                "ORA-PATCH-004", "Patch activity summary",
                "Patching & Versions", "INFO",
                "AD_BUGS",
                f"Patches in last 180 days: {cnt}",
                f"{cnt} patch(es) applied in the last 6 months.",
                "Continue regular patching cadence.",
            ))

    # ═════════════════════════════════════════════════════════════════
    # Check Group 10 — Workflow & Approvals  (ORA-WF-001 .. 004)
    # ═════════════════════════════════════════════════════════════════

    def _check_workflow(self):

        # ORA-WF-001  Stuck / errored workflow items
        rows = self._query(
            "SELECT wi.ITEM_TYPE, COUNT(*) AS CNT "
            "FROM WF_ITEMS wi "
            "WHERE wi.END_DATE IS NULL "
            "  AND wi.BEGIN_DATE < SYSDATE - 30 "
            "GROUP BY wi.ITEM_TYPE "
            "HAVING COUNT(*) > 100 "
            "ORDER BY CNT DESC"
        )
        if rows:
            details = "; ".join(
                f"{r['ITEM_TYPE']}({r['CNT']:,})" for r in rows[:10]
            )
            total = sum(r["CNT"] for r in rows)
            self._add(Finding(
                "ORA-WF-001", "Stuck workflow items detected",
                "Workflow & Approvals", "MEDIUM",
                "WF_ITEMS",
                f"Stuck items ({total:,}): {details}",
                f"{total:,} workflow item(s) have been open for more than "
                "30 days. Stuck workflows can indicate approval process "
                "failures or bypass.",
                "Investigate and resolve stuck workflow items. Consider "
                "running the Workflow Background Process to retry deferred "
                "activities.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-WF-001", "No stuck workflow items")

        # ORA-WF-002  Workflow notification mailer status
        rows = self._query(
            "SELECT COMPONENT_NAME, COMPONENT_STATUS "
            "FROM FND_SVC_COMPONENTS "
            "WHERE COMPONENT_TYPE = 'WF_MAILER' "
            "ORDER BY COMPONENT_NAME"
        )
        if rows:
            for r in rows:
                status = r.get("COMPONENT_STATUS", "UNKNOWN")
                name = r.get("COMPONENT_NAME", "Mailer")
                if status not in ("RUNNING", "STARTED"):
                    self._add(Finding(
                        "ORA-WF-002", "Workflow mailer not running",
                        "Workflow & Approvals", "MEDIUM",
                        "FND_SVC_COMPONENTS",
                        f"{name} status: {status}",
                        f"The Workflow Notification Mailer '{name}' is in "
                        f"'{status}' state. Approval notifications may not "
                        "be delivered.",
                        "Start the Workflow Notification Mailer from the "
                        "OAM Service Management console.",
                    ))
                else:
                    self._pass("ORA-WF-002", f"Mailer '{name}' is running")
        else:
            self._vprint("  Could not query FND_SVC_COMPONENTS for mailer status")

        # ORA-WF-003  Errored workflow activities
        cnt = self._count(
            "SELECT COUNT(*) FROM WF_ITEM_ACTIVITY_STATUSES "
            "WHERE ACTIVITY_STATUS = 'ERROR' "
            "  AND BEGIN_DATE > SYSDATE - 30"
        )
        if cnt > 50:
            self._add(Finding(
                "ORA-WF-003", "Workflow activity errors in last 30 days",
                "Workflow & Approvals", "MEDIUM",
                "WF_ITEM_ACTIVITY_STATUSES",
                f"Errored activities (30d): {cnt:,}",
                f"{cnt:,} workflow activity(ies) have errored in the last "
                "30 days. This may indicate approval process failures.",
                "Review errored workflow activities and address root causes. "
                "Common issues include invalid approvers, missing setup, "
                "or custom PL/SQL errors.",
            ))
        else:
            self._pass("ORA-WF-003", "Workflow error count acceptable")

        # ORA-WF-004  Background workflow engine status
        rows = self._query(
            "SELECT COMPONENT_NAME, COMPONENT_STATUS "
            "FROM FND_SVC_COMPONENTS "
            "WHERE COMPONENT_TYPE LIKE '%AGENT%' "
            "  OR COMPONENT_NAME LIKE '%Background%' "
            "ORDER BY COMPONENT_NAME"
        )
        if rows:
            stopped = [
                r for r in rows
                if r.get("COMPONENT_STATUS") not in ("RUNNING", "STARTED")
            ]
            if stopped:
                details = "; ".join(
                    f"{r['COMPONENT_NAME']}={r['COMPONENT_STATUS']}"
                    for r in stopped
                )
                self._add(Finding(
                    "ORA-WF-004", "Workflow background engine not running",
                    "Workflow & Approvals", "LOW",
                    "FND_SVC_COMPONENTS",
                    f"Stopped engines: {details}",
                    "One or more workflow background engines are not running. "
                    "Deferred and timed-out activities may not be processed.",
                    "Start workflow background engines from the OAM console.",
                ))
            else:
                self._pass("ORA-WF-004", "Background engines running")
        else:
            self._vprint("  Could not query workflow engine status")

    # ═════════════════════════════════════════════════════════════════
    # Check Group 11 — Application Configuration  (ORA-APP-001 .. 015)
    # ═════════════════════════════════════════════════════════════════

    def _check_app_config(self):

        # ORA-APP-001  Document sequencing not enabled (SOX)
        val = self._get_profile_value("UNIQUE:SEQ_NUMBERS")
        if not val or val.upper() not in ("A", "P"):
            self._add(Finding(
                "ORA-APP-001",
                "Document sequencing not enabled",
                "Application Configuration", "HIGH",
                "FND_PROFILE_OPTION_VALUES",
                f"UNIQUE:SEQ_NUMBERS = {val or 'NULL'}",
                "Document sequencing is not enabled. SOX compliance requires "
                "sequential numbering for financial documents (invoices, "
                "journals, payments) to detect gaps and missing transactions.",
                "Set UNIQUE:SEQ_NUMBERS to 'A' (Always Used) at Site level "
                "for SOX compliance.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-APP-001", "Document sequencing enabled")

        # ORA-APP-002  Financial approval limits — users with unlimited
        rows = self._query(
            "SELECT DISTINCT fu.USER_NAME, aal.AMOUNT_LIMIT "
            "FROM AP_APPROVAL_LIMITS aal "
            "JOIN FND_USER fu ON aal.EMPLOYEE_ID = fu.EMPLOYEE_ID "
            "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND aal.AMOUNT_LIMIT > 999999999 "
            "ORDER BY fu.USER_NAME"
        )
        if rows:
            names = ", ".join(r["USER_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-APP-002",
                "Users with unlimited financial approval limits",
                "Application Configuration", "HIGH",
                "AP_APPROVAL_LIMITS",
                f"Unlimited approvers ({len(rows)}): {names}",
                f"{len(rows)} user(s) have effectively unlimited approval "
                "limits (>999M). This bypasses financial controls.",
                "Set appropriate approval limits based on job role and "
                "authorization matrix. No user should have unlimited limits.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-APP-002", "Approval limits within bounds")

        # ORA-APP-003  Invoice holds not configured
        cnt = self._count(
            "SELECT COUNT(*) FROM AP_HOLD_CODES "
            "WHERE HOLD_TYPE = 'SUPPLY' "
            "  AND INACTIVE_DATE IS NULL"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-APP-003",
                "No active AP invoice hold codes configured",
                "Application Configuration", "MEDIUM",
                "AP_HOLD_CODES",
                "Active supply hold codes: 0",
                "No active invoice hold codes are configured. Invoice holds "
                "are a critical control for preventing unauthorized payments.",
                "Configure appropriate hold codes and hold reasons for "
                "invoice validation (matching, amount limits, etc.).",
                "CWE-284",
            ))
        else:
            self._pass("ORA-APP-003", f"Invoice hold codes active: {cnt}")

        # ORA-APP-004  Period open/close access too broad
        rows = self._query(
            "SELECT DISTINCT fu.USER_NAME "
            "FROM FND_USER fu "
            "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
            "  ON fu.USER_ID = furg.USER_ID "
            "JOIN FND_RESPONSIBILITY_TL frt "
            "  ON furg.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID "
            "  AND furg.RESPONSIBILITY_APPLICATION_ID = frt.APPLICATION_ID "
            "  AND frt.LANGUAGE = 'US' "
            "WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
            "  AND (frt.RESPONSIBILITY_NAME LIKE '%General Ledger%' "
            "    OR frt.RESPONSIBILITY_NAME LIKE '%GL Super%') "
            "ORDER BY fu.USER_NAME"
        )
        if len(rows) > 10:
            names = ", ".join(r["USER_NAME"] for r in rows[:10])
            self._add(Finding(
                "ORA-APP-004",
                "Too many users with GL period access",
                "Application Configuration", "HIGH",
                "FND_USER_RESP_GROUPS_DIRECT",
                f"GL users ({len(rows)}): {names} ...",
                f"{len(rows)} users have General Ledger responsibilities that "
                "may include ability to open/close accounting periods. "
                "Period control should be limited to designated controllers.",
                "Restrict GL Super User and period-management functions to "
                "designated financial controllers (2-3 max).",
                "CWE-269",
            ))
        else:
            self._pass("ORA-APP-004", "GL period access appropriately limited")

        # ORA-APP-005  Lookup values not frozen
        rows = self._query(
            "SELECT LOOKUP_TYPE, COUNT(*) AS VAL_CNT "
            "FROM FND_LOOKUP_VALUES "
            "WHERE LOOKUP_TYPE IN ("
            "  'YES_NO','APPROVAL STATUS','HOLD_STATUS',"
            "  'PAYMENT METHOD','AP_HOLD_CODE','INVOICE TYPE',"
            "  'CURRENCY_CODE','JOURNAL_TYPE')"
            "  AND ENABLED_FLAG = 'Y' "
            "  AND (END_DATE_ACTIVE IS NULL OR END_DATE_ACTIVE > SYSDATE) "
            "GROUP BY LOOKUP_TYPE "
            "ORDER BY LOOKUP_TYPE"
        )
        # Check if lookups are customizable (not frozen)
        unfrozen = self._query(
            "SELECT LOOKUP_TYPE FROM FND_LOOKUP_TYPES "
            "WHERE LOOKUP_TYPE IN ("
            "  'YES_NO','APPROVAL STATUS','HOLD_STATUS',"
            "  'PAYMENT METHOD','AP_HOLD_CODE','INVOICE TYPE',"
            "  'CURRENCY_CODE','JOURNAL_TYPE') "
            "  AND CUSTOMIZATION_LEVEL = 'U'"
        )
        if unfrozen:
            types = ", ".join(r["LOOKUP_TYPE"] for r in unfrozen[:8])
            self._add(Finding(
                "ORA-APP-005",
                "Critical lookup types not frozen",
                "Application Configuration", "MEDIUM",
                "FND_LOOKUP_TYPES",
                f"Unfrozen lookups: {types}",
                f"{len(unfrozen)} critical lookup type(s) allow user-level "
                "customization. Users could modify lookup values that affect "
                "financial processing logic.",
                "Set CUSTOMIZATION_LEVEL to 'S' (System) for critical "
                "lookup types to prevent unauthorized modifications.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-APP-005", "Critical lookups properly restricted")

        # ORA-APP-006  Flexfield security rules
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_FLEX_VALUE_RULE_USAGES "
            "WHERE ROWNUM = 1"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-APP-006",
                "No flexfield security rules defined",
                "Application Configuration", "MEDIUM",
                "FND_FLEX_VALUE_RULE_USAGES",
                "Flexfield security rules: none",
                "No flexfield value security rules are defined. Users with "
                "GL access can post to any chart of accounts segment value.",
                "Define flexfield security rules to restrict which cost "
                "centers, accounts, and entities each responsibility can access.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-APP-006", "Flexfield security rules defined")

        # ORA-APP-007  OAF personalization unrestricted
        val = self._get_profile_value("FND_CUSTOM_OA_DEFINTION")
        val2 = self._get_profile_value("PERSONALIZE_SELF_SERVICE_DEFN")
        if (val and val.upper() == "Y") or (val2 and val2.upper() == "Y"):
            self._add(Finding(
                "ORA-APP-007",
                "OA Framework personalization unrestricted",
                "Application Configuration", "LOW",
                "FND_PROFILE_OPTION_VALUES",
                f"FND_CUSTOM_OA_DEFINTION={val or 'NULL'}, "
                f"PERSONALIZE_SELF_SERVICE_DEFN={val2 or 'NULL'}",
                "OA Framework personalization is enabled, allowing users to "
                "modify page layouts and potentially expose hidden fields.",
                "Set both FND_CUSTOM_OA_DEFINTION and "
                "PERSONALIZE_SELF_SERVICE_DEFN to 'N' in production.",
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
                "FND_PROFILE_OPTION_VALUES",
                f"FND_ATTACHMENT_STORAGE = {val}",
                "Document attachments are stored on the file system rather "
                "than in the database. File system storage requires proper "
                "directory permissions to prevent unauthorized access.",
                "Verify attachment directory permissions are restricted to "
                "applmgr:dba (750). Consider DB storage for sensitive docs.",
                "CWE-732",
            ))
        else:
            self._pass("ORA-APP-008", "Attachment storage acceptable")

        # ORA-APP-009  Alert configuration for security events
        cnt = self._count(
            "SELECT COUNT(*) FROM ALR_ALERTS "
            "WHERE ENABLED_FLAG = 'Y' "
            "  AND (UPPER(ALERT_NAME) LIKE '%SECURITY%' "
            "    OR UPPER(ALERT_NAME) LIKE '%LOGIN%' "
            "    OR UPPER(ALERT_NAME) LIKE '%PASSWORD%' "
            "    OR UPPER(ALERT_NAME) LIKE '%SYSADMIN%')"
        )
        if cnt == 0:
            self._add(Finding(
                "ORA-APP-009",
                "No security alerts configured",
                "Application Configuration", "MEDIUM",
                "ALR_ALERTS",
                "Active security alerts: 0",
                "No Oracle Alert rules are configured for security events "
                "(failed logins, privilege changes, password resets). "
                "Security incidents may go undetected.",
                "Create Oracle Alerts for: failed login threshold, SYSADMIN "
                "login, responsibility changes, and password resets.",
                "CWE-778",
            ))
        else:
            self._pass("ORA-APP-009", f"Security alerts configured: {cnt}")

        # ORA-APP-010  Function security — unregistered functions
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_FORM_FUNCTIONS "
            "WHERE TYPE = 'WWW' "
            "  AND FUNCTION_NAME NOT IN ("
            "    SELECT FUNCTION_ID FROM FND_MENU_ENTRIES) "
            "  AND FUNCTION_NAME NOT LIKE 'FND%TEST%' "
            "  AND CREATION_DATE > SYSDATE - 365"
        )
        if cnt > 20:
            self._add(Finding(
                "ORA-APP-010",
                "Unregistered web functions detected",
                "Application Configuration", "HIGH",
                "FND_FORM_FUNCTIONS",
                f"Unattached functions (recent): {cnt}",
                f"{cnt} web-type form functions created in the last year are "
                "not attached to any menu. They may be accessible via direct "
                "URL if function security is not enforced.",
                "Review unattached functions and either assign them to "
                "appropriate menus or disable them.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-APP-010", "Function security coverage acceptable")

        # ORA-APP-011  Multi-Org security not enforced
        val = self._get_profile_value("XLA_MO_SECURITY_PROFILE_LEVEL")
        val2 = self._get_profile_value("MO:SECURITY_PROFILE")
        if not val2 and not val:
            self._add(Finding(
                "ORA-APP-011",
                "Multi-Org security profile not configured",
                "Application Configuration", "HIGH",
                "FND_PROFILE_OPTION_VALUES",
                f"MO:SECURITY_PROFILE = {val2 or 'NULL'}",
                "Multi-Org security profile is not set. Users may be able to "
                "access data across all operating units without restriction.",
                "Configure MO:SECURITY_PROFILE at the responsibility level "
                "to restrict data access by operating unit.",
                "CWE-269",
            ))
        else:
            self._pass("ORA-APP-011", "Multi-Org security configured")

        # ORA-APP-012  Descriptive flexfield PII exposure
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_DESCRIPTIVE_FLEXS "
            "WHERE APPLICATION_TABLE_NAME IN ("
            "  'PER_ALL_PEOPLE_F','HZ_PARTIES','AP_SUPPLIERS',"
            "  'HR_ALL_ORGANIZATION_UNITS') "
            "  AND PROTECTED_FLAG = 'N'"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-APP-012",
                "Unprotected descriptive flexfields on PII tables",
                "Application Configuration", "MEDIUM",
                "FND_DESCRIPTIVE_FLEXS",
                f"Unprotected DFFs on PII tables: {cnt}",
                f"{cnt} descriptive flexfield(s) on tables containing personal "
                "data are not protected. Sensitive data in DFF segments may "
                "be accessible without proper authorization.",
                "Set PROTECTED_FLAG = 'Y' for DFFs on PII-containing tables "
                "and apply value set security rules.",
                "CWE-284",
            ))
        else:
            self._pass("ORA-APP-012", "PII table DFFs protected")

        # ORA-APP-013  Self-service modules exposed
        ss_resps = self._query(
            "SELECT DISTINCT frt.RESPONSIBILITY_NAME, "
            "  COUNT(DISTINCT fu.USER_ID) AS USER_CNT "
            "FROM FND_RESPONSIBILITY_TL frt "
            "JOIN FND_USER_RESP_GROUPS_DIRECT furg "
            "  ON frt.RESPONSIBILITY_ID = furg.RESPONSIBILITY_ID "
            "  AND frt.APPLICATION_ID = furg.RESPONSIBILITY_APPLICATION_ID "
            "JOIN FND_USER fu ON furg.USER_ID = fu.USER_ID "
            "WHERE frt.LANGUAGE = 'US' "
            "  AND (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE) "
            "  AND (furg.END_DATE IS NULL OR furg.END_DATE > SYSDATE) "
            "  AND (frt.RESPONSIBILITY_NAME LIKE '%iSupplier%' "
            "    OR frt.RESPONSIBILITY_NAME LIKE '%iRecruitment%' "
            "    OR frt.RESPONSIBILITY_NAME LIKE '%Self-Service%' "
            "    OR frt.RESPONSIBILITY_NAME LIKE '%Internet Expenses%') "
            "GROUP BY frt.RESPONSIBILITY_NAME "
            "ORDER BY USER_CNT DESC"
        )
        if ss_resps:
            details = "; ".join(
                f"{r['RESPONSIBILITY_NAME']}({r['USER_CNT']})"
                for r in ss_resps[:5]
            )
            self._add(Finding(
                "ORA-APP-013",
                "External self-service modules active",
                "Application Configuration", "MEDIUM",
                "FND_RESPONSIBILITY_TL",
                f"Self-service resps: {details}",
                f"{len(ss_resps)} external-facing self-service responsibility(ies) "
                "are assigned to users. These modules expose EBS functionality "
                "to external users (suppliers, candidates) and increase "
                "attack surface.",
                "Review self-service responsibility assignments. Ensure "
                "external-facing modules are protected by SSO, MFA, and "
                "regular security patching.",
            ))
        else:
            self._pass("ORA-APP-013", "No external self-service modules active")

        # ORA-APP-014  XML Gateway / Integration interfaces
        cnt = self._count(
            "SELECT COUNT(*) FROM ECX_TP_HEADERS "
            "WHERE PARTY_TYPE = 'E'"
        )
        if cnt > 0:
            self._add(Finding(
                "ORA-APP-014",
                "XML Gateway trading partners configured",
                "Application Configuration", "MEDIUM",
                "ECX_TP_HEADERS",
                f"External trading partners: {cnt}",
                f"{cnt} external trading partner(s) are configured in the XML "
                "Gateway. External integrations are a common attack vector "
                "for XXE and injection attacks.",
                "Review XML Gateway trading partners. Ensure all interfaces "
                "use encrypted transport (HTTPS/SFTP) and validate input XML.",
                "CWE-611",
            ))
        else:
            self._pass("ORA-APP-014", "No XML Gateway partners configured")

        # ORA-APP-015  Integration Repository — exposed REST/SOAP services
        cnt = self._count(
            "SELECT COUNT(*) FROM FND_IREP_CLASSES "
            "WHERE DEPLOYED_FLAG = 'Y' "
            "  AND SCOPE_TYPE = 'PUBLIC'"
        )
        if cnt > 50:
            self._add(Finding(
                "ORA-APP-015",
                "Excessive public Integration Repository services",
                "Application Configuration", "HIGH",
                "FND_IREP_CLASSES",
                f"Public deployed services: {cnt}",
                f"{cnt} Integration Repository services are deployed as public. "
                "Excessive public API exposure increases the attack surface.",
                "Review deployed Integration Repository services. Undeploy "
                "services that are not required. Set scope to PRIVATE for "
                "internal-only APIs.",
                "CWE-284",
            ))
        elif cnt > 0:
            self._add(Finding(
                "ORA-APP-015",
                "Integration Repository services deployed",
                "Application Configuration", "INFO",
                "FND_IREP_CLASSES",
                f"Public deployed services: {cnt}",
                f"{cnt} Integration Repository service(s) are publicly deployed.",
                "Periodically review deployed services for necessity.",
            ))
        else:
            self._pass("ORA-APP-015", "No public IREP services deployed")

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
        print(f"{B}  Oracle EBS Security Audit Scanner v{VERSION}  —  Scan Report{R}")
        print(f"  Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self._instance_name:
            print(f"  Instance   : {self._instance_name} @ {self._host_name}")
        if self._ebs_version:
            print(f"  EBS Release: {self._ebs_version}")
        if self._db_version:
            print(f"  Database   : {self._db_version}")
        print(f"  Findings   : {len(self.findings)}")
        print(f"{B}{'=' * 72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                self.SEVERITY_ORDER.get(f.severity, 5),
                f.category,
                f.rule_id,
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
            "scanner": "oracle_ebs_scanner",
            "version": VERSION,
            "generated": datetime.datetime.now().isoformat(),
            "instance": self._instance_name,
            "host": self._host_name,
            "ebs_version": self._ebs_version,
            "db_version": self._db_version,
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
                f.category,
                f.rule_id,
            ),
        )

        # ── Severity chips ────────────────────────────────────────────
        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        # ── Table rows ────────────────────────────────────────────────
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

        # ── Category filter options ───────────────────────────────────
        categories = sorted({f.category for f in self.findings})
        cat_options = "".join(
            f'<option value="{esc(c)}">{esc(c)}</option>' for c in categories
        )

        # ── Full HTML document ────────────────────────────────────────
        html_content = textwrap.dedent(f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle EBS Security Audit Report</title>
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
  <h1>Oracle E-Business Suite Security Audit Report</h1>
  <p class="meta">Scanner: Oracle EBS Security Audit Scanner v{esc(VERSION)}</p>
  <p class="meta">Instance: {esc(self._instance_name)} @ {esc(self._host_name)}</p>
  <p class="meta">EBS Release: {esc(self._ebs_version)}</p>
  <p class="meta">Database: {esc(self._db_version)}</p>
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
                "No findings — Oracle EBS instance is clean!</div>\n"
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
        prog="oracle_ebs_scanner",
        description=(
            f"Oracle E-Business Suite Security Audit Scanner v{VERSION} — "
            "Comprehensive security audit via live database queries "
            "(125 checks across 11 domains)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Connection examples:
              # Easy Connect syntax
              python oracle_ebs_scanner.py --host dbhost --port 1521 \\
                  --service EBSPROD --user APPS

              # Full DSN string
              python oracle_ebs_scanner.py --dsn "dbhost:1521/EBSPROD" \\
                  --user APPS --json report.json --html report.html

            Environment variables:
              ORA_HOST   ORA_PORT   ORA_SERVICE   ORA_USER   ORA_PASSWORD

            Required privileges (read-only):
              SELECT on FND_USER, FND_USER_RESP_GROUPS_DIRECT,
              FND_RESPONSIBILITY, FND_RESPONSIBILITY_TL,
              FND_PROFILE_OPTIONS, FND_PROFILE_OPTION_VALUES,
              FND_CONCURRENT_PROGRAMS, FND_REQUEST_GROUPS,
              FND_REQUEST_GROUP_UNITS, FND_LOGINS, FND_SVC_COMPONENTS,
              FND_PRODUCT_GROUPS, FND_MENUS, FND_AUDIT_TABLES,
              FND_AUDIT_SCHEMAS, WF_ITEMS, WF_ITEM_ACTIVITY_STATUSES,
              AD_BUGS, PER_ALL_PEOPLE_F (optional),
              V$PARAMETER, V$VERSION, V$INSTANCE,
              DBA_USERS, DBA_ROLE_PRIVS, DBA_TAB_PRIVS, DBA_DB_LINKS,
              DBA_PROFILES
        """),
    )

    # Connection arguments
    parser.add_argument(
        "--host",
        default=os.environ.get("ORA_HOST", ""),
        metavar="HOST",
        help="Database hostname. Env: ORA_HOST",
    )
    parser.add_argument(
        "--port",
        default=os.environ.get("ORA_PORT", "1521"),
        metavar="PORT",
        help="Database port (default: 1521). Env: ORA_PORT",
    )
    parser.add_argument(
        "--service",
        default=os.environ.get("ORA_SERVICE", ""),
        metavar="SERVICE",
        help="Database service name. Env: ORA_SERVICE",
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("ORA_DSN", ""),
        metavar="DSN",
        help="Full DSN string (host:port/service). Overrides --host/--port/"
             "--service. Env: ORA_DSN",
    )
    parser.add_argument(
        "--user", "-u",
        default=os.environ.get("ORA_USER", ""),
        metavar="USER",
        help="Database username (typically APPS). Env: ORA_USER",
    )
    parser.add_argument(
        "--password", "-p",
        default=os.environ.get("ORA_PASSWORD", ""),
        metavar="PASS",
        help="Database password (prompted if not provided). Env: ORA_PASSWORD",
    )

    # Output arguments
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
        help="Verbose output (SQL queries, passed checks, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"oracle_ebs_scanner v{VERSION}",
    )

    args = parser.parse_args()

    # ── Build DSN ─────────────────────────────────────────────────────
    dsn = args.dsn
    if not dsn:
        if not args.host:
            parser.error(
                "Either --dsn or --host is required.\n"
                "  Use --dsn 'host:port/service' or --host HOST --service SVC"
            )
        if not args.service:
            parser.error("--service is required when using --host")
        dsn = f"{args.host}:{args.port}/{args.service}"

    # ── Username ──────────────────────────────────────────────────────
    user = args.user
    if not user:
        parser.error(
            "--user is required (typically APPS). "
            "Env: ORA_USER"
        )

    # ── Password (prompt if not supplied) ─────────────────────────────
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {user}@{dsn}: ")

    # ── Run scanner ───────────────────────────────────────────────────
    print(f"[*] Oracle EBS Security Audit Scanner v{VERSION}")
    print(f"[*] Target: {dsn}")

    scanner = OracleEBSScanner(
        dsn=dsn, user=user, password=password, verbose=args.verbose,
    )

    if not scanner.connect():
        print("[!] Cannot proceed without a database connection.", file=sys.stderr)
        sys.exit(2)

    try:
        scanner.scan()
    finally:
        scanner.disconnect()

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
