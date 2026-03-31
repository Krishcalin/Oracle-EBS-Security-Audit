# CLAUDE.md — Oracle EBS Security Audit Scanner

## Project Overview

Open-source Python security audit tool for Oracle E-Business Suite R12.x. Performs **68 security checks** across **10 categories** in two modes: live database (via `oracledb`) and offline CSV analysis (zero dependencies).

## Repository Structure

```
oracle_ebs_scanner.py          # Live DB scanner (~2,330 lines) — requires `oracledb`
oracle_ebs_offline_scanner.py  # Offline CSV scanner (~2,090 lines) — stdlib only
export_ebs_audit_data.sql      # 20 SQL export queries for offline mode
banner.svg                     # README banner image
README.md                      # Full documentation
LICENSE                        # MIT License
```

Both scanners are **single-file, self-contained** scripts. There are no packages, modules, or test files.

## Architecture

Each scanner has:
- A `Finding` class (using `__slots__`) with fields: `rule_id`, `name`, `category`, `severity`, `source`, `context`, `description`, `recommendation`, `cwe`
- A main scanner class (`OracleEBSScanner` / `OracleEBSOfflineScanner`) with:
  - 10 check methods: `_check_users`, `_check_passwords`, `_check_profiles`, `_check_responsibilities`, `_check_sod`, `_check_concurrent`, `_check_audit`, `_check_database`, `_check_patching`, `_check_workflow`
  - Output methods: `print_report()`, `save_json()`, `save_html()`
  - A `scan()` orchestrator that calls all check methods
- CLI via `argparse`

## Check Categories and Rule IDs

```
ORA-USER-001..008   User Account Security (8 checks)
ORA-PWD-001..006    Password & Authentication (6 checks)
ORA-PROF-001..010   Profile Options (10 checks)
ORA-ROLE-001..006   Responsibility & Access (6 checks)
ORA-SOD-001..006    Segregation of Duties (6 checks)
ORA-CONC-001..004   Concurrent Programs (4 checks)
ORA-AUDIT-001..005  Audit Trail (5 checks)
ORA-DB-001..010     Database Security (10 checks)
ORA-PATCH-001..004  Patching & Versions (4 checks)
ORA-WF-001..004     Workflow & Approvals (4 checks)
```

## Key Conventions

- **Severity levels:** CRITICAL, HIGH, MEDIUM, LOW, INFO (in descending order)
- **Exit codes:** `1` if any CRITICAL or HIGH findings, `0` otherwise
- **Python version:** 3.8+ minimum
- **Only external dependency:** `oracledb` (live scanner only); offline scanner uses stdlib only
- **Environment variables:** `ORA_HOST`, `ORA_PORT`, `ORA_SERVICE`, `ORA_DSN`, `ORA_USER`, `ORA_PASSWORD`
- **HTML reports** use Catppuccin Mocha dark theme, self-contained with inline CSS/JS
- **Version:** Both scanners are at v1.0.0 (`__version__ = "1.0.0"`)

## Development Guidelines

- Both scanners must stay in sync — same 68 checks, same rule IDs, same severity levels, same Finding structure
- When adding a new check, update **both** scanners and the SQL export file if the check requires new data
- Each check should produce a `Finding` with a meaningful `description`, `recommendation`, and `cwe` mapping
- Checks that depend on optional data (CSV files or DBA_* views) must fail gracefully with skip behavior
- Keep scanners as single files — do not split into packages
- The offline scanner must remain zero-dependency (Python stdlib only)

## Running

```bash
# Live scanner
pip install oracledb
python oracle_ebs_scanner.py --host HOST --service EBSPROD --user APPS --json report.json --html report.html

# Offline scanner (no install needed)
python oracle_ebs_offline_scanner.py ./csv_export_dir/ --json report.json --html report.html
```

## Compliance Frameworks Covered

SOX, CIS Oracle Database Benchmark, NIST 800-53, PCI-DSS v4.0, HIPAA, ISO 27001
