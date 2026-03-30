-- ============================================================================
-- Oracle EBS Security Audit — Data Export Queries  v1.2.0
-- ============================================================================
-- Run these queries against your Oracle EBS database and export each result
-- set to the corresponding CSV file.  The offline scanner expects these exact
-- file names and column headers.
--
-- Tools that support CSV export:
--   SQL*Plus    :  SET MARKUP CSV ON  /  SPOOL filename.csv
--   SQLcl       :  SET SQLFORMAT CSV  /  SPOOL filename.csv
--   SQL Developer:  Right-click result → Export → CSV
--   Toad / DBeaver:  Export to CSV
--
-- Connection: APPS schema (recommended) or a read-only audit account with
--             SELECT grants on the tables listed below.
-- ============================================================================


-- ────────────────────────────────────────────────────────────────────────────
-- 1.  instance_info.csv
--     Instance and version metadata (single row)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    (SELECT INSTANCE_NAME FROM V$INSTANCE WHERE ROWNUM = 1) AS INSTANCE_NAME,
    (SELECT HOST_NAME     FROM V$INSTANCE WHERE ROWNUM = 1) AS HOST_NAME,
    (SELECT BANNER        FROM V$VERSION  WHERE ROWNUM = 1) AS DB_VERSION,
    (SELECT RELEASE_NAME  FROM FND_PRODUCT_GROUPS WHERE ROWNUM = 1) AS EBS_VERSION
FROM DUAL;


-- ────────────────────────────────────────────────────────────────────────────
-- 2.  ebs_users.csv
--     All EBS user accounts with employee status
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fu.USER_NAME,
    fu.DESCRIPTION,
    TO_CHAR(fu.START_DATE,      'YYYY-MM-DD') AS START_DATE,
    TO_CHAR(fu.END_DATE,        'YYYY-MM-DD') AS END_DATE,
    TO_CHAR(fu.LAST_LOGON_DATE, 'YYYY-MM-DD') AS LAST_LOGON_DATE,
    TO_CHAR(fu.PASSWORD_DATE,   'YYYY-MM-DD') AS PASSWORD_DATE,
    TO_CHAR(fu.CREATION_DATE,   'YYYY-MM-DD') AS CREATION_DATE,
    fu.EMPLOYEE_ID,
    fu.PERSON_PARTY_ID,
    fu.EMAIL_ADDRESS,
    fu.ENCRYPTED_USER_PASSWORD,
    papf.CURRENT_EMPLOYEE_FLAG AS EMPLOYEE_CURRENT_FLAG
FROM FND_USER fu
LEFT JOIN PER_ALL_PEOPLE_F papf
    ON fu.EMPLOYEE_ID = papf.PERSON_ID
    AND SYSDATE BETWEEN papf.EFFECTIVE_START_DATE AND papf.EFFECTIVE_END_DATE
ORDER BY fu.USER_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 3.  ebs_user_responsibilities.csv
--     User-to-responsibility assignments (active users only)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fu.USER_NAME,
    TO_CHAR(fu.END_DATE,   'YYYY-MM-DD') AS USER_END_DATE,
    frt.RESPONSIBILITY_NAME,
    TO_CHAR(furg.START_DATE,'YYYY-MM-DD') AS RESP_START_DATE,
    TO_CHAR(furg.END_DATE,  'YYYY-MM-DD') AS RESP_END_DATE,
    furg.RESPONSIBILITY_APPLICATION_ID,
    furg.RESPONSIBILITY_ID
FROM FND_USER fu
JOIN FND_USER_RESP_GROUPS_DIRECT furg
    ON fu.USER_ID = furg.USER_ID
JOIN FND_RESPONSIBILITY_TL frt
    ON furg.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID
    AND furg.RESPONSIBILITY_APPLICATION_ID = frt.APPLICATION_ID
    AND frt.LANGUAGE = 'US'
ORDER BY fu.USER_NAME, frt.RESPONSIBILITY_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 4.  ebs_profile_options.csv
--     Security-relevant profile option values (Site level)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fpo.PROFILE_OPTION_NAME,
    fpov.PROFILE_OPTION_VALUE,
    fpov.LEVEL_ID
FROM FND_PROFILE_OPTIONS fpo
JOIN FND_PROFILE_OPTION_VALUES fpov
    ON fpo.PROFILE_OPTION_ID = fpov.PROFILE_OPTION_ID
WHERE fpo.PROFILE_OPTION_NAME IN (
    'SIGNON_PASSWORD_LENGTH',
    'SIGNON_PASSWORD_HARD_TO_GUESS',
    'SIGNON_PASSWORD_NO_REUSE',
    'SIGNON_PASSWORD_FAILURE_LIMIT',
    'ICX_SESSION_TIMEOUT',
    'GUEST_USER_PWD',
    'FND_DIAGNOSTICS',
    'AFLOG_ENABLED',
    'APPS_SERVLET_AGENT',
    'APPS_FRAMEWORK_AGENT',
    'FND_CUSTOM_OA_DEFINTION',
    'SIGN_ON_NOTIFICATION',
    'ICX_LIMIT_CONNECT',
    'SIGNONAUDIT:LEVEL',
    'AUDITTRAIL:ACTIVATE',
    'SELF_REGISTRATION_ENABLED',
    'SELF_REGISTRATION_APPROVAL',
    'APPS_SSO',
    'CONCURRENT_LOGIN_LIMIT',
    'APPLCSF',
    'APPLOUT',
    'UNIQUE:SEQ_NUMBERS',
    'PERSONALIZE_SELF_SERVICE_DEFN',
    'FND_ATTACHMENT_STORAGE',
    'MO:SECURITY_PROFILE',
    'XLA_MO_SECURITY_PROFILE_LEVEL'
)
ORDER BY fpo.PROFILE_OPTION_NAME, fpov.LEVEL_ID;


-- ────────────────────────────────────────────────────────────────────────────
-- 5.  ebs_responsibilities.csv
--     Responsibility definitions with menu names
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    frt.RESPONSIBILITY_NAME,
    fa.APPLICATION_SHORT_NAME AS APPLICATION_NAME,
    fm.MENU_NAME,
    TO_CHAR(fr.END_DATE, 'YYYY-MM-DD') AS RESP_END_DATE
FROM FND_RESPONSIBILITY fr
JOIN FND_RESPONSIBILITY_TL frt
    ON fr.RESPONSIBILITY_ID = frt.RESPONSIBILITY_ID
    AND fr.APPLICATION_ID   = frt.APPLICATION_ID
    AND frt.LANGUAGE = 'US'
JOIN FND_APPLICATION fa
    ON fr.APPLICATION_ID = fa.APPLICATION_ID
LEFT JOIN FND_MENUS fm
    ON fr.MENU_ID = fm.MENU_ID
ORDER BY frt.RESPONSIBILITY_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 6.  ebs_concurrent_programs.csv
--     Enabled concurrent programs
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fcp.CONCURRENT_PROGRAM_NAME,
    fcpt.USER_CONCURRENT_PROGRAM_NAME,
    fcp.EXECUTION_METHOD_CODE,
    fcp.ENABLED_FLAG
FROM FND_CONCURRENT_PROGRAMS fcp
JOIN FND_CONCURRENT_PROGRAMS_TL fcpt
    ON fcp.CONCURRENT_PROGRAM_ID = fcpt.CONCURRENT_PROGRAM_ID
    AND fcp.APPLICATION_ID       = fcpt.APPLICATION_ID
    AND fcpt.LANGUAGE = 'US'
WHERE fcp.ENABLED_FLAG = 'Y'
ORDER BY fcp.CONCURRENT_PROGRAM_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 7.  ebs_request_group_access.csv
--     Which programs are in which request groups
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    frg.REQUEST_GROUP_NAME,
    fcp.CONCURRENT_PROGRAM_NAME,
    frgu.REQUEST_UNIT_TYPE
FROM FND_REQUEST_GROUP_UNITS frgu
JOIN FND_REQUEST_GROUPS frg
    ON frgu.REQUEST_GROUP_ID = frg.REQUEST_GROUP_ID
    AND frgu.APPLICATION_ID  = frg.APPLICATION_ID
LEFT JOIN FND_CONCURRENT_PROGRAMS fcp
    ON frgu.REQUEST_UNIT_ID     = fcp.CONCURRENT_PROGRAM_ID
    AND frgu.UNIT_APPLICATION_ID = fcp.APPLICATION_ID
    AND frgu.REQUEST_UNIT_TYPE   = 'P'
ORDER BY frg.REQUEST_GROUP_NAME, fcp.CONCURRENT_PROGRAM_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 8.  ebs_concurrent_requests.csv
--     Completed concurrent requests in last 30 days (submitted by whom)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fu.USER_NAME,
    fcp.CONCURRENT_PROGRAM_NAME,
    fcr.PHASE_CODE,
    TO_CHAR(fcr.ACTUAL_START_DATE, 'YYYY-MM-DD') AS ACTUAL_START_DATE
FROM FND_CONCURRENT_REQUESTS fcr
JOIN FND_USER fu
    ON fcr.REQUESTED_BY = fu.USER_ID
JOIN FND_CONCURRENT_PROGRAMS fcp
    ON fcr.CONCURRENT_PROGRAM_ID = fcp.CONCURRENT_PROGRAM_ID
    AND fcr.PROGRAM_APPLICATION_ID = fcp.APPLICATION_ID
WHERE fcr.PHASE_CODE = 'C'
    AND fcr.ACTUAL_START_DATE > SYSDATE - 30
ORDER BY fcr.ACTUAL_START_DATE DESC;


-- ────────────────────────────────────────────────────────────────────────────
-- 9.  ebs_audit_config.csv
--     Audit trail table configuration
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fat.TABLE_NAME,
    fas.STATE AS AUDIT_STATE
FROM FND_AUDIT_TABLES fat
JOIN FND_AUDIT_SCHEMAS fas
    ON fat.AUDIT_SCHEMA_ID = fas.AUDIT_SCHEMA_ID
ORDER BY fat.TABLE_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 10. ebs_patches.csv
--     Applied patches (AD_BUGS)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    BUG_NUMBER,
    TO_CHAR(LAST_UPDATE_DATE, 'YYYY-MM-DD') AS LAST_UPDATE_DATE
FROM AD_BUGS
ORDER BY LAST_UPDATE_DATE DESC;


-- ────────────────────────────────────────────────────────────────────────────
-- 11. ebs_workflow_components.csv
--     Workflow service component status
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    COMPONENT_NAME,
    COMPONENT_TYPE,
    COMPONENT_STATUS
FROM FND_SVC_COMPONENTS
ORDER BY COMPONENT_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 12. ebs_workflow_stuck.csv
--     Stuck workflow items (open > 30 days, grouped by type)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    ITEM_TYPE,
    COUNT(*) AS ITEM_COUNT
FROM WF_ITEMS
WHERE END_DATE IS NULL
    AND BEGIN_DATE < SYSDATE - 30
GROUP BY ITEM_TYPE
HAVING COUNT(*) > 10
ORDER BY COUNT(*) DESC;


-- ────────────────────────────────────────────────────────────────────────────
-- 13. ebs_workflow_errors.csv
--     Workflow activity errors in last 30 days
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    COUNT(*) AS ERROR_COUNT_30D
FROM WF_ITEM_ACTIVITY_STATUSES
WHERE ACTIVITY_STATUS = 'ERROR'
    AND BEGIN_DATE > SYSDATE - 30;


-- ────────────────────────────────────────────────────────────────────────────
-- 14. ebs_login_audit_old.csv
--     Count of audit records older than 1 year (retention review)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    COUNT(*) AS OLD_RECORD_COUNT
FROM FND_LOGIN_RESP_ACTIONS
WHERE LOGIN_ID IN (
    SELECT LOGIN_ID FROM FND_LOGINS
    WHERE START_TIME < SYSDATE - 365
);


-- ────────────────────────────────────────────────────────────────────────────
-- 15. db_users.csv
--     Database user accounts
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    USERNAME,
    ACCOUNT_STATUS,
    PROFILE
FROM DBA_USERS
ORDER BY USERNAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 16. db_role_privs.csv
--     Database role privilege grants
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    GRANTEE,
    GRANTED_ROLE,
    ADMIN_OPTION
FROM DBA_ROLE_PRIVS
ORDER BY GRANTEE, GRANTED_ROLE;


-- ────────────────────────────────────────────────────────────────────────────
-- 17. db_tab_privs.csv
--     Database object privilege grants (filtered to sensitive packages)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    GRANTEE,
    TABLE_NAME,
    PRIVILEGE
FROM DBA_TAB_PRIVS
WHERE PRIVILEGE = 'EXECUTE'
    AND TABLE_NAME IN (
        'UTL_FILE','UTL_HTTP','UTL_SMTP','UTL_TCP','UTL_INADDR',
        'DBMS_SQL','DBMS_JAVA','DBMS_BACKUP_RESTORE',
        'DBMS_SYS_SQL','DBMS_RANDOM','DBMS_LOB',
        'DBMS_ADVISOR','DBMS_OBFUSCATION_TOOLKIT'
    )
ORDER BY TABLE_NAME, GRANTEE;


-- ────────────────────────────────────────────────────────────────────────────
-- 18. db_links.csv
--     Database links
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    OWNER,
    DB_LINK,
    HOST,
    TO_CHAR(CREATED, 'YYYY-MM-DD') AS CREATED
FROM DBA_DB_LINKS
ORDER BY OWNER, DB_LINK;


-- ────────────────────────────────────────────────────────────────────────────
-- 19. db_profiles.csv
--     Database password / resource profiles
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    PROFILE,
    RESOURCE_NAME,
    LIMIT AS LIMIT_VALUE
FROM DBA_PROFILES
ORDER BY PROFILE, RESOURCE_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 20. db_parameters.csv
--     Security-relevant database initialization parameters
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    NAME,
    VALUE
FROM V$PARAMETER
WHERE NAME IN (
    'audit_trail',
    'utl_file_dir',
    'remote_os_authent',
    'sec_case_sensitive_logon',
    'os_authent_prefix',
    'remote_login_passwordfile',
    'sqlnet.encryption_server',
    'o7_dictionary_accessibility',
    'audit_sys_operations',
    'sec_max_failed_login_attempts'
)
ORDER BY NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 21. ebs_logins.csv
--     Recent EBS login records (last 30 days)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    LOGIN_NAME,
    LOGIN_TYPE,
    TO_CHAR(START_TIME, 'YYYY-MM-DD') AS START_TIME
FROM FND_LOGINS
WHERE START_TIME > SYSDATE - 30
ORDER BY START_TIME DESC;


-- ────────────────────────────────────────────────────────────────────────────
-- 22. db_sys_privs.csv
--     Database system privilege grants
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    GRANTEE,
    PRIVILEGE,
    ADMIN_OPTION
FROM DBA_SYS_PRIVS
WHERE PRIVILEGE IN (
    'SELECT ANY TABLE',
    'ALTER SYSTEM',
    'CREATE ANY PROCEDURE',
    'DROP ANY TABLE',
    'ALTER ANY TABLE',
    'GRANT ANY PRIVILEGE',
    'GRANT ANY ROLE'
)
ORDER BY PRIVILEGE, GRANTEE;


-- ────────────────────────────────────────────────────────────────────────────
-- 23. db_dv_status.csv
--     Oracle Database Vault status (if installed)
-- ────────────────────────────────────────────────────────────────────────────
-- NOTE: This query will fail if Database Vault is not installed.
--       Simply skip this file if the query errors.
SELECT NAME, STATUS FROM DBA_DV_STATUS;


-- ────────────────────────────────────────────────────────────────────────────
-- 24. db_fga_policies.csv
--     Fine-Grained Auditing policies
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    OBJECT_SCHEMA,
    OBJECT_NAME,
    POLICY_NAME,
    ENABLED
FROM DBA_AUDIT_POLICIES
ORDER BY OBJECT_SCHEMA, OBJECT_NAME, POLICY_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 25. db_unified_audit.csv
--     Unified Audit enabled policies (12c+)
-- ────────────────────────────────────────────────────────────────────────────
-- NOTE: This query requires Oracle 12c+.  Skip if on 11g.
SELECT
    POLICY_NAME,
    ENABLED_OPTION,
    ENTITY_NAME,
    ENTITY_TYPE
FROM AUDIT_UNIFIED_ENABLED_POLICIES
ORDER BY POLICY_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 26. ebs_approval_limits.csv
--     AP approval limits per user
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    fu.USER_NAME,
    aal.AMOUNT_LIMIT,
    aal.CURRENCY_CODE
FROM AP_APPROVAL_LIMITS aal
JOIN FND_USER fu ON aal.EMPLOYEE_ID = fu.EMPLOYEE_ID
WHERE (fu.END_DATE IS NULL OR fu.END_DATE > SYSDATE)
ORDER BY aal.AMOUNT_LIMIT DESC;


-- ────────────────────────────────────────────────────────────────────────────
-- 27. ebs_hold_codes.csv
--     AP invoice hold codes
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    HOLD_LOOKUP_CODE,
    HOLD_TYPE,
    DESCRIPTION,
    TO_CHAR(INACTIVE_DATE, 'YYYY-MM-DD') AS INACTIVE_DATE
FROM AP_HOLD_CODES
ORDER BY HOLD_LOOKUP_CODE;


-- ────────────────────────────────────────────────────────────────────────────
-- 28. ebs_lookup_types.csv
--     Lookup type customization levels
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    LOOKUP_TYPE,
    CUSTOMIZATION_LEVEL,
    SECURITY_GROUP_ID
FROM FND_LOOKUP_TYPES
WHERE LOOKUP_TYPE IN (
    'YES_NO','APPROVAL STATUS','HOLD_STATUS',
    'PAYMENT METHOD','AP_HOLD_CODE','INVOICE TYPE',
    'CURRENCY_CODE','JOURNAL_TYPE'
)
ORDER BY LOOKUP_TYPE;


-- ────────────────────────────────────────────────────────────────────────────
-- 29. ebs_flex_rules.csv
--     Flexfield security rule usages (existence check)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    APPLICATION_ID,
    RESPONSIBILITY_ID,
    FLEX_VALUE_RULE_ID
FROM FND_FLEX_VALUE_RULE_USAGES
WHERE ROWNUM <= 100
ORDER BY APPLICATION_ID;


-- ────────────────────────────────────────────────────────────────────────────
-- 30. ebs_alerts.csv
--     Oracle Alert definitions
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    ALERT_NAME,
    ENABLED_FLAG,
    ALERT_CONDITION_TYPE
FROM ALR_ALERTS
ORDER BY ALERT_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 31. ebs_form_functions.csv
--     Form function security (recent web functions)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    FUNCTION_NAME,
    TYPE,
    TO_CHAR(CREATION_DATE, 'YYYY-MM-DD') AS CREATION_DATE,
    CASE WHEN FUNCTION_ID IN (
        SELECT FUNCTION_ID FROM FND_MENU_ENTRIES
    ) THEN 'Y' ELSE 'N' END AS ATTACHED_TO_MENU
FROM FND_FORM_FUNCTIONS
WHERE TYPE = 'WWW'
    AND CREATION_DATE > SYSDATE - 365
ORDER BY CREATION_DATE DESC;


-- ────────────────────────────────────────────────────────────────────────────
-- 32. ebs_dff_config.csv
--     Descriptive flexfield configuration (PII tables)
-- ────────────────────────────────────────────────────────────────────────────
SELECT
    APPLICATION_TABLE_NAME,
    DESCRIPTIVE_FLEXFIELD_NAME,
    PROTECTED_FLAG
FROM FND_DESCRIPTIVE_FLEXS
WHERE APPLICATION_TABLE_NAME IN (
    'PER_ALL_PEOPLE_F','HZ_PARTIES','AP_SUPPLIERS',
    'HR_ALL_ORGANIZATION_UNITS'
)
ORDER BY APPLICATION_TABLE_NAME;


-- ────────────────────────────────────────────────────────────────────────────
-- 33. ebs_xml_gateway.csv
--     XML Gateway trading partners
-- ────────────────────────────────────────────────────────────────────────────
-- NOTE: Table may not exist if XML Gateway is not used. Skip on error.
SELECT
    TP_HEADER_ID,
    PARTY_TYPE,
    PARTY_SITE_ID
FROM ECX_TP_HEADERS
ORDER BY TP_HEADER_ID;


-- ────────────────────────────────────────────────────────────────────────────
-- 34. ebs_irep_services.csv
--     Integration Repository deployed services
-- ────────────────────────────────────────────────────────────────────────────
-- NOTE: Table may not exist on older EBS versions. Skip on error.
SELECT
    CLASS_NAME,
    DEPLOYED_FLAG,
    SCOPE_TYPE
FROM FND_IREP_CLASSES
WHERE DEPLOYED_FLAG = 'Y'
ORDER BY CLASS_NAME;


-- ============================================================================
-- END OF EXPORT QUERIES
-- ============================================================================
-- Place all CSV files in a single directory and run:
--   python oracle_ebs_offline_scanner.py /path/to/csv_dir
--
-- Required files  : instance_info.csv, ebs_users.csv,
--                   ebs_user_responsibilities.csv, ebs_profile_options.csv
-- Optional files  : all others (checks are skipped if file is missing)
-- ============================================================================
