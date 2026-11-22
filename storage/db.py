"""SQLite storage for CloudGuardian.

Scans use the format in results.py. Credentials are not ever stored here.

Every function returns two things: the result and an error. If it worked the
error is None. If it failed, the error is a dict with a message to show
"""

import os
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id           TEXT PRIMARY KEY,
    account_id        TEXT,
    scan_time         TEXT NOT NULL,
    selected_services TEXT NOT NULL,
    scan_status       TEXT NOT NULL
        CHECK (scan_status IN ('running', 'completed', 'interrupted')),
    coverage_status   TEXT NOT NULL
        CHECK (coverage_status IN ('complete', 'incomplete'))
);

CREATE TABLE IF NOT EXISTS checks (
    check_id      TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    service       TEXT NOT NULL CHECK (service IN ('S3', 'IAM')),
    resource_id   TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'incomplete')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    reason        TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    check_id   TEXT NOT NULL UNIQUE REFERENCES checks (check_id) ON DELETE CASCADE,
    issue      TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('High', 'Medium', 'Low'))
);

CREATE TABLE IF NOT EXISTS explanations (
    finding_id             TEXT PRIMARY KEY
        REFERENCES findings (finding_id) ON DELETE CASCADE,
    explanation_status     TEXT NOT NULL
        CHECK (explanation_status IN ('pending', 'available', 'unavailable')),
    risk_explanation       TEXT,
    recommended_steps_json TEXT
);

CREATE TABLE IF NOT EXISTS scan_errors (
    error_id    INTEGER PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    stage       TEXT NOT NULL
        CHECK (stage IN ('collection', 'detection', 'AI', 'storage', 'reporting')),
    operation   TEXT NOT NULL,
    resource_id TEXT,
    message     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_checks_scan_id ON checks (scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_errors_scan_id ON scan_errors (scan_id);
"""

# The :names get filled in from the matching keys of each record
INSERT_SCAN = """INSERT INTO scans VALUES
    (:scan_id, :account_id, :scan_time, :selected_services, :scan_status, :coverage_status)"""
INSERT_CHECK = """INSERT INTO checks VALUES
    (:check_id, :scan_id, :service, :resource_id, :rule_id, :status, :evidence_json, :reason)"""
INSERT_FINDING = """INSERT INTO findings VALUES
    (:finding_id, :check_id, :issue, :severity)"""
INSERT_EXPLANATION = """INSERT INTO explanations VALUES
    (:finding_id, :explanation_status, :risk_explanation, :recommended_steps_json)"""
INSERT_ERROR = """INSERT INTO scan_errors (scan_id, stage, operation, resource_id, message)
    VALUES (:scan_id, :stage, :operation, :resource_id, :message)"""


def default_db_path():
    """Where the database file lives. Set CLOUDGUARDIAN_DB to use a different file."""
    if os.environ.get("CLOUDGUARDIAN_DB"):
        return Path(os.environ["CLOUDGUARDIAN_DB"])
    if os.name == "nt":  # Windows (less sure of status on ubuntu)
        return Path(os.environ["LOCALAPPDATA"]) / "CloudGuardian" / "cloudguardian.db"
    return Path.home() / ".local" / "share" / "cloudguardian" / "cloudguardian.db"


def connect(db_path=None):
    """Open the database. Rows come back so you can use row["column_name"]."""
    if db_path is None:
        db_path = default_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite has this off by default (??)
    return conn


def make_error(operation, message):
    return {"stage": "storage", "operation": operation, "resource_id": None, "message": message}


def init_db(db_path=None):
    """Create the folder and the tables if they don't exist yet."""
    if db_path is None:
        db_path = default_db_path()
    try:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = connect(db_path)
        conn.executescript(SCHEMA)
        conn.close()
        return True, None
    except (sqlite3.Error, OSError) as e:
        return False, make_error("init_db", str(e))


def save_scan(scan, db_path=None):
    """Save a whole scan. If any part fails, nothing is saved."""
    conn = connect(db_path)
    try:
        conn.execute(INSERT_SCAN, scan["metadata"])
        for check in scan["checks"]:
            conn.execute(INSERT_CHECK, check)
        for finding in scan["findings"]:
            conn.execute(INSERT_FINDING, finding)
        for explanation in scan["explanations"]:
            conn.execute(INSERT_EXPLANATION, explanation)
        for error in scan["errors"]:
            conn.execute(INSERT_ERROR, error)
        conn.commit()
        return True, None
    except sqlite3.Error as e:
        conn.rollback()
        return False, make_error("save_scan", str(e))
    finally:
        conn.close()


def save_explanations(scan_id, explanations, db_path=None):
    """Save AI explanations after the scan is already saved.

    This is separate from save_scan so that if the AI part fails, the rule
    results that were already saved are not lost. Saving an explanation for
    a finding that already has one replaces the old one.
    """
    conn = connect(db_path)
    try:
        # Make sure every explanation is for a finding in this scan
        rows = conn.execute("""
            SELECT findings.finding_id FROM findings
            JOIN checks ON checks.check_id = findings.check_id
            WHERE checks.scan_id = ?""", (scan_id,)).fetchall()
        finding_ids = []
        for row in rows:
            finding_ids.append(row["finding_id"])

        for explanation in explanations:
            if explanation["finding_id"] not in finding_ids:
                message = f"Finding {explanation['finding_id']} is not in scan {scan_id}."
                return False, make_error("save_explanations", message)

        for explanation in explanations:
            conn.execute("DELETE FROM explanations WHERE finding_id = ?",
                         (explanation["finding_id"],))
            conn.execute(INSERT_EXPLANATION, explanation)
        conn.commit()
        return True, None
    except sqlite3.Error as e:
        conn.rollback()
        return False, make_error("save_explanations", str(e))
    finally:
        conn.close()


def list_scans(db_path=None):
    """All saved scans (just the scans table), newest first."""
    conn = connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM scans ORDER BY scan_time DESC").fetchall()
        scans = []
        for row in rows:
            scans.append(dict(row))
        return scans, None
    except sqlite3.Error as e:
        return [], make_error("list_scans", str(e))
    finally:
        conn.close()


def load_scan(scan_id, db_path=None):
    """Load one saved scan back into the results.py format"""
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            return None, make_error("load_scan", f"Scan {scan_id} was not found.")

        checks = conn.execute("""
            SELECT * FROM checks
            WHERE scan_id = ?""", (scan_id,)).fetchall()

        findings = conn.execute("""
            SELECT findings.* FROM findings
            JOIN checks ON checks.check_id = findings.check_id
            WHERE checks.scan_id = ?""", (scan_id,)).fetchall()

        explanations = conn.execute("""
            SELECT explanations.* FROM explanations
            JOIN findings ON findings.finding_id = explanations.finding_id
            JOIN checks ON checks.check_id = findings.check_id
            WHERE checks.scan_id = ?""", (scan_id,)).fetchall()

        errors = conn.execute("""
            SELECT scan_id, stage, operation, resource_id, message FROM scan_errors
            WHERE scan_id = ?
            ORDER BY error_id""", (scan_id,)).fetchall()

        scan = {
            "metadata": dict(row),
            "checks": [dict(r) for r in checks],
            "findings": [dict(r) for r in findings],
            "explanations": [dict(r) for r in explanations],
            "errors": [dict(r) for r in errors],
        }
        return scan, None
    except sqlite3.Error as e:
        return None, make_error("load_scan", str(e))
    finally:
        conn.close()


def delete_scan(scan_id, db_path=None):
    """Delete a scan. Its checks, findings, explanations and errors are to be deleted, too"""
    conn = connect(db_path)
    try:
        cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return False, make_error("delete_scan", f"Scan {scan_id} was not found.")
        return True, None
    except sqlite3.Error as e:
        conn.rollback()
        return False, make_error("delete_scan", str(e))
    finally:
        conn.close()
