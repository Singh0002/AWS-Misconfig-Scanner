"""CloudGuardian Streamlit page. Run it with: streamlit run app.py

This file just draws the page. The AWS, AI and database code live in their
own modules. Anything we haven't built yet is disabled for now.
"""

import json
import os

import pandas as pd
import streamlit as st

from storage import db

# rule_id (what gets saved in the database) -> name shown on the page
RULES = {
    "S3": {
        "s3_public_acl": "Public ACL grants",
        "s3_block_public_access": "Block Public Access off",
        "s3_wildcard_principal": "Wildcard principal",
        "s3_versioning": "Versioning disabled",
        "s3_https_only": "HTTPS not enforced",
    },
    "IAM": {
        "iam_admin_wildcard": "Admin wildcards",
        "iam_user_mfa": "Users without MFA",
        "iam_root_mfa": "Root without MFA",
        "iam_password_policy": "Weak password policy",
        "iam_unused_access_key": "Access keys unused 90+ days",
    },
}

LOGO = "assets/logo.png"

st.set_page_config(page_title="CloudGuardian", page_icon=LOGO, layout="wide")


@st.cache_resource
def setup_database():
    # cache_resource so this only runs once instead of on every rerun
    return db.init_db()


def rule_name(rule_id):
    for service in RULES:
        if rule_id in RULES[service]:
            return RULES[service][rule_id]
    return rule_id


def format_time(scan):
    # 2026-10-15T14:30:00+00:00 -> 2026-10-15 14:30 UTC
    return scan["scan_time"][:16].replace("T", " ") + " UTC"


def format_services(scan):
    # selected_services is stored as a JSON string, e.g. '["S3", "IAM"]'
    return ", ".join(json.loads(scan["selected_services"]))


def scan_label(scan):
    return format_time(scan) + " - " + format_services(scan)


def find_check(scan, check_id):
    for check in scan["checks"]:
        if check["check_id"] == check_id:
            return check
    return None


@st.dialog("Delete this scan?")
def confirm_delete(scan_id):
    st.write("This removes the scan and all of its results. It can't be undone.")
    if st.button("Delete", type="primary"):
        ok, error = db.delete_scan(scan_id)
        if not ok:
            st.error("Couldn't delete it: " + error["message"])
            return

        # clear the Results tab if it was showing the scan we just deleted
        open_scan = st.session_state.get("scan")
        if open_scan is not None and open_scan["metadata"]["scan_id"] == scan_id:
            st.session_state.scan = None
        st.rerun()


db_ok, db_error = setup_database()

logo_col, title_col, settings_col = st.columns([0.6, 7, 1.5], vertical_alignment="center")
logo_col.image(LOGO, width=64)
title_col.title("CloudGuardian", anchor=False)

# popover instead of a dialog so the settings don't reset when it closes
with settings_col.popover("Settings", width="stretch"):
    st.text_input("AWS profile", value="default")
    st.selectbox("Region", ["us-east-1", "us-east-2", "us-west-1", "us-west-2"])
    st.button("Check connection", disabled=True)

    st.divider()
    st.toggle("AI explanations", value=True)
    if os.environ.get("ANTHROPIC_API_KEY"):
        st.caption("Anthropic API key found.")
    else:
        st.caption("No Anthropic API key found. Set ANTHROPIC_API_KEY to turn on explanations.")

scan_tab, results_tab, saved_tab = st.tabs(["Scan", "Results", "Saved scans"])


# Scan tab
with scan_tab:
    selected_services = []
    selected_rules = []

    s3_col, iam_col = st.columns(2)
    for service, column in [("S3", s3_col), ("IAM", iam_col)]:
        with column:
            if st.checkbox("**" + service + "**", value=True):
                selected_services.append(service)
                for rule_id in RULES[service]:
                    if st.checkbox(RULES[service][rule_id], value=True, key=rule_id):
                        selected_rules.append(rule_id)

    if st.button("Start scan", type="primary"):
        if len(selected_services) == 0 or len(selected_rules) == 0:
            st.warning("Pick at least one service and one rule.")
        else:
            # TODO (Martin): call the coordinator here
            st.info("Scanning isn't hooked up yet.")

    # TODO (Ajay): real progress + block a second scan while one is running
    st.progress(0, text="No scan running.")


# Saved scans tab. This is above the Results tab on purpose so that a scan
# opened here shows up in Results on the same run.
with saved_tab:
    if not db_ok:
        st.error("Couldn't open the local database: " + db_error["message"])
        saved_scans = []
    else:
        saved_scans, error = db.list_scans()
        if error:
            st.error("Couldn't load saved scans: " + error["message"])

    if len(saved_scans) == 0:
        st.write("No saved scans yet.")
    else:
        rows = []
        for scan in saved_scans:
            rows.append({
                "Scan time": format_time(scan),
                "Account": scan["account_id"],
                "Services": format_services(scan),
                "Status": scan["scan_status"],
                "Coverage": scan["coverage_status"],
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    chosen = st.selectbox("Scan", saved_scans, format_func=scan_label,
                          placeholder="Nothing saved")

    # only reads from the database, no AWS or AI calls
    if st.button("Open", disabled=chosen is None):
        scan, error = db.load_scan(chosen["scan_id"])
        if error:
            st.error("Couldn't open that scan: " + error["message"])
        else:
            st.session_state.scan = scan
            st.success("Opened. See the Results tab.")

    if st.button("Delete", disabled=chosen is None):
        confirm_delete(chosen["scan_id"])


# Results tab
with results_tab:
    scan = st.session_state.get("scan")

    if scan is None:
        st.write("No scan loaded yet.")
        st.caption("High: 0, Medium: 0, Low: 0, Passed: 0, Incomplete: 0")
    else:
        account = scan["metadata"]["account_id"] or "unknown"
        st.write("Account " + account + " | " + format_time(scan["metadata"])
                 + " | " + format_services(scan["metadata"]))

        high = medium = low = 0
        for finding in scan["findings"]:
            if finding["severity"] == "High":
                high += 1
            elif finding["severity"] == "Medium":
                medium += 1
            else:
                low += 1

        passed = incomplete = 0
        for check in scan["checks"]:
            if check["status"] == "pass":
                passed += 1
            elif check["status"] == "incomplete":
                incomplete += 1

        st.caption(f"High: {high}, Medium: {medium}, Low: {low}, "
                   f"Passed: {passed}, Incomplete: {incomplete}")

    # TODO (Martin): make these filters work. Disabled until then.
    st.pills("Show", ["S3", "IAM", "High", "Medium", "Low"], selection_mode="multi",
             default=["S3", "IAM", "High", "Medium", "Low"],
             label_visibility="collapsed", disabled=True)

    # sort findings High -> Medium -> Low
    findings = []
    if scan is not None:
        for severity in ["High", "Medium", "Low"]:
            for finding in scan["findings"]:
                if finding["severity"] == severity:
                    findings.append(finding)

        if len(scan["findings"]) == 0:
            st.write("The selected checks found no issues.")

    rows = []
    for finding in findings:
        check = find_check(scan, finding["check_id"])
        rows.append({
            "Severity": finding["severity"],
            "Service": check["service"],
            "Resource": check["resource_id"],
            "Issue": finding["issue"],
        })
    table = pd.DataFrame(rows, columns=["Severity", "Service", "Resource", "Issue"])

    st.dataframe(table, hide_index=True, width="stretch")

    # TODO (Ajay): details + AI explanation for the selected finding
    st.caption("Finding details and AI explanations will show here.")

    with st.expander("Incomplete checks and errors"):
        incomplete_rows = []
        error_rows = []
        if scan is not None:
            for check in scan["checks"]:
                if check["status"] == "incomplete":
                    incomplete_rows.append({
                        "Service": check["service"],
                        "Resource": check["resource_id"],
                        "Rule": rule_name(check["rule_id"]),
                        "Reason": check["reason"],
                    })
            for error in scan["errors"]:
                error_rows.append({
                    "Stage": error["stage"],
                    "Operation": error["operation"],
                    "Resource": error["resource_id"],
                    "Message": error["message"],
                })

        if len(incomplete_rows) == 0 and len(error_rows) == 0:
            st.write("None.")
        if len(incomplete_rows) > 0:
            st.dataframe(pd.DataFrame(incomplete_rows), hide_index=True, width="stretch")
        if len(error_rows) > 0:
            st.dataframe(pd.DataFrame(error_rows), hide_index=True, width="stretch")

    # TODO: report download (Sprint 3)
    st.download_button("Download report", data="", file_name="cloudguardian-report.html",
                       disabled=True)
