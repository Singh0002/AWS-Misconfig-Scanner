"""CloudGuardian Streamlit page. Run it with: streamlit run app.py

This file just draws the page. The AWS, AI and database code live in their
own modules. Colors, font and corners come from .streamlit/config.toml.
"""

import json
import os

import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError
import streamlit as st

import coordinator
import test_connection
import finding_details
import scan_progress
from ai import client
from report import html_report
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

# name in the Settings dropdown -> model ID sent to Anthropic
MODELS = {
    "Opus": "claude-opus-5-5",
    "Sonnet": "claude-sonnet-5-5",
    "Haiku": "claude-haiku-5-5",
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


def short_account(account_id):
    # only the last 4 digits on screen, e.g. ••••9012
    if not account_id:
        return "unknown"
    return "••••" + str(account_id)[-4:]


def count_results(scan):
    counts = {"High": 0, "Medium": 0, "Low": 0, "pass": 0, "incomplete": 0}
    for finding in scan["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    for check in scan["checks"]:
        if check["status"] in ("pass", "incomplete"):
            counts[check["status"]] += 1
    return counts


def show_finding(scan, finding, expanded):
    """One finding that opens to show what the rule found, then the AI explanation."""
    info = finding_details.details(scan, finding)
    with st.expander(finding_details.title(scan, finding), expanded=expanded):
        st.caption(info["service"] + " · " + rule_name(info["rule_id"]))
        if info["evidence"]:
            st.markdown("**What we found**")
            st.code("\n".join(info["evidence"]), language=None)

        ai = info["explanation"]
        if ai["state"] == "available":
            if ai["text"]:
                st.markdown("**Why it matters** :gray[(AI explanation)]")
                st.markdown(ai["text"])
            if ai["steps"]:
                st.markdown("**How to fix it**")
                for number, step in enumerate(ai["steps"], 1):
                    st.markdown(str(number) + ". " + step)
            st.caption("Suggestions are advice only. CloudGuardian never changes your account.")
        else:
            st.info(ai["message"])


def check_connection():
    """Read-only checks that the AWS credentials, S3 and IAM work. Never shows a key."""
    try:
        session = coordinator.make_session()
    except Exception as error:
        return [("AWS credentials", False, "Couldn't set up AWS (" + type(error).__name__ + ").")]
    ok, message = test_connection.check_aws_credentials(session)
    results = [("AWS credentials", ok, message)]
    if ok:
        results.append(("S3",) + test_connection.check_s3_access(session))
        results.append(("IAM",) + test_connection.check_iam_access(session))
    return results


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

# defaults the header needs before the widgets that change them are drawn
st.session_state.setdefault("explain", True)
st.session_state.setdefault("model", "Opus")
if "api_key" not in st.session_state:
    # load a key saved last time, only once so it doesn't undo what you type
    st.session_state.api_key = client.saved_key()
    st.session_state.remember = bool(st.session_state.api_key)

title_col, status_col = st.columns([3, 1.4], vertical_alignment="center")
with title_col:
    logo_col, name_col = st.columns([1, 9], vertical_alignment="center")
    logo_col.image(LOGO, width=64)
    name_col.title("CloudGuardian", anchor=False)
    name_col.caption("Your AWS security check-up, explained in plain English")
with status_col:
    # AWS: from the last connection check, or else the account of the open scan
    aws = st.session_state.get("aws_status")
    open_scan = st.session_state.get("scan")
    if aws is None and open_scan is not None:
        aws = (True, open_scan["metadata"]["account_id"])
    if aws is None:
        aws_badge = ":gray-badge[AWS not checked]"
    elif aws[0]:
        aws_badge = ":green-badge[:material/check_circle: AWS " + short_account(aws[1]) + "]"
    else:
        aws_badge = ":red-badge[:material/error: AWS not connected]"
    has_key = st.session_state.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if st.session_state.explain and has_key:
        ai_badge = ":orange-badge[:material/auto_awesome: AI · " + st.session_state.model + "]"
    else:
        ai_badge = ":gray-badge[AI off]"
    st.markdown(aws_badge + " " + ai_badge)

scan_tab, results_tab, saved_tab, settings_tab = st.tabs(
    [":material/radar: Scan", ":material/fact_check: Results",
     ":material/history: Saved scans", ":material/settings: Settings"])


# Settings tab. This is drawn first so the key and model are set before a scan uses them.
with settings_tab:
    st.subheader("Settings", anchor=False)
    with st.container(border=True):
        st.markdown("**AWS connection**")
        st.caption("CloudGuardian uses the credentials from 'aws configure' (or AWS_PROFILE). "
                   "It only reads settings.")
        if st.button("Check connection", icon=":material/refresh:"):
            checks = check_connection()
            st.session_state.connection_checks = checks
            if checks[0][1]:
                # check_aws_credentials ends with "(account 123456789012)."
                st.session_state.aws_status = (True, checks[0][2].rsplit(" ", 1)[-1].strip(").").strip())
            else:
                st.session_state.aws_status = (False, None)
            st.rerun()
        aws = st.session_state.get("aws_status")
        for name, ok, message in st.session_state.get("connection_checks", []):
            if aws and aws[1]:
                # same short account number as the header
                message = message.replace(aws[1], short_account(aws[1]))
            if ok:
                st.success(message, icon=":material/check_circle:")
            else:
                st.error(message, icon=":material/error:")

    with st.container(border=True):
        st.markdown("**AI explanations**")
        st.text_input("Anthropic API key", type="password", key="api_key")
        st.checkbox("Remember this key on this computer", key="remember")
        # unticking it deletes the saved key
        if not st.session_state.remember:
            client.forget_key()
        elif st.session_state.api_key and st.session_state.api_key != client.saved_key():
            client.save_key(st.session_state.api_key)

        st.selectbox("Model", list(MODELS), key="model")
        if st.session_state.api_key and st.session_state.remember:
            st.caption("Key saved on this computer (not in the repo). Untick the box to delete it.")
        elif st.session_state.api_key:
            st.caption("Using the key you pasted. It's gone when you close the page.")
        elif os.environ.get("ANTHROPIC_API_KEY"):
            st.caption("Anthropic API key found.")
        else:
            st.caption("No Anthropic API key. Paste one above or set ANTHROPIC_API_KEY.")


# Scan tab
def run_requested_scan(bar):
    """Runs the scan that Start scan asked for and updates the progress bar."""
    request = st.session_state.get("scan_request")
    runner = getattr(coordinator, "run_scan", None)
    if request is None or runner is None:
        # nothing to run (or the coordinator isn't written yet)
        st.session_state.progress = scan_progress.idle()
        st.session_state.scan_notice = ("info", "Scanning isn't hooked up yet.")
        st.session_state.scan_request = None
        st.rerun()

    def on_progress(done, total, message):
        st.session_state.progress = scan_progress.update(st.session_state.progress, done, total, message)
        bar.progress(scan_progress.fraction(st.session_state.progress), text=message)

    try:
        scan = runner(request["services"], request["rules"], on_progress)
    except Exception as error:
        # only the error type is shown, in case the message has account details
        st.session_state.progress = scan_progress.finish(st.session_state.progress, False)
        # test_connection turns AWS errors into one safe sentence (no secrets in it)
        hint = ""
        if isinstance(error, (BotoCoreError, ClientError)):
            hint = " " + test_connection._aws_error_message(error)
        st.session_state.scan_notice = (
            "error", "The scan stopped (" + type(error).__name__ + ")." + hint
            + " Nothing in AWS was changed.")
    else:
        st.session_state.progress = scan_progress.finish(st.session_state.progress, True)
        st.session_state.scan_notice = ("success", "Scan finished. See the Results tab.")
        st.session_state.scan = scan
        # a failed save still leaves the results on the page
        saved, error = db.save_scan(scan)
        if not saved:
            st.session_state.scan_notice = ("warning", "Scan finished but couldn't be saved: " + error["message"])
        elif st.session_state.explain and scan["findings"]:
            # explanations are saved on their own so a failure here can't touch the scan
            bar.progress(1.0, text="Getting explanations for the findings...")
            # no pasted key means explain_scan uses ANTHROPIC_API_KEY instead
            model = MODELS[st.session_state.model]
            scan["explanations"] = client.explain_scan(scan, st.session_state.api_key, model)
            db.save_explanations(scan["metadata"]["scan_id"], scan["explanations"])
            missing = 0
            for explanation in scan["explanations"]:
                if explanation["explanation_status"] == "unavailable":
                    missing += 1
            if missing > 0:
                st.session_state.scan_notice = (
                    "warning", "Scan finished, but " + str(missing) + " finding(s) have no explanation. "
                    "The rule results are still correct.")
    st.session_state.scan_request = None
    st.rerun()


with scan_tab:
    if "progress" not in st.session_state:
        st.session_state.progress = scan_progress.idle()
    progress = st.session_state.progress
    # Everything on this tab is locked while a scan runs. Changing a checkbox
    # would rerun the script and restart the scan.
    running = not scan_progress.can_start(progress)

    st.subheader("Start a scan", anchor=False)
    st.caption("CloudGuardian only reads your settings. It never changes anything in your account.")

    selected_services = []
    selected_rules = []
    with st.container(border=True):
        st.markdown("**What to check**")
        columns = st.columns(2)
        for service, column in zip(RULES, columns):
            with column.container(border=True):
                if st.checkbox("**" + service + "**", value=True, key="service_" + service, disabled=running):
                    selected_services.append(service)

        # the rules use the boxes' saved values, so the count is right before they're drawn
        chosen = 0
        for service in RULES:
            if st.session_state.get("service_" + service, True):
                for rule_id in RULES[service]:
                    if st.session_state.get(rule_id, True):
                        chosen += 1
        with st.expander("Choose specific checks (optional) · " + str(chosen) + " of 10 selected"):
            rule_columns = st.columns(2)
            for service, column in zip(RULES, rule_columns):
                with column:
                    for rule_id in RULES[service]:
                        # a check can't run if its service is off
                        if st.checkbox(RULES[service][rule_id], value=True, key=rule_id,
                                       disabled=running or service not in selected_services):
                            if service in selected_services:
                                selected_rules.append(rule_id)

    with st.container(border=True):
        text_col, toggle_col = st.columns([5, 1], vertical_alignment="center")
        text_col.markdown("**AI explanations**")
        text_col.caption("Explain each finding and suggest fix steps · Model: " + st.session_state.model
                         + " (change it in Settings)")
        toggle_col.toggle("AI explanations", key="explain", disabled=running, label_visibility="collapsed")

    start_clicked = st.button("Start scan", type="primary", icon=":material/play_arrow:",
                              disabled=running, width="stretch")
    bar = st.progress(scan_progress.fraction(progress), text=scan_progress.text(progress))
    # messages are kept in session_state because the page reruns right after a scan ends
    notice = st.session_state.get("scan_notice")
    if notice:
        getattr(st, notice[0])(notice[1])

    if start_clicked and scan_progress.can_start(progress):
        if len(selected_services) == 0 or len(selected_rules) == 0:
            st.warning("Pick at least one service and one check.")
        else:
            st.session_state.progress = scan_progress.start()
            st.session_state.scan_notice = None
            st.session_state.scan_request = {"services": selected_services, "rules": selected_rules}
            # rerun so the button and checkboxes are drawn locked before the scan starts
            st.rerun()
    elif running:
        run_requested_scan(bar)


# Saved scans tab. This is above the Results tab on purpose so that a scan
# opened here shows up in Results on the same run.
with saved_tab:
    st.subheader("Saved scans", anchor=False)
    st.caption("Saved on this computer only. Opening a saved scan doesn't contact AWS or the AI.")
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
                "Account": short_account(scan["account_id"]),
                "Services": format_services(scan),
                "Status": scan["scan_status"],
                "Coverage": scan["coverage_status"],
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    pick_col, open_col, delete_col = st.columns([3, 1, 1], vertical_alignment="bottom")
    chosen = pick_col.selectbox("Scan", saved_scans, format_func=scan_label, placeholder="Nothing saved")

    # only reads from the database, no AWS or AI calls
    if open_col.button("Open", type="primary", disabled=chosen is None, width="stretch"):
        scan, error = db.load_scan(chosen["scan_id"])
        if error:
            st.error("Couldn't open that scan: " + error["message"])
        else:
            st.session_state.scan = scan
            st.success("Opened. See the Results tab.")

    if delete_col.button("Delete", disabled=chosen is None, width="stretch"):
        confirm_delete(chosen["scan_id"])


# Results tab
with results_tab:
    scan = st.session_state.get("scan")

    title_col, report_col = st.columns([3, 1], vertical_alignment="bottom")
    title_col.subheader("Scan results", anchor=False)
    # the report for whatever scan is open, new or saved (E-4 S-10)
    if scan is None:
        title_col.caption("No scan open. Run a scan, or open one from Saved scans.")
        report_col.download_button("Download report", data="", file_name="cloudguardian-report.html",
                                   icon=":material/download:", disabled=True, width="stretch")
    else:
        title_col.caption("Account " + short_account(scan["metadata"]["account_id"]) + " · "
                          + format_time(scan["metadata"]) + " · " + format_services(scan["metadata"])
                          + " · " + str(len(scan["checks"])) + " checks")
        report_col.download_button("Download report", data=html_report.build_report(scan),
                                   file_name=html_report.report_file_name(scan), mime="text/html",
                                   icon=":material/download:", type="primary", width="stretch")

    if scan is not None:
        # the counts always cover every finding, whatever the filters below show
        counts = count_results(scan)
        with st.container(border=True):
            total = len(scan["checks"])
            st.markdown("**" + str(counts["pass"]) + " of " + str(total) + " checks passed**")
            st.progress(counts["pass"] / total if total else 0.0)
            boxes = st.columns(5)
            boxes[0].metric(":red[High]", counts["High"], border=True)
            boxes[1].metric(":orange[Medium]", counts["Medium"], border=True)
            boxes[2].metric(":blue[Low]", counts["Low"], border=True)
            boxes[3].metric(":green[Passed]", counts["pass"], border=True)
            boxes[4].metric(":yellow[Couldn't check]", counts["incomplete"], border=True)

        if counts["incomplete"]:
            st.warning("**" + str(counts["incomplete"]) + " check(s) couldn't run.** They are not counted "
                       "as passed. See \"Checks that couldn't run, and errors\" below.",
                       icon=":material/warning:")

    heading_col, filter_col = st.columns([1, 2], vertical_alignment="center")
    # sort findings High -> Medium -> Low
    findings = []
    if scan is not None:
        for severity in ["High", "Medium", "Low"]:
            for finding in scan["findings"]:
                if finding["severity"] == severity:
                    findings.append(finding)
    # service and severity filters (E-4 S-7-2). They only change the list below
    with filter_col:
        shown = st.pills("Show", finding_details.FILTERS, selection_mode="multi",
                         default=finding_details.FILTERS, label_visibility="collapsed", key="filters")
    if scan is not None:
        findings = finding_details.filter_findings(scan, findings, shown)
    heading_col.markdown("#### Findings (" + str(len(findings)) + ")")

    if scan is not None:
        if len(scan["findings"]) == 0:
            st.write("The selected checks found no issues.")
        elif len(findings) == 0:
            st.write("No findings match the filters.")

    # each finding opens to show its details and the AI explanation (E-4 S-7-3).
    # the first one starts open
    for number, finding in enumerate(findings):
        show_finding(scan, finding, expanded=number == 0)

    if scan is not None:
        with st.expander("Checks that couldn't run, and errors"):
            incomplete_rows = []
            error_rows = []
            for check in scan["checks"]:
                if check["status"] == "incomplete":
                    incomplete_rows.append({
                        "Service": check["service"],
                        "Resource": check["resource_id"],
                        "Check": rule_name(check["rule_id"]),
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
