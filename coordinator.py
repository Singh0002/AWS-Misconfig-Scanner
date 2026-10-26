"""Runs a scan: the collectors first, then the rules (E-1 S-2-3).

app.py calls run_scan(selected_services, selected_rules, on_progress) and
gets back the finished scan from results.new_scan(). Every AWS call here is
read-only.
"""

from botocore.exceptions import BotoCoreError, ClientError

import results
from collectors import iam, s3
from collectors.common import read_setting
from detection import findings
from test_connection import make_session


def run_scan(selected_services, selected_rules, on_progress, session=None):
    if session is None:
        session = make_session()
    # this fails right away if the credentials are missing or wrong
    account_id = session.client("sts").get_caller_identity()["Account"]
    scan = results.new_scan(selected_services, account_id)
    total = len(selected_services)

    if "S3" in selected_services:
        on_progress(0, total, "Scanning S3 buckets...")
        # the account-wide Block Public Access setting counts for every bucket
        try:
            account_block = session.client("s3control").get_public_access_block(
                AccountId=account_id)["PublicAccessBlockConfiguration"]
        except (BotoCoreError, ClientError):
            # not set or not readable, so only the bucket's own setting counts.
            # that can only make the rule stricter, never a false pass
            account_block = None
        findings.check_s3(scan, s3.collect_s3(session), selected_rules, account_block)

    if "IAM" in selected_services:
        on_progress(total - 1, total, "Scanning IAM users...")
        # root MFA comes from the account summary, not from a user
        status, summary, code = read_setting(session.client("iam").get_account_summary)
        findings.check_iam(scan, iam.collect_iam(session), selected_rules, summary, code)

    scan["metadata"]["scan_status"] = "completed"
    return scan
