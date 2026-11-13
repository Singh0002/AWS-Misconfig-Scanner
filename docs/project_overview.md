# CloudGuardian project overview and rule documentation (E-8 S-16-1, E-8 S-16-3)

## What CloudGuardian is

CloudGuardian is a local app that checks one AWS account for 10 common S3 and IAM
misconfigurations. It runs on the user's own computer with Streamlit. It only reads
settings from AWS and never changes anything. For each problem it finds, it can ask an
AI model for a short explanation and fix steps. Scans are saved on the computer and can
be downloaded as one HTML report.

Team: Ajay Singh (project manager, detection rules, interface, report), Martin Perez
(S3 and IAM collectors, scan coordinator, test account), Zach Kidwell (AI explanations,
SQLite storage, dashboard, tests).

## How a scan works

1. **Start.** The user picks S3, IAM or both on the Scan tab and presses Start scan.
   `coordinator.run_scan` checks the AWS credentials first by asking AWS which account
   it is. If that fails, the scan stops with a clear message.
2. **Collect.** `collectors/s3.py` and `collectors/iam.py` read the settings. Every
   setting comes back as *available* (AWS answered), *missing* (AWS says it isn't set)
   or *failed* (we couldn't read it).
3. **Check.** `detection/findings.py` runs the rules in `detection/s3_rules.py` and
   `detection/iam_rules.py`. Each check ends as **pass**, **fail** or **incomplete**.
   A setting we couldn't read is always incomplete, never a pass.
4. **Save.** `storage/db.py` saves the scan to a local SQLite file in one transaction.
5. **Explain.** If AI explanations are on, `ai/client.py` sends the failed checks to
   Anthropic and `ai/formatter.py` checks the reply. This happens after the save, so an
   AI problem can't lose the results.
6. **Show.** The Results tab shows the counts and each finding. `report/html_report.py`
   builds the downloadable report.

## The 10 rules

Each rule runs once per bucket or user, except the two account rules, which run once
per scan. Every rule gives **incomplete** when the setting it needs couldn't be read.

### S3 rules (`detection/s3_rules.py`)

| # | Rule | What it reads | Passes when | Fails when | Severity |
|---|---|---|---|---|---|
| 1 | Public ACL grants (`s3_public_acl`) | Bucket ACL | No grant to the All Users or Authenticated Users groups | Any grant to one of those groups | High |
| 2 | Block Public Access (`s3_block_public_access`) | Bucket and account Block Public Access | All four settings are on, for the bucket or for the whole account | Any of the four is off, or none is set | High |
| 3 | Wildcard principal (`s3_wildcard_principal`) | Bucket policy | No Allow statement for everyone, or it has a condition | An Allow statement for `*` (or a NotPrincipal) with no condition | High |
| 4 | Versioning (`s3_versioning`) | Bucket versioning | Status is Enabled | Suspended or never turned on | Medium |
| 5 | HTTPS only (`s3_https_only`) | Bucket policy | A Deny statement blocks requests that aren't HTTPS for the whole bucket | No policy, or no statement that blocks plain HTTP | Medium |

The four Block Public Access settings are BlockPublicAcls, IgnorePublicAcls,
BlockPublicPolicy and RestrictPublicBuckets.

### IAM rules (`detection/iam_rules.py`)

| # | Rule | What it reads | Passes when | Fails when | Severity |
|---|---|---|---|---|---|
| 6 | Admin wildcards (`iam_admin_wildcard`) | The user's inline and attached policies | No statement allows every action on every resource | A statement allows `*` on `*` with no condition | High |
| 7 | User MFA (`iam_user_mfa`) | The user's MFA devices | At least one device | No device | High |
| 8 | Root MFA (`iam_root_mfa`) | Account summary | Root has MFA | Root has no MFA | High |
| 9 | Password policy (`iam_password_policy`) | Account password policy | At least 14 characters and uppercase, lowercase, numbers and symbols all required | Shorter than 14, a character type not required, or no policy | Medium |
| 10 | Unused access keys (`iam_unused_access_key`) | The user's access keys | Every active key was used in the last 90 days | An active key unused for more than 90 days | Medium |

Notes:
- Rule 6 passes a wildcard statement that has a condition, but lists it in the evidence.
- Rule 10 skips inactive keys. A key that was never used counts from the day it was made.
  A key with no dates is incomplete.
- Only the last 4 characters of an access key ID are ever kept.
- Policies a user gets through a group are not collected in this version.

## AI explanations (`ai/client.py`, `ai/formatter.py`)

- **What is sent:** only the finding ID, service, resource name, rule, issue, severity and
  evidence. Fields that look like secrets are dropped and whole access key IDs are blanked.
- **How:** 5 findings per request, a 30 second limit, one retry, and a fixed reply format.
  The model gets no tools, so it can only reply with text.
- **What comes back:** 2 or 3 sentences on the risk and 2 to 4 fix steps for each finding.
- **When it fails:** the finding says the explanation is unavailable. The rule result and
  severity never change. The error type is saved with the scan.
- **The key:** pasted on the Settings tab or read from `ANTHROPIC_API_KEY`. "Remember this
  key" saves it in `api_key.txt` next to the database, outside the repo.
- **Accuracy:** we tested 50 explanations and found no hallucinations, but it can still
  happen, so the app tells users to check the steps before changing anything.

## Storage (`storage/db.py`)

One SQLite file, `cloudguardian.db`, made the first time the app runs
(`%LOCALAPPDATA%\CloudGuardian` on Windows, `~/.local/share/cloudguardian` on Ubuntu).

| Table | Holds |
|---|---|
| `scans` | One row per scan: account, time, services, status and coverage |
| `checks` | Every check: resource, rule, status, evidence and reason |
| `findings` | One row per failed check: issue and severity |
| `explanations` | The AI explanation and fix steps for a finding |
| `scan_errors` | Collection, AI and storage errors (error codes only) |

A scan is saved in one transaction, so it's all or nothing. Deleting a scan deletes its
rows in every table. No AWS keys or API keys are stored.

## HTML report (`report/html_report.py`)

`build_report(scan)` returns one HTML page with the scan details, the findings (most
severe first), the explanations and fix steps, and the incomplete checks and errors.
All text is escaped, and the page has no scripts and no outside links, so it opens
offline. The file name has the scan date and time.

## Requirements and tests

`docs/test_traceability.md` maps each requirement to the tests that check it.
`docs/test_record.md` holds the test results, and `docs/security_review.md` the
credential review.
