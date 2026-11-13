# CloudGuardian test record (E-8 S-16-2)

What was tested, on what, and the result. Rows marked **Not run yet** need the real AWS
test account or a person at a computer. Fill in the date, who ran it and what happened.

## 1. Automated tests

| Date | Computer | Python | Command | Result |
|---|---|---|---|---|
| 11/13/2026 | Ubuntu 24.04 | 3.13.16 | `python -m unittest discover tests` | 144 tests: 142 passed, 2 skipped (the live tests) |

The 2 skipped tests are in `tests/test_live.py`. They need the real test account and an
Anthropic key (`CLOUDGUARDIAN_LIVE=1`).

## 2. Clean startup (E-8 S-14-2)

Steps: clone the repo into an empty folder, make a new virtual environment,
`pip install -r requirements.txt`, run the tests, run `python test_connection.py`,
then `streamlit run app.py` and open the page.

| Date | Computer | Python | Install | Tests | App starts | Notes |
|---|---|---|---|---|---|---|
| 11/13/2026 | Ubuntu 24.04 | 3.13.16 | OK | 144 OK (2 skipped) | Yes, the page loads | With no AWS credentials, `test_connection.py` gives a clear message and no keys |
| Not run yet | Windows 11 | | | | | Run from a fresh clone, not the folder used for development |

## 3. Repeated or slow requests (E-6 S-13-3, S-13-4)

Checked with the fake AWS account, which records every call. Scan of 2 buckets and
2 users, both services:

| Call | Times | Expected |
|---|---|---|
| `get_caller_identity`, `list_buckets`, `list_users` | 1 each | Once per scan |
| `get_account_public_access_block`, `get_account_summary`, `get_account_password_policy` | 1 each | Once per scan |
| `get_bucket_acl`, `get_public_access_block`, `get_bucket_versioning`, `get_bucket_policy` | 2 each | Once per bucket |
| `list_user_policies`, `list_attached_user_policies`, `list_mfa_devices`, `list_access_keys` | 2 each | Once per user |

**Found:** a managed policy attached to several users was downloaded again for every
user (`get_policy` and `get_policy_version`).
**Fixed:** `collectors/iam.py` now downloads each managed policy once per scan. A failed
download is not remembered, so it's tried again for the next user.
**Tests:** `test_collectors.RepeatedRequestTests` (3 tests).

Temporary AWS errors are retried up to 3 times with a 10 second connect limit and a
30 second read limit (E-6 S-12-2, `test_coordinator.RetryTests`).

## 4. Scan timing on the real account (E-6 S-13-1, S-13-2, S-13-5)

Target: 10 buckets and 10 users in under 5 minutes, not counting the AI.
Run `Scripts/Timing.py --runs 3 --ai` with the read-only scanner profile.

| Date | Computer and network | Buckets / users | S3 time | IAM time | Whole scan | AI time | Under 5 minutes? |
|---|---|---|---|---|---|---|---|
| Not run yet | | | | | | | |

## 5. System test on the real account (E-8 S-14, FR-DET)

Set up the account with `Scripts/CreateTestAccount.py create`, scan it, and compare.

| What is set up | Rule | Expected | What happened | Pass/Fail |
|---|---|---|---|---|
| Bucket whose ACL lets All Users read | Public ACL grants | Fail (High) | | |
| Bucket policy that allows `*` with no condition | Wildcard principal | Fail (High) | | |
| Bucket with versioning suspended | Versioning | Fail (Medium) | | |
| Bucket with no bucket policy | HTTPS only | Fail (Medium) | | |
| 6 buckets with everything secure | All five S3 rules | Pass | | |
| User with AdministratorAccess | Admin wildcards | Fail (High) | | |
| Users with no MFA device | User MFA | Fail (High) | | |
| Root account with MFA on | Root MFA | Pass | | |
| Password policy with 8 characters (`password weak`) | Password policy | Fail (Medium) | | |
| Password policy with 14 characters (`password strong`) | Password policy | Pass | | |
| Access key unused for over 90 days | Unused access keys | Fail (Medium), or note that a new account can't have one | | |
| One permission taken from the scanner user | The checks that need it | Incomplete, not Pass | | |

## 6. Read-only and secrets on the real account (E-6 S-11-1, S-11-5)

| Check | How | Date | Result |
|---|---|---|---|
| The scanner only made read calls | `Scripts/readonly.py --user <scanner user> --minutes 60` a few minutes after a scan | Not run yet | |
| No AWS key or Anthropic key in the database, report, page or terminal | Search each one for the real key values | Not run yet | |
| Nothing in the test account changed | Compare the account before and after the scan | Not run yet | |

## 7. Acceptance test (E-8 S-14-3, S-14-4)

One teammate (or classmate) uses only the README. The others watch and take notes.

| Step | Worked without help? | Notes |
|---|---|---|
| 1. Set up the app from the README | Not run yet | |
| 2. Run `python test_connection.py` | | |
| 3. Start the app, pick the services, run a scan | | |
| 4. Read the findings and open one with its explanation | | |
| 5. Download the report and open it | | |
| 6. Close the app, open it again, open the saved scan | | |
| 7. Run a second scan and check it's saved separately | | |
| 8. Remove the API key and check the message makes sense | | |

Defects found and fixes (E-8 S-14-4):

| Defect | Fix | Retested |
|---|---|---|
| | | |
