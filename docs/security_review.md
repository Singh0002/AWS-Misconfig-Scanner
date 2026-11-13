# Credential protection review (E-6 S-11)

Reviewed 11/13/2026 against `main` plus the changes in this branch.

## How credentials are loaded (E-6 S-11-2)

**AWS credentials**
- The app never asks for AWS keys and has no place to type them.
- `test_connection.make_session()` makes a normal boto3 session, so the keys come from
  the user's own setup: `aws configure` (the `~/.aws` files), `AWS_PROFILE`, or the
  standard AWS environment variables.
- The session is only used to make read calls. Keys are never copied into a variable,
  the database, the report, the page or a log.
- The page shows only the last 4 digits of the account number.
- Result: **pass**. Nothing to fix.

**Anthropic API key**
- Pasted on the Settings tab in a password box, or read from `ANTHROPIC_API_KEY`.
- A pasted key stays in the page's memory and is gone when the page closes.
- "Remember this key" saves it in `api_key.txt` in the same folder as the database,
  which is outside the repo. On Ubuntu the file is set so only the user can read it.
  Unticking the box deletes the file.
- `.gitignore` leaves out `api_key.txt`, the database files and `.streamlit/secrets.toml`.
- Result: **pass**, with one thing to know: on Windows the file is protected only by the
  user's own account folder, not by extra file permissions.

## Checks

| Task | Check | How it was checked | Result |
|---|---|---|---|
| S-11-1 | The scanner only makes read calls | `test_collectors.ReadOnlyTests`, `test_integration.WorkflowTests`: the fake AWS rejects every call that isn't `get_` or `list_` | Pass (automated) |
| S-11-1 | Same, on the real account | `Scripts/readonly.py` reads CloudTrail after a scan | Not run yet |
| S-11-2 | Credential loading | The review above | Pass |
| S-11-3 | No secrets in Git | `.gitignore` covers the key file and database; searched the repo for `sk-ant-`, `AKIA` and `aws_secret_access_key` (only fake test values and help text) | Pass |
| S-11-3 | No secrets in saved records | `test_storage.test_dummy_credentials_never_reach_the_database` | Pass (automated) |
| S-11-4 | No secrets in AI requests | `test_ai.RequestTests`: a fake secret key, session token, whole access key ID, API key and account ID never reach the request | Pass (automated) |
| S-11-4 | No secrets in the report | `test_reporting.ReportSafetyTests` | Pass (automated) |
| S-11-4 | No secrets in error messages | `test_coordinator.SetupCheckTests` and `SettingsPageTests`: AWS error text is never passed through, only the error code or type | Pass (automated) |
| S-11-4 | HTTPS for AWS and Anthropic | `test_integration.test_aws_and_anthropic_requests_use_https` | Pass (automated) |
| S-11-5 | Tests with fake credentials | All of the above use the fake secrets in `tests/fakes.py` | Pass, 144 tests |
| S-11-5 | Search after a real scan | Search the database, report, page and terminal for the real keys | Not run yet |

## Still to do on the real account

1. Run a scan with the read-only scanner user.
2. Run `Scripts/readonly.py` and record the result in `docs/test_record.md`.
3. Search `cloudguardian.db`, the downloaded report and the terminal output for the AWS
   access key ID and the Anthropic key. None should be found.
