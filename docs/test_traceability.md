# CloudGuardian requirements-to-tests traceability (E-8 S-15-3)

Maps each requirement to the automated tests that check it. All tests are in
`tests/` and run with:

```
python -m unittest discover tests
```

Status as of 10/31/2026: **174 tests, all passing** (1 skipped when `moto` isn't installed).

The requirement IDs come from the requirement list in our Agile planning document.
Check each ID against the final SRS before submitting.

## Covered by automated tests

| Requirement IDs | Requirement | Tests (file.Class) | Tests | Status |
|---|---|---|---|---|
| DETECT-1 to DETECT-7, FR-DET-1, DOM-4 | Flag S3 ACL grants to All Users or Authenticated Users | test_s3_rules.PublicAclTests, test_s3.PublicAccessTests | 5 + 4 | Pass |
| DETECT-1 to DETECT-7, FR-DET-1, DOM-4 | Flag Block Public Access that isn't fully on (bucket or account) | test_s3_rules.BlockPublicAccessTests | 5 | Pass |
| DETECT-1 to DETECT-7, FR-DET-1, DOM-4 | Flag bucket policies that allow any principal without a condition | test_s3_rules.WildcardPrincipalTests | 10 | Pass |
| DETECT-1 to DETECT-7, FR-DET-1, DOM-4 | Flag buckets with versioning suspended or never enabled | test_s3_rules.VersioningTests, test_findings.S3Tests | 5 + 3 | Pass |
| DETECT-1 to DETECT-7, FR-DET-1, DOM-4 | Flag bucket policies that don't enforce HTTPS | test_s3_rules.HttpsOnlyTests, test_findings.S3Tests | 9 + 3 | Pass |
| FR-IAM-1, FR-DET-2, DOM-4 | Flag policies that allow every action on every resource, considering conditions | test_iam_rules.AdminWildcardTests, test_findings.IamTests | 12 + 4 | Pass |
| FR-IAM-1, FR-DET-2, DOM-4 | Flag IAM users without MFA | test_iam_rules.UserMfaTests, test_findings.IamTests | 4 + 4 | Pass |
| FR-IAM-1, FR-DET-2, DOM-4 | Flag a root account without MFA | test_iam_rules.RootMfaTests, test_findings.IamTests | 4 + 4 | Pass |
| FR-IAM-1, FR-DET-2, DOM-4 | Flag a weak or missing password policy (13 vs 14 characters, each character type) | test_iam_rules.PasswordPolicyTests | 9 | Pass |
| FR-IAM-1, FR-DET-2, DOM-4 | Flag active keys unused for more than 90 days (89, 90 and 91 days; never-used keys) | test_iam_rules.UnusedAccessKeyTests | 12 | Pass |
| SCAN-4, SCAN-5, FR-S3-1, DOM-3 | Rules read the same data shapes real AWS returns | test_s3_rules.RealResponseShapeTests, test_iam_rules.RealResponseShapeTests | 2 | Pass |
| FR-DET-3, DETECT-3 to DETECT-7 | One shared result format with pass, fail and incomplete statuses and stable finding IDs | test_results.ResultFormatTests, test_findings.FindingsTests | 7 + 5 | Pass |
| NFR-SAFE-3, OUT-6 | Settings that can't be read are incomplete, never passed | the unreadable/not-collected tests in every rule class, test_findings.FindingsTests | 20+ | Pass |
| SCAN-1 to SCAN-3, FR-UI-1 | Pick S3, IAM or both and only the selected rules run; picking nothing shows a warning | test_scan_progress.TestScanTab, test_s3_rules.GoodBucketTests, test_iam_rules.CheckUserTests, test_findings.FindingsTests | 5 + 4 + 3 + 5 | Pass |
| SCAN-6, NFR-SEC-4, OUT-7 | Clear setup errors for missing, invalid or denied credentials, with no keys shown | test_setup_checks.TestAwsChecks, test_setup_checks.TestAiKeyCheck | 8 + 3 | Pass |
| FR-UI-1 | Progress bar, and only one scan at a time | test_scan_progress.TestProgressState, test_scan_progress.TestScanTab | 9 + 5 | Pass |
| FR-UI-2, OUT-2 to OUT-5, AI-5, AI-6 | Finding details and the AI explanation, with a clear message when the AI is missing or failed | test_finding_details.DetailsTests, ExplanationTests, ResultsTabTests | 4 + 6 + 3 | Pass |
| OUT-1, FR-REP-1 | Report shows the scan details and findings, most severe first | test_html_report.ScanDetailsTests, test_html_report.FindingsTests | 4 + 4 | Pass |
| NFR-SEC-1, FR-REP-1 | Text from AWS, the AI or the database can't add HTML to the report | test_html_report.EscapeTests, test_html_report.ReportEscapingTests | 3 + 3 | Pass |
| OUT-1 (course database outline) | Save, reopen, list and delete scans; a failed save saves nothing | test_storage.StorageSchemaTests, test_storage.SaveLoadTests | 6 + 9 | Pass |

## Not covered yet

| Requirement IDs | Requirement | Planned test | Owner | Sprint |
|---|---|---|---|---|
| AI-1 to AI-4, FR-AI-1, NFR-SEC-1 | AI client: timeout, limited retries, no credentials sent | Malformed, missing and failed AI responses (E-4 S-9-5) | Zach, Martin | 3 → 4 |
| FR-REP-1 | Downloading the report for current and saved scans | E-4 S-10-5 | Martin | 3 → 4 |
| NFR-SEC-1 to NFR-SEC-3 | No secrets in saved scans, logs, the UI or the AI request | E-5 S-8-5, E-6 S-11 credential-leak sweep | Martin, Zach | 4 |
| NFR-SAFE-1 | Every AWS call is read-only | Review of every Boto3 call (E-6 S-11) | Martin | 4 |
| NFR-PERF-1 | A scan of 10 buckets and 10 users finishes within 5 minutes | Timing on the test account (E-6 S-13) | Martin | 4 |
| All detection requirements | All 10 rules give the expected result on the real test account | System test on the test account (E-8 S-14) | Martin | 4 |
| Portability (6.4) | Installs and runs on Windows and Ubuntu | Clean install check (E-8 S-14, S-16) | Ajay, Martin | 4–5 |
| Acceptance | 2–3 classmates complete setup, scan, report and saved-scan review | User acceptance test (E-8 S-14) | Ajay | 4 |
