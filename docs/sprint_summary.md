# Sprint plans and reviews (E-8 S-16-4)

The plan comes from our Agile planning document. The reviews say what was delivered,
with the pull request that merged it. The backlog is on GitHub Issues.

## Stories and points

| Story | Description | Points | Sprint |
|---|---|---|---|
| E-7 S-1 | Local application setup | 5 | 1 |
| E-1 S-2 | Service selection and scanning | 5 | 1 |
| E-5 S-8 | Saved scan storage | 5 | 1 |
| E-2 S-3 | S3 public-access checks | 8 | 2 |
| E-2 S-4 | S3 versioning and HTTPS checks | 3 | 2 |
| E-3 S-5 | IAM permission and MFA checks | 8 | 2 |
| E-3 S-6 | IAM password and access key checks | 5 | 3 |
| E-4 S-7 | Scan results dashboard | 3 | 3 |
| E-4 S-9 | AI explanations | 5 | 3 |
| E-4 S-10 | HTML report download | 3 | 3 |
| E-8 S-15 | Test plan and presentation | 2 | 3 |
| E-6 S-11 | Credential protection | 3 | 4 |
| E-6 S-12 | Failure recovery | 8 | 4 |
| E-6 S-13 | Scan performance | 3 | 4 |
| E-8 S-14 | Acceptance and delivery | 5 | 4 and 5 |
| E-8 S-16 | Final documentation and demo | 3 | 5 |

## Sprint 1 (10/12 to 10/18)

**Goal:** start the local app, select services and rules, run a sample scan, reopen
saved sample results, and set up SQLite.

**Delivered**
- Streamlit page, the shared result format and SQLite storage with 22 tests (#1, 10/15).
- Project structure and the first IAM collector (#2, 10/15).
- Pinned packages, `test_connection.py` setup checks and scan progress (#3, 10/18).

**Carried over:** the Check connection button on the page (done in Sprint 4), the AWS
test account (E-7 S-1-6), and the SRS wording about SQLite (E-5 S-8-6).

## Sprint 2 (10/19 to 10/25)

**Goal:** run the S3 checks and the IAM permission and MFA checks on real settings,
including incomplete checks.

**Delivered**
- The 5 S3 rules and the first 3 IAM rules, with incomplete results (#8, 10/24).
- S3 and IAM collectors, the findings step and the scan hooked up to the page (#9, 10/25).

**Review:** scans worked end to end for S3. The IAM collector and the rules used
different field names, which was found and fixed in Sprint 3.

## Sprint 3 (10/26 to 11/1)

**Goal:** all ten checks, findings on the dashboard, AI explanations, the HTML report,
and the test plan ready for November 2.

**Delivered**
- Password policy and unused access key rules, the finding details panel and the report (#10, 10/31).
- AI explanations with the API key box and model choice (#11, 10/31).
- IAM collector field fix so rules 9 and 10 run in scans, the filters, the full report (#12, 10/31).
- Tests reorganized to follow section 5 of the design document (#13, 11/1).
- Test plan document and slides, presented 11/2.

**Review:** all 10 rules run in a scan. This was the heaviest sprint, as the plan expected.

## Sprint 4 (11/2 to 11/8)

**Goal:** verify the full workflow, credential protection, recovery and scan speed, fix
defects, run acceptance tests, and prepare the deployment package.

**Delivered**
- Interface redesign, a Settings tab and a working Check connection button (#14, 11/8).
- Setup help, dark mode, going straight to Results, and AI hallucination testing of
  50 explanations (#15, 11/9).
- Scripts to build the test account, time a scan and check read-only use (Martin's
  branch, not merged yet).

**Review:** the interface work was not in the plan but was needed for the acceptance
test and the demo. The checks that need the real AWS account (timing, read-only use,
the system test and the acceptance run) moved to Sprint 5.

## Sprint 5 (11/9 to 11/15)

**Goal:** a new user can install the final package on Windows and Ubuntu. Fix the
acceptance defects, finish the documentation and prepare the final demo.

**Delivered so far**
- AI errors are saved with the scan (E-6 S-12-3).
- Limited retries and time limits for AWS calls (E-6 S-12-2).
- Repeated-request review and fix: a shared policy is downloaded once (E-6 S-13-3, S-13-4).
- Credential review (`docs/security_review.md`, E-6 S-11).
- Project and rule documentation (`docs/project_overview.md`, E-8 S-16-1, S-16-3).
- Test record with the clean Ubuntu startup (`docs/test_record.md`, E-8 S-14-2, S-16-2).
- Demo steps and draft lessons learned (`docs/demo_steps.md`, E-8 S-16-6).

**Still open**
- Build the AWS test account and run the system test, timing and read-only checks.
- Clean startup on Windows from a fresh clone.
- The acceptance run, and fixing what it finds.
- Final slides and a rehearsal.

## Risks that came up

| Risk in the plan | What happened |
|---|---|
| Incorrect rule results | Edge-case tests were added for policies that look safe but aren't |
| AI failures | Handled as planned: findings stay and the explanation is marked unavailable |
| Limited time or owner overload | Sprint 3 was heavy; the filters and some tasks finished at the end of the sprint |
| AWS permissions and the test account | The test account was late, so real-account tests moved to Sprint 5 |
| Requirements disagree about storage | The SRS wording fix (E-5 S-8-6) still needs to be confirmed |
