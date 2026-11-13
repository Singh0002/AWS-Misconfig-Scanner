# Final demo steps (E-8 S-16-6)

For the final presentation on 11/16/2026. About 8 to 10 minutes of live demo.

## Before the demo

- [ ] Pull the latest `main` and run `python -m unittest discover tests` (should say OK).
- [ ] Set up the AWS test account with the known problems (`Scripts/CreateTestAccount.py create`).
- [ ] Run `python test_connection.py --ai-call` and check every line says PASS.
- [ ] Run one scan ahead of time, so there is a saved scan to open if the network is slow.
- [ ] Download one report ahead of time as a backup.
- [ ] Use the read-only scanner user, never an admin user.
- [ ] Close anything on screen that shows keys. The app only shows the last 4 digits of the account.
- [ ] Make the browser text bigger (Ctrl and +) so the room can read it.

## Demo script

| # | Do | Say |
|---|---|---|
| 1 | Run `streamlit run app.py` | "CloudGuardian runs on your own computer. Nothing is hosted." |
| 2 | Settings tab, press Check connection | "It checks the AWS credentials and read access to S3 and IAM. It only reads, and it never shows a key." |
| 3 | Scan tab: point at S3 and IAM, open Choose specific checks | "You pick the services. All 10 checks are on, and you can turn some off." |
| 4 | Press Start scan | "It reads the settings, runs our rules, saves the scan, and then asks the AI to explain the findings." |
| 5 | Results tab: the bar and the count boxes | "This shows how many checks passed and how many problems there are by severity. A check we couldn't run is counted separately. It never counts as passed." |
| 6 | Open the public bucket finding | "This is what our rule found, why it matters, and how to fix it. The rule decides the result. The AI only explains it." |
| 7 | Use the S3, IAM and severity filters | "The filters change the list but not the counts." |
| 8 | Press Download report and open the file | "One HTML file with everything. It opens offline." |
| 9 | Saved scans tab, open an older scan | "Opening a saved scan doesn't contact AWS or the AI." |
| 10 | Settings: turn on dark mode (optional) | "Colors can be changed in Settings." |

## If something goes wrong

| Problem | What to do |
|---|---|
| No internet or AWS is slow | Open the saved scan from Saved scans and continue from step 5 |
| The AI is slow or fails | Show that the findings are still there and the page says the explanation is unavailable. That's the designed behavior |
| The app won't start | Show the downloaded report and the screenshots in the slides |

## Who presents what (proposed, confirm as a team)

| Part | Presenter |
|---|---|
| Problem, goals and the 10 rules | Ajay |
| Collectors, coordinator and the real-account test results | Martin |
| AI explanations, storage, security checks and hallucination testing | Zach |
| Live demo | (decide: one person drives, one talks) |
| Lessons learned and questions | Everyone |

## Lessons learned (draft, edit as a team)

- Agreeing on one result format early (`results.py`) let three people build separate
  parts that fit together.
- A field-name mismatch between the IAM collector and the rules broke IAM scans in
  Sprint 3. Integration tests that run the real parts together now catch that kind of bug.
- "Couldn't check" has to be its own result. Treating an unreadable setting as a pass
  would tell users they're safe when we never looked.
- Testing against a fake AWS account made tests fast, free and repeatable, but it can't
  replace a run on a real account.
- Saving the scan before calling the AI means an AI problem never loses results.
- Requirement IDs drifted between documents. One list, checked every sprint, would have
  saved time.
- Short sprints and a weekly update showed slipped tasks early enough to move them.

## Rehearsal

- [ ] One full run-through with a timer, on the computer that will be used.
- [ ] One run-through of the backup plan with the network turned off.
