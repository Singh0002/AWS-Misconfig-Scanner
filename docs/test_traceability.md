# CloudGuardian test coverage

This maps our requirements to the tests that check them. All the tests use the fake AWS account and fake AI in `tests/fakes.py`.
All the tests are complete, some of which were completed informally with the help of friends (acceptance testing).

Run them from the project folder:

python -m unittest discover tests

As of 11/8/2026: 138 tests, all passing. The 2 live tests are skipped unless `CLOUDGUARDIAN_LIVE=1` is set, because they need our real AWS test account and an Anthropic key.

## Tested

| Area | What we check | Test file | Tests |
|---|---|---|---|
| Detection | All 10 rules, tricky policies, incomplete checks, findings | test_detection.py | 34 |
| Collectors | Reads every setting and page, tells "not set" from "couldn't read", read-only calls | test_collectors.py | 16 |
| App | Scan options, setup errors, Results tab, Settings tab | test_coordinator.py | 32 |
| AI | Only finding data is sent, secrets removed, bad replies handled | test_ai.py | 18 |
| Storage | Save, open, list and delete scans, no credentials stored | test_storage.py | 14 |
| Report | Has everything from the scan, HTML is escaped, no secrets | test_reporting.py | 10 |
| Full workflow | A scan from start to report, plus AI outages and failed saves | test_integration.py | 12 |
| Live | Real AWS account and Anthropic API | test_live.py | 2 (skipped) |
