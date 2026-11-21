# AWS Misconfiguration Scanner

CloudGuardian is our senior project for finding security issues in AWS settings. It checks S3 and IAM against ten rules and shows the results in a local Streamlit app. We use AI to explain findings and suggest fixes. The scanner reads settings but does not change anything in AWS.

## What it does

- Scan S3, IAM, or both in one AWS account
- Show passed and incomplete checks, findings, and severity
- Use the Anthropic API to explain findings
- Save scans locally and download an HTML report

## Setup

Running:

Install the packages:

   ```bash
   pip install -r requirements.txt
   ```

## Running the app

Start the app from the project folder:

```bash
streamlit run app.py
```

Open http://localhost:8501, pick S3, IAM, or both, and start a scan. You can also pick specific checks. Results shows the findings, and Saved scans lets you open past scans.

Settings has connection checks, setup help, model selection, dark mode, and button colors. The colors reset when the app restarts.

## AI explanations

Turn on AI explanations on the Scan tab and pick a model in Settings. The app sends finding info to Anthropic and shows an explanation and fix steps for each finding. The rules decide the results and severity.

Before sending findings, we remove fields named with `secret`, `token`, or `credential` and mask full AWS access key IDs. This does not catch every kind of sensitive information. If a request fails or there is no key, the finding still shows without an explanation. 

A key pasted into Settings stays in memory unless you check "Remember this key on this computer". That saves it in `api_key.txt` beside the database. Uncheck it to delete the file. This doesn't go anywhere except your computer.

## Saved scans and reports

The app saves scans in a local SQLite database:

- Windows: `%LOCALAPPDATA%\CloudGuardian\cloudguardian.db`

Set `CLOUDGUARDIAN_DB` to use a different location. The database holds scan results and is left out of Git. Close the app before backing it up.

Use the service and severity filters on Results to change which findings show. The counts and report still include everything. Download report gives you an HTML file with the scan details, findings, explanations, and incomplete checks.

## Tests

Run the tests from the project folder:

```bash
python -m unittest discover tests
```

The live tests need a real AWS test account and an Anthropic API key. They are skipped unless you set `CLOUDGUARDIAN_LIVE=1`.

## Team

- Ajay Singh, project manager, front-end, S3/IAM, HTML report
- Martin Perez, S3/IAM collectors
- Zach Kidwell, front-end design, presentations, AI integration
