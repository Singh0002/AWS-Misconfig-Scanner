# AWS Misconfiguration Scanner

CloudGuardian is our senior project for finding security issues in AWS settings. It checks S3 and IAM against ten rules and shows the results in a local Streamlit app. We use AI to explain findings and suggest fixes. The scanner reads settings but does not change anything in AWS.

## What it does

- Scan S3, IAM, or both in one AWS account
- Show passed and incomplete checks, findings, and severity
- Use the Anthropic API to explain findings
- Save scans locally and download an HTML report

## Setup

1. Extract the ZIP and open the extracted folder in a terminal. You need Python 3.12.

2. Make a virtual environment:

   ```bash
   python -m venv .venv
   ```

   On Windows PowerShell, turn it on with:

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

   On Windows Command Prompt, use `.venv\Scripts\activate.bat` instead.
   On macOS or Linux, use `source .venv/bin/activate`.

3. Install the packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Set up AWS credentials for the account you want to scan. Use a read-only
   user with the `SecurityAudit` policy. Install the AWS CLI, run `aws configure`,
   and enter the access key, secret key, and region. Do not share your keys.

5. For AI explanations, paste an Anthropic API key into Settings after you start
   the app. The scan works without it, but it will not have AI explanations.

Settings has help for AWS and the Anthropic key. You can also run
`python test_connection.py` to check your setup.

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

A key pasted into Settings stays in memory unless you check "Remember this key on this computer". That saves it in `api_key.txt` beside the database. Uncheck it to delete the file
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
