# AWS Misconfiguration Scanner

CloudGuardian is our senior project for finding security issues in AWS settings. It checks S3 and IAM against ten rules and shows the results in a local Streamlit app. We use AI to explain findings and suggest fixes. The scanner reads settings but does not change anything in AWS.

## What it does

- Scan S3, IAM, or both in one AWS account.
- Show passed and incomplete checks, findings, and severity.
- Use the Anthropic API to explain findings.
- Save scans locally and download an HTML report.

We check S3 for public ACLs, Block Public Access, wildcard principals, versioning, and HTTPS. For IAM, we check broad permissions, MFA, password policy, and unused access keys. We do not scan other services or make fixes automatically.

## Setup

You need Python 3.12 and Git.

1. Clone the repo and open the folder:

   ```bash
   git clone https://github.com/Singh0002/AWS-Misconfig-Scanner.git
   cd AWS-Misconfig-Scanner
   ```

2. Make a virtual environment and turn it on:

   ```bash
   python -m venv .venv
   ```

   On Windows PowerShell:

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

   On Windows Command Prompt:

   ```cmd
   .venv\Scripts\activate.bat
   ```

   On Ubuntu:

   ```bash
   source .venv/bin/activate
   ```

3. Install the packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up your AWS credentials. Use a read-only account with the `SecurityAudit` policy. If you have the AWS CLI, run:

   ```bash
   aws configure
   ```

   If you do not have the CLI, make a `credentials` file in `C:\Users\<you>\.aws\` on Windows or `~/.aws/` on Ubuntu:

   ```ini
   [default]
   aws_access_key_id = your-key-id
   aws_secret_access_key = your-secret
   ```

   Make a `config` file in the same folder:

   ```ini
   [default]
   region = us-east-1
   ```

5. For AI explanations, paste your Anthropic API key into Settings after starting the app. You can also set it before starting:

   ```powershell
   $env:ANTHROPIC_API_KEY="your-key-here"  # Windows PowerShell
   ```

   ```cmd
   set ANTHROPIC_API_KEY=your-key-here  # Windows Command Prompt
   ```

   ```bash
   export ANTHROPIC_API_KEY=your-key-here  # Ubuntu
   ```

   Do not put your key in the code or commit it.

6. Check your setup. Add `--ai-call` to test your AI key and credits too:

   ```bash
   python test_connection.py
   python test_connection.py --ai-call
   ```

## Running the app

Start the app from the project folder:

```bash
streamlit run app.py
```

Open http://localhost:8501, pick S3, IAM, or both, and start a scan. You can also pick specific checks. Results shows the findings, and Saved scans lets you open past scans.

Settings has connection checks, setup help, model selection, dark mode, and button colors. The colors reset when the app restarts. Press Ctrl+C in the terminal to stop it.

## AI explanations

Turn on AI explanations on the Scan tab and pick a model in Settings. The app sends finding info to Anthropic and shows an explanation and fix steps for each finding. The rules decide the results and severity.

Before sending findings, we remove fields named with `secret`, `token`, or `credential` and mask full AWS access key IDs. This does not catch every kind of sensitive information. If a request fails or there is no key, the finding still shows without an explanation. AI can make mistakes, so check the steps before changing anything in AWS.

A key pasted into Settings stays in memory unless you check "Remember this key on this computer". That saves it in `api_key.txt` beside the database. Uncheck it to delete the file.

## Saved scans and reports

The app saves scans in a local SQLite database:

- Windows: `%LOCALAPPDATA%\CloudGuardian\cloudguardian.db`
- Ubuntu: `~/.local/share/cloudguardian/cloudguardian.db`

Set `CLOUDGUARDIAN_DB` to use a different location. The database holds scan results and is left out of Git. Close the app before backing it up.

Use the service and severity filters on Results to change which findings show. The counts and report still include everything. Download report gives you an HTML file with the scan details, findings, explanations, and incomplete checks.

## Tests

Run the tests from the project folder:

```bash
python -m unittest discover tests
```

The live tests need a real AWS test account and an Anthropic API key. They are skipped unless you set `CLOUDGUARDIAN_LIVE=1`.

## Team

- Ajay Singh, project manager
- Martin Perez
- Zach Kidwell
