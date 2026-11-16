# AWS Misconfiguration Scanner

CloudGuardian is our senior project for finding common security issues in AWS configurations. It checks S3 and IAM settings against ten rules and shows the results in a local Streamlit app. We use AI to explain findings and suggest fixes. The scanner only reads AWS settings; it does not change them.

## What it does

- Scans S3, IAM, or both in one AWS account.
- Shows passed and incomplete checks and findings with their severity.
- Uses the Anthropic API to explain findings when AI explanations are turned on.
- Saves scans locally and creates an HTML report you can open offline.

The S3 checks cover public ACLs, Block Public Access, wildcard principals, versioning, and HTTPS. The IAM checks cover broad permissions, user and root MFA, password policy, and unused access keys. We do not scan other services or make fixes automatically.

## Setup

You need Python 3.12 and Git.

1. Clone the repository and open the folder:

   ```bash
   git clone https://github.com/Singh0002/AWS-Misconfig-Scanner.git
   cd AWS-Misconfig-Scanner
   ```

2. Create a virtual environment and activate it:

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

4. Set up AWS credentials for the account you want to scan. Use a read-only account with the `SecurityAudit` policy. If you have the AWS CLI, run:

   ```bash
   aws configure
   ```

   If you do not have the CLI, create a `credentials` file in `C:\Users\<you>\.aws\` on Windows or `~/.aws/` on Ubuntu:

   ```ini
   [default]
   aws_access_key_id = your-key-id
   aws_secret_access_key = your-secret
   ```

   Create a `config` file in the same folder:

   ```ini
   [default]
   region = us-east-1
   ```

5. For AI explanations, paste your Anthropic API key into the Settings tab after starting the app. You can also set `ANTHROPIC_API_KEY` before starting it:

   ```powershell
   $env:ANTHROPIC_API_KEY="your-key-here"  # Windows PowerShell
   ```

   ```cmd
   set ANTHROPIC_API_KEY=your-key-here  # Windows Command Prompt
   ```

   ```bash
   export ANTHROPIC_API_KEY=your-key-here  # Ubuntu
   ```

   Do not put your key in the code or commit it to Git.

6. Check your setup. The second command also makes a small AI request to test your key and credits:

   ```bash
   python test_connection.py
   python test_connection.py --ai-call
   ```

## Running the app

Start the app from the project folder:

```bash
streamlit run app.py
```

Open http://localhost:8501, select S3, IAM, or both, and start a scan. You can also choose specific checks. The Results tab shows the findings, and Saved scans lets you reopen past scans without running them again.

The Settings tab has connection checks, setup help, AI model selection, dark mode, and button colors. The appearance settings reset when the app restarts. Press Ctrl+C in the terminal to stop the app.

## AI explanations

Turn on AI explanations on the Scan tab and select a model on the Settings tab. The app sends finding information to Anthropic and shows the explanation and suggested steps with each finding. The rules decide the results and severity.

We remove fields with names containing `secret`, `token`, or `credential` and mask full AWS access key IDs before sending finding data. Do not rely on this to remove every kind of sensitive information. If a request fails or no key is set, the explanation is unavailable and the finding stays in the results. AI can make mistakes, so check the suggested steps before changing anything in AWS.

A key pasted into Settings stays in memory unless you select "Remember this key on this computer". That option saves it in `api_key.txt` beside the database. Clear the option to delete the saved file.

## Saved scans and reports

The app creates a local SQLite database when it starts. The default locations are:

- Windows: `%LOCALAPPDATA%\CloudGuardian\cloudguardian.db`
- Ubuntu: `~/.local/share/cloudguardian/cloudguardian.db`

Set `CLOUDGUARDIAN_DB` to use a different location. The database contains scan results and is not included in Git. Close the app before backing it up.

On the Results tab, use the service and severity filters to change the findings shown. The counts and downloaded report still include all findings. Download report creates an HTML file with the scan details, findings, explanations, and incomplete checks.

## Tests

Run the automated tests from the project folder:

```bash
python -m unittest discover tests
```

The live tests need a real AWS test account and an Anthropic API key. They are skipped unless `CLOUDGUARDIAN_LIVE=1` is set.

## Team

- Ajay Singh, project manager
- Martin Perez
- Zach Kidwell
