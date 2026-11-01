# AWS Misconfiguration Scanner

## Project Overview
The AWS Misconfiguration Scanner is an AI-assisted security tool designed to identify configuration issues in selected AWS services. The first version of the project will focus on Amazon S3 and AWS IAM. The scanner will retrieve configuration information from an AWS account, compare it against predefined security rules, and flag configurations that may create security risks. AI will be used to help explain the findings and provide clearer information to the user.


## Features
It will scan S3 configurations
It will scan IAM configurations
Check configurations against predefined rules 
use ai api to explain detected findings 
Results shown in streamlet interface 
Downloadable html file



## Technologies Used
python
boto3
aws
streamlit
github
ai api 

## How It Works
the user will first configure there aws credentials locally
the aws boto3 will use those credentials to connect the a specfic aws account
the boto3 will retrieve s3 and iam configuration information
the configurations then will be scanned against predefined rules 

## Setup
You need Python 3.12 and git.

1. Clone the repo and go into the folder
```
git clone https://github.com/Singh0002/AWS-Misconfig-Scanner.git
cd AWS-Misconfig-Scanner
```

2. Make a virtual environment and turn it on
```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Ubuntu
```

3. Install the packages
```
pip install -r requirements.txt
```

4. Set up your AWS credentials (only needed for real scans). You need the AWS CLI installed for this. Use an account with read-only access. The scanner never changes anything in AWS.
```
aws configure
```
The AWS user needs the `SecurityAudit` policy (it's read only). If you don't have the AWS CLI you can make the files yourself. Put this in `C:\Users\<you>\.aws\credentials` (Windows) or `~/.aws/credentials` (Ubuntu):
```
[default]
aws_access_key_id = your-key-id
aws_secret_access_key = your-secret
```
and this in a file called `config` in the same folder:
```
[default]
region = us-east-1
```

5. Set your Anthropic API key (only needed for AI explanations). The easy way is to paste it in Settings in the app. Tick "Remember this key on this computer" if you don't want to paste it every time. Or set it once like below. Don't put the key in the code or commit it.
```
set ANTHROPIC_API_KEY=your-key-here           # Windows (cmd)
$env:ANTHROPIC_API_KEY="your-key-here"        # Windows (PowerShell)
export ANTHROPIC_API_KEY=your-key-here        # Ubuntu
```

6. Check your setup. This only reads from AWS and never prints keys. Add `--ai-call` to also make one tiny AI request that confirms your key and credits work.
```
python test_connection.py
python test_connection.py --ai-call
```

## Running the app
```
streamlit run app.py
```
It opens at http://localhost:8501. Pick the services and rules and press Start scan. Finished scans save automatically and show up in Saved scans. Don't use the VS Code run button, it runs plain python and nothing will open. Press Ctrl+C in the terminal to stop it.

## Database
Saved scans go in a local SQLite file called `cloudguardian.db`. The app makes it and its tables the first time it runs.
- Windows: `%LOCALAPPDATA%\CloudGuardian\cloudguardian.db`
- Ubuntu: `~/.local/share/cloudguardian/cloudguardian.db`

You can set `CLOUDGUARDIAN_DB` to put it somewhere else. It has scan results in it so it's left out of Git. If you want to back it up, close the app first.

## Results format
All the modules pass results around in the same format, defined in `results.py`. Use its `make_check`, `make_finding`, `make_explanation` and `make_error` functions so the results can be saved straight to the database.

## Explanations
After a scan the app sends the findings to Anthropic and shows a short explanation and fix steps for each one under Finding details on the Results tab. They get saved with the scan, so they show up again when you open it from Saved scans.

Paste your API key and pick a model (Opus, Sonnet or Haiku) in Settings. The key is only kept while the page is open, unless you tick "Remember this key on this computer". That saves it in `api_key.txt` in the same folder as the database (see Database above), not in the repo. Untick it to delete the file. You can also set `ANTHROPIC_API_KEY` like in Setup.

Only the finding info gets sent, and anything that looks like a secret or an access key is taken out first. If there's no key, the request fails, or it takes over 30 seconds, the finding just says there's no explanation. The rule results and severity don't change either way.

Not done yet:
- tests for the explanation code
- the password policy and unused access key rules aren't hooked up to scans yet, that's waiting on the IAM collector changes
- the downloadable report doesn't have the explanations in it yet

## Tests
```
python -m unittest discover tests
```

## Project Scope

## Team
