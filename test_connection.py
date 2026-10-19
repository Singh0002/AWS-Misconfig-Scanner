"""Checks that this machine is set up to run CloudGuardian (S-1-4).

Run it from the project folder with:

    python test_connection.py              # AWS credentials, S3 and IAM read access, AI key
    python test_connection.py --ai-call    # also makes one tiny AI request to confirm credits

It only reads from AWS. It never prints keys or secrets, only whether each
check worked and what to fix if it didn't. Each check_ function returns
(ok, message) so the app's "Check connection" button can reuse them.
"""

import os
import sys

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)


def _aws_error_message(error):
    """Turns a boto3 error into one short sentence with no secrets in it."""
    if isinstance(error, NoCredentialsError):
        return "No AWS credentials found. Run 'aws configure' or set AWS_PROFILE."
    if isinstance(error, ProfileNotFound):
        return "That AWS profile doesn't exist. Check the profile name."
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "Unknown")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "Access denied. This account needs read-only permissions for this service."
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken"):
            return "AWS rejected the credentials (wrong or expired). Check 'aws configure'."
        return "AWS returned an error: " + code
    return "Couldn't reach AWS. Check your internet connection and region."


def make_session(profile=None, region=None):
    # profile=None lets boto3 use the default profile or environment variables
    session = boto3.Session(profile_name=profile, region_name=region)
    if session.region_name is None:
        # S3 and IAM don't depend on region, but boto3 wants one set
        session = boto3.Session(profile_name=profile, region_name="us-east-1")
    return session


def check_aws_credentials(session):
    """Asks AWS who we are. Only the account ID is shown, never a key."""
    try:
        identity = session.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as error:
        return False, _aws_error_message(error)
    return True, "AWS credentials work (account " + identity["Account"] + ")."


def check_s3_access(session):
    try:
        buckets = session.client("s3").list_buckets()["Buckets"]
    except (BotoCoreError, ClientError) as error:
        return False, _aws_error_message(error)
    return True, "S3 read access works (" + str(len(buckets)) + " bucket(s))."


def check_iam_access(session):
    try:
        session.client("iam").list_users(MaxItems=1)
    except (BotoCoreError, ClientError) as error:
        return False, _aws_error_message(error)
    return True, "IAM read access works."


def check_ai_key(make_request=False):
    """Checks the Anthropic key is set. make_request=True also sends one tiny
    request, which uses a very small amount of credit, to prove the key and
    credits really work."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return False, "No ANTHROPIC_API_KEY set. AI explanations will be off."
    if not make_request:
        return True, "ANTHROPIC_API_KEY is set (not tested; use --ai-call to test it)."

    try:
        import anthropic
    except ImportError:
        return False, "The anthropic package isn't installed. Run 'pip install -r requirements.txt'."
    try:
        client = anthropic.Anthropic(api_key=key, timeout=30, max_retries=0)
        client.messages.create(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-haiku-5-5"),
            max_tokens=1,
            messages=[{"role": "user", "content": "hi"}],
        )
    except anthropic.AuthenticationError:
        return False, "The Anthropic key was rejected. Check that it is correct."
    except anthropic.PermissionDeniedError:
        return False, "The Anthropic key isn't allowed to use that model."
    except anthropic.RateLimitError:
        return False, "Anthropic rate limit hit. Try again in a minute."
    except anthropic.APIStatusError as error:
        # a 400 here is usually "credit balance is too low"
        return False, "Anthropic returned an error (status " + str(error.status_code) + "). Check your credits."
    except anthropic.APIConnectionError:
        return False, "Couldn't reach Anthropic. Check your internet connection."
    return True, "Anthropic key and credits work."


def run_all(profile=None, region=None, ai_call=False):
    """Runs every check. Returns a list of (name, ok, message)."""
    results = []
    try:
        session = make_session(profile, region)
    except (BotoCoreError, ClientError) as error:
        return [("AWS credentials", False, _aws_error_message(error))]

    ok, message = check_aws_credentials(session)
    results.append(("AWS credentials", ok, message))
    if ok:
        # no point trying S3 and IAM if the credentials themselves don't work
        for name, check in (("S3", check_s3_access), ("IAM", check_iam_access)):
            ok, message = check(session)
            results.append((name, ok, message))
    ok, message = check_ai_key(make_request=ai_call)
    results.append(("AI key", ok, message))
    return results


if __name__ == "__main__":
    all_ok = True
    for name, ok, message in run_all(
        profile=os.environ.get("AWS_PROFILE"), ai_call="--ai-call" in sys.argv
    ):
        print(("PASS  " if ok else "FAIL  ") + name + ": " + message)
        all_ok = all_ok and ok
    sys.exit(0 if all_ok else 1)
