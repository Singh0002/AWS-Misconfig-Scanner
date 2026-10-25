from botocore.exceptions import BotoCoreError, ClientError


def read_setting(call, missing_codes=()):
    """Runs one read-only AWS call. Returns (status, value, error_code)."""
    try:
        return "available", call(), None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code in missing_codes:
            return "missing", None, None
        return "failed", None, code
    except BotoCoreError as e:
        return "failed", None, type(e).__name__


def error_code(e):
    """Safe text for an error record: the code or type only, never the message."""
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "Unknown")
    return type(e).__name__
