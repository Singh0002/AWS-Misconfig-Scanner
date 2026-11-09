"""Checks CloudTrail that the scanner only made read calls (E-6 S-11-1).

Run it with an ADMIN profile (needs cloudtrail:LookupEvents) a few minutes after a scan:

    python scripts/check_readonly.py --user cloudguardian-scanner --minutes 60

Event history can lag by several minutes. Exits with 1 if any call was not a
Get, List or Describe, so the result can go straight in the test record.
"""

import argparse
import collections
import datetime
import sys

import boto3

READ_PREFIXES = ("Get", "List", "Describe")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True, help="IAM user name the scanner runs as")
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    end = datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(minutes=args.minutes)
    client = boto3.Session(region_name=args.region).client("cloudtrail")
    pages = client.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": args.user}],
        StartTime=start, EndTime=end)

    names = collections.Counter()
    writes = []
    for page in pages:
        for event in page["Events"]:
            names[event["EventName"]] += 1
            if event.get("ReadOnly") == "false" or not event["EventName"].startswith(READ_PREFIXES):
                writes.append(event["EventName"])

    for name, count in sorted(names.items()):
        print(f"{count:4d}  {name}")
    print(f"\n{sum(names.values())} events from {args.user} in the last {args.minutes} minutes.")
    if not names:
        sys.exit("No events found. Wait a few minutes, check the user name, or check the region.")
    if writes:
        print("NOT READ-ONLY: " + ", ".join(sorted(set(writes))))
        sys.exit(1)
    print("PASS: every call was a Get, List or Describe.")


if __name__ == "__main__":
    main()
