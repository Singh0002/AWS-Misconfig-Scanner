"""Pieces of the downloadable HTML report.

This file has the scan details and findings sections (E-4 S-10-2) and the
escaping every section uses (E-4 S-10-4). The page layout (E-4 S-10-1) and
the explanations and incomplete checks sections (E-4 S-10-3) go here too.
A layout can put the sections together like this:

    body = scan_details_html(scan) + findings_html(scan)

Every value that comes from AWS, the AI or the database goes through esc()
before it is added to the HTML. Bucket names, usernames, policy text and AI
answers are data, so something like "<script>" must show as text and never
run in the report.
"""

import html
import json

from finding_details import evidence_lines, find_check

SEVERITY_ORDER = ["High", "Medium", "Low"]


def esc(value):
    """Makes any value safe to put inside HTML text or an attribute. None -> ""."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def format_time(scan_time):
    # 2026-10-15T14:30:00+00:00 -> 2026-10-15 14:30 UTC
    return scan_time[:16].replace("T", " ") + " UTC"


def format_services(selected_services):
    # stored as a JSON string, e.g. '["S3", "IAM"]'
    try:
        return ", ".join(json.loads(selected_services))
    except (TypeError, ValueError):
        return str(selected_services)


def count_results(scan):
    """How many findings of each severity, plus passed and incomplete checks."""
    counts = {"High": 0, "Medium": 0, "Low": 0, "Passed": 0, "Incomplete": 0}
    for finding in scan["findings"]:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1
    for check in scan["checks"]:
        if check["status"] == "pass":
            counts["Passed"] += 1
        elif check["status"] == "incomplete":
            counts["Incomplete"] += 1
    return counts


def scan_details_html(scan):
    """The scan details section: account, time, services, status and the counts."""
    meta = scan["metadata"]
    rows = [
        ("Account", meta.get("account_id") or "unknown"),
        ("Scan time", format_time(meta["scan_time"])),
        ("Services", format_services(meta["selected_services"])),
        ("Scan status", meta["scan_status"]),
        ("Coverage", meta["coverage_status"]),
    ]
    counts = count_results(scan)
    summary = ", ".join(f"{name}: {number}" for name, number in counts.items())

    parts = ['<section class="scan-details">', "<h2>Scan details</h2>", "<table>"]
    for label, value in rows:
        parts.append(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>")
    parts.append("</table>")
    parts.append(f'<p class="summary">{esc(summary)}</p>')
    if meta["coverage_status"] == "incomplete":
        parts.append('<p class="note">Some checks couldn\'t run, so this scan doesn\'t '
                     "cover everything. Incomplete checks are never counted as passed.</p>")
    parts.append("</section>")
    return "\n".join(parts)


def sorted_findings(scan):
    """Findings in High, Medium, Low order. Anything else goes last."""
    def rank(finding):
        if finding["severity"] in SEVERITY_ORDER:
            return SEVERITY_ORDER.index(finding["severity"])
        return len(SEVERITY_ORDER)
    return sorted(scan["findings"], key=rank)


def findings_html(scan):
    """The findings section: one table row per finding, most severe first."""
    parts = ['<section class="findings">', "<h2>Findings</h2>"]
    if not scan["findings"]:
        parts.append("<p>The selected checks found no issues.</p>")
        parts.append("</section>")
        return "\n".join(parts)

    parts.append("<table>")
    parts.append("<tr><th>Severity</th><th>Service</th><th>Resource</th>"
                 "<th>Issue</th><th>What the rule found</th></tr>")
    for finding in sorted_findings(scan):
        check = find_check(scan, finding["check_id"]) or {}
        evidence = "<br>".join(esc(line) for line in evidence_lines(check.get("evidence_json")))
        severity_class = esc("severity-" + finding["severity"].lower())
        parts.append(
            f'<tr class="{severity_class}">'
            f"<td>{esc(finding['severity'])}</td>"
            f"<td>{esc(check.get('service'))}</td>"
            f"<td>{esc(check.get('resource_id'))}</td>"
            f"<td>{esc(finding['issue'])}</td>"
            f"<td>{evidence}</td></tr>")
    parts.append("</table>")
    parts.append("</section>")
    return "\n".join(parts)
