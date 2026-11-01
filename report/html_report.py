"""The downloadable HTML report.

build_report(scan) returns the whole page as one HTML string. It works the
same for the scan that just ran and for one opened from Saved scans, because
both have the same shape (results.py).

    page layout                      E-4 S-10-1
    scan details and findings        E-4 S-10-2
    explanations, incomplete checks  E-4 S-10-3
    escaping                         E-4 S-10-4

Every value that comes from AWS, the AI or the database goes through esc()
before it is added to the HTML. Bucket names, usernames, policy text and AI
answers are data, so something like "<script>" must show as text and never
run in the report. The page has no scripts and loads nothing from the web,
so it opens the same anywhere, even offline.
"""

import html
import json

from finding_details import evidence_lines, explanation_view, find_check, find_explanation

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


def explanations_html(scan):
    """The AI explanation and fix steps for each finding, most severe first."""
    parts = ['<section class="explanations">', "<h2>Explanations and fix steps</h2>"]
    if not scan["findings"]:
        parts.append("<p>No findings, so there is nothing to explain.</p>")
        parts.append("</section>")
        return "\n".join(parts)

    parts.append('<p class="note">Explanations are written by AI to help you fix each finding. '
                 "The rules decide pass or fail, not the AI.</p>")
    for finding in sorted_findings(scan):
        check = find_check(scan, finding["check_id"]) or {}
        ai = explanation_view(find_explanation(scan, finding["finding_id"]))
        parts.append('<div class="explanation">')
        parts.append(f"<h3>{esc(finding['severity'])}: {esc(finding['issue'])} "
                     f"({esc(check.get('resource_id'))})</h3>")
        if ai["state"] == "available":
            if ai["text"]:
                parts.append(f"<p>{esc(ai['text'])}</p>")
            if ai["steps"]:
                parts.append("<ol>")
                for step in ai["steps"]:
                    parts.append(f"<li>{esc(step)}</li>")
                parts.append("</ol>")
        else:
            parts.append(f'<p class="note">{esc(ai["message"])}</p>')
        parts.append("</div>")
    parts.append("</section>")
    return "\n".join(parts)


def incomplete_html(scan):
    """Checks that couldn't run, and what went wrong during the scan."""
    incomplete = [c for c in scan["checks"] if c["status"] == "incomplete"]
    parts = ['<section class="incomplete">', "<h2>Incomplete checks and errors</h2>"]
    if not incomplete and not scan["errors"]:
        parts.append("<p>None. Every selected check ran.</p>")
        parts.append("</section>")
        return "\n".join(parts)

    if incomplete:
        parts.append('<p class="note">These checks couldn\'t run, so they are not counted as passed.</p>')
        parts.append("<table>")
        parts.append("<tr><th>Service</th><th>Resource</th><th>Rule</th><th>Reason</th></tr>")
        for check in incomplete:
            parts.append(f"<tr><td>{esc(check['service'])}</td><td>{esc(check['resource_id'])}</td>"
                         f"<td>{esc(check['rule_id'])}</td><td>{esc(check['reason'])}</td></tr>")
        parts.append("</table>")
    if scan["errors"]:
        parts.append("<table>")
        parts.append("<tr><th>Stage</th><th>Operation</th><th>Resource</th><th>Message</th></tr>")
        for error in scan["errors"]:
            parts.append(f"<tr><td>{esc(error['stage'])}</td><td>{esc(error['operation'])}</td>"
                         f"<td>{esc(error['resource_id'])}</td><td>{esc(error['message'])}</td></tr>")
        parts.append("</table>")
    parts.append("</section>")
    return "\n".join(parts)


STYLE = """
body { font-family: Arial, Helvetica, sans-serif; color: #14202e; background: #f4f3ee;
       max-width: 1000px; margin: 0 auto; padding: 32px 24px; line-height: 1.45; }
header { border-bottom: 4px solid #f0a35e; margin-bottom: 24px; }
h1 { margin: 0 0 4px; }
h2 { margin-top: 36px; }
h3 { font-size: 1.05em; margin-bottom: 4px; }
table { border-collapse: collapse; width: 100%; background: #ffffff; }
th, td { border: 1px solid #d5d8dc; padding: 6px 10px; text-align: left; vertical-align: top; }
th { background: #e9e7df; }
.severity-high td:first-child { font-weight: bold; color: #b03a2e; }
.severity-medium td:first-child { font-weight: bold; color: #9a5b13; }
.explanation { background: #ffffff; border: 1px solid #d5d8dc; padding: 4px 16px 8px; margin: 12px 0; }
.note, footer { color: #5d6873; }
footer { margin-top: 40px; font-size: 0.9em; }
"""


def build_report(scan):
    """The whole report as one HTML page (E-4 S-10-1)."""
    meta = scan["metadata"]
    title = "CloudGuardian report " + format_time(meta["scan_time"])
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{esc(title)}</title>",
        f"<style>{STYLE}</style>",
        "</head>",
        "<body>",
        "<header>",
        "<h1>CloudGuardian report</h1>",
        f'<p class="note">Account {esc(meta.get("account_id") or "unknown")} | '
        f"{esc(format_time(meta['scan_time']))}</p>",
        "</header>",
        scan_details_html(scan),
        findings_html(scan),
        explanations_html(scan),
        incomplete_html(scan),
        "<footer>CloudGuardian only reads AWS settings and never changes anything. "
        "Findings come from the rules; AI explanations are advice to help fix them.</footer>",
        "</body>",
        "</html>",
    ])


def report_file_name(scan):
    # e.g. cloudguardian-report-2026-11-01-1430.html
    stamp = scan["metadata"]["scan_time"][:16].replace("T", "-").replace(":", "")
    return "cloudguardian-report-" + stamp + ".html"
