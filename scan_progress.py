"""Tracks scan progress and prevents overlapping scans."""

IDLE = "idle"
RUNNING = "running"
DONE = "done"
FAILED = "failed"


def idle():
    return {"state": IDLE, "done": 0, "total": 0, "message": ""}


def start():
    """A scan has been requested. total is unknown until the coordinator reports it."""
    return {"state": RUNNING, "done": 0, "total": 0, "message": "Starting scan..."}


def can_start(progress):
    """False while a scan is running, so a second scan can't be started."""
    return progress["state"] != RUNNING


def update(progress, done, total, message):
    """Returns the progress after one step. done is never above total."""
    if progress["state"] != RUNNING:
        return progress
    total = max(int(total), 0)
    done = min(max(int(done), 0), total)
    return {"state": RUNNING, "done": done, "total": total, "message": message}


def finish(progress, ok, message=None):
    state = DONE if ok else FAILED
    if message is None:
        message = "Scan finished." if ok else "The scan stopped before it finished."
    done = progress["total"] if ok else progress["done"]
    return {"state": state, "done": done, "total": progress["total"], "message": message}


def fraction(progress):
    """A number from 0.0 to 1.0 for st.progress."""
    if progress["state"] == DONE:
        return 1.0
    if progress["total"] == 0:
        return 0.0
    return progress["done"] / progress["total"]


def text(progress):
    """The words shown next to the bar."""
    if progress["state"] == IDLE:
        return "No scan running."
    return progress["message"]
