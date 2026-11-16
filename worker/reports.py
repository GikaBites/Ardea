"""Scheduled report e-mails (Pro), and one report per customer SIEM (MSP).

ARDEA_REPORTS=weekly | monthly | off (default off). Weekly reports go out on Monday for the previous
Monday-to-Sunday week, monthly reports on the 1st for the previous month (UTC). Recipients:
ARDEA_REPORT_TO (comma list), else SMTP_TO. MSP: every SIEM in siems.json with "report_to" also gets its
own report, limited to that SIEM's alerts and sent under ARDEA_BRAND_NAME.

Each report is sent once: report_runs records it, so several workers or restarts never send it twice.
The e-mail is plain text with the key figures and a link to the full report in the web UI.
"""
import logging
from datetime import datetime, timedelta, timezone

import config
import elastic
import licensing

log = logging.getLogger("reports")
SCHEMA = """CREATE TABLE IF NOT EXISTS report_runs (
    run_key TEXT PRIMARY KEY, sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'sent', detail TEXT)"""


def ensure_schema(conn):
    conn.execute(SCHEMA)


def due_period(schedule: str, now: datetime) -> dict | None:
    """The period whose report is due now, or None."""
    if schedule == "weekly":
        this_monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        start = this_monday - timedelta(days=7)
        iso = start.isocalendar()
        return {"start": start, "end": this_monday, "key": f"weekly:{iso.year}-W{iso.week:02d}",
                "label": f"week of {start:%d/%m/%Y}", "link": "range=7d"}
    if schedule == "monthly":
        first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = (first - timedelta(days=1)).replace(day=1)
        return {"start": start, "end": first, "key": f"monthly:{start:%Y-%m}", "label": f"{start:%B %Y}",
                "link": f"month={start:%Y-%m}"}
    return None


def summary(conn, start, end, siem: str | None) -> dict:
    p = {"start": start, "end": end, "siem": siem}
    scope = "AND a.siem = %(siem)s" if siem else ""
    t = conn.execute(f"""
        SELECT count(*) AS alerts, COALESCE(sum(a.count), 0) AS raw,
               count(*) FILTER (WHERE t.verdict = 'True Positive') AS tp,
               count(*) FILTER (WHERE t.verdict = 'Needs Human Review') AS review,
               count(*) FILTER (WHERE t.verdict IN ('Benign Positive', 'False Positive')) AS closed,
               COALESCE(sum(a.count) FILTER (WHERE t.verdict IN ('Benign Positive', 'False Positive')), 0) AS closed_raw
        FROM triage_results t JOIN alerts a USING (alert_id)
        WHERE t.created_at >= %(start)s AND t.created_at < %(end)s {scope}""", p).fetchone()
    rules = conn.execute(f"""
        SELECT a.rule_name, COALESCE(sum(a.count), 0) AS raw
        FROM triage_results t JOIN alerts a USING (alert_id)
        WHERE t.created_at >= %(start)s AND t.created_at < %(end)s {scope}
        GROUP BY a.rule_name ORDER BY 2 DESC LIMIT 5""", p).fetchall()
    tps = conn.execute(f"""
        SELECT a.rule_name, a.host_name, t.severity, t.created_at
        FROM triage_results t JOIN alerts a USING (alert_id)
        WHERE t.created_at >= %(start)s AND t.created_at < %(end)s {scope} AND t.verdict = 'True Positive'
        ORDER BY t.created_at DESC LIMIT 10""", p).fetchall()
    return {**t, "rules": rules, "true_positives": tps}


def render(s: dict, period: dict, brand: str, siem_name: str | None, minutes: int) -> tuple[str, str]:
    closed_pct = round(100 * s["closed"] / s["alerts"]) if s["alerts"] else 0
    hours = round(s["closed_raw"] * minutes / 60, 1)
    where = f" · {siem_name}" if siem_name else ""
    subject = (f"[{brand}] Report {period['label']}{where}: {s['raw']} alerts, {closed_pct}% closed automatically, "
               f"{s['tp']} true positive{'' if s['tp'] == 1 else 's'}")[:200]
    lines = [f"{brand} triage report, {period['label']}{where}", "",
             f"Alerts triaged:          {s['raw']} ({s['alerts']} after merging duplicates)",
             f"Closed automatically:    {s['closed']} ({closed_pct}%)",
             f"Sent to a person:        {s['tp'] + s['review']} ({s['review']} review, {s['tp']} true positive)",
             f"Analyst time saved:      about {hours} h (estimate, {minutes} min per closed alert)"]
    if s["true_positives"]:
        lines += ["", "True positives:"]
        for r in s["true_positives"]:
            host = "" if config.NOTIFY_DETAIL == "minimal" else f" on {r['host_name'] or '?'}"
            lines.append(f"  - {r['created_at']:%d/%m %H:%M} {r['severity']}: {r['rule_name']}{host}")
    if s["rules"]:
        lines += ["", "Noisiest rules:"] + [f"  - {r['rule_name']}: {r['raw']}" for r in s["rules"]]
    if config.ARDEA_PUBLIC_URL:
        link = f"{config.ARDEA_PUBLIC_URL}/insights/report?{period['link']}"
        lines += ["", f"Full report: {link}"]
    lines += ["", "Figures come from your own Ardea database. Time saved is an estimate."]
    return subject, "\n".join(lines)


def _recipients() -> list[str]:
    raw = config.env("ARDEA_REPORT_TO") or config.env("SMTP_TO")
    return [a.strip() for a in raw.split(",") if a.strip()]


def run_due(conn, now: datetime | None = None, send=None) -> list[str]:
    """Send whatever report is due. Never raises. Returns the run keys sent (for tests and logs)."""
    schedule = config.env("ARDEA_REPORTS", "off").lower()
    period = due_period(schedule, now or datetime.now(timezone.utc))
    if not period or not licensing.has("reports"):
        return []
    import notifier
    send = send or (lambda subject, body, to: notifier.send_smtp({}, {"smtp_to": to}, subject, body))
    brand = (config.env("ARDEA_BRAND_NAME") if licensing.has("branding") else "") or "Ardea"
    minutes = max(1, int(config.env("ARDEA_MINUTES_PER_ALERT", "10") or 10))
    jobs = []
    if _recipients():
        jobs.append((f"{period['key']}:all", None, None, _recipients()))
    if licensing.has("customer_reports"):
        for s in elastic.configured().values():
            if s.report_to:
                jobs.append((f"{period['key']}:{s.id}", s.id, s.name, list(s.report_to)))
    sent = []
    for key, siem_id, siem_name, to in jobs:
        try:
            claimed = conn.execute("INSERT INTO report_runs (run_key, status) VALUES (%s, 'sending') "
                                   "ON CONFLICT (run_key) DO NOTHING RETURNING run_key", (key,)).fetchone()
            if not claimed:
                continue
            p = dict(period, link=period["link"] + (f"&siem={siem_id}" if siem_id else ""))
            subject, body = render(summary(conn, period["start"], period["end"], siem_id), p, brand, siem_name,
                                   minutes)
            send(subject, body, to)
            conn.execute("UPDATE report_runs SET status = 'sent', sent_at = NOW() WHERE run_key = %s", (key,))
            sent.append(key)
            log.info("report %s sent to %s recipient(s)", key, len(to))
        except Exception as exc:
            log.error("report %s failed, will retry: %s", key, exc)
            try:   # forget the claim so the next maintenance cycle tries again
                conn.execute("DELETE FROM report_runs WHERE run_key = %s", (key,))
            except Exception:
                pass
    return sent
