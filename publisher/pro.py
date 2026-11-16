"""Pro and MSP pages: Insights (report, trends, rule tuning), CSV export, re-triage, MSP usage export.

In the Community edition the Insights pages still open, but show what the feature does instead of data,
so people can see what an upgrade gives them. Nothing here changes how alerts are triaged.
"""
import csv
import io
import json
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, g, jsonify, render_template, request

import auth
import editions
import insights
from db import get_connection

bp = Blueprint("pro", __name__)
SECTIONS = ("report", "trends", "tuning")


def _main():
    import app as main          # late import: app registers this blueprint at the end of its module
    return main


def _scope():
    main = _main()
    siems = main.load_siems()
    first = siems[0]["id"] if siems else ""
    requested = (request.args.get("siem") or "")[:32] or None
    visible = [s for s in siems if auth.can_see_siem(g.user, s["id"])]
    return insights.scope_siems(g.user, requested, siems), first, visible, requested


def _locked(section, feature):
    return render_template("insights.html", section=section, locked=True,
                           needs=editions.FEATURES[feature], edition=editions.edition())


@bp.get("/insights")
def insights_home():
    return insights_page("report")


@bp.get("/insights/<section>")
def insights_page(section):
    if section not in SECTIONS:
        abort(404)
    feature = {"report": "reports", "trends": "reports", "tuning": "tuning"}[section]
    if section == "tuning" and g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)                                     # tuning proposes rule changes: analysts and admins
    if not editions.has(feature):
        return _locked(section, feature)
    scope, first, visible, requested = _scope()
    period = insights.period_from_args(request.args)
    data = {}
    if scope != []:
        if section == "report":
            data = insights.report(period, scope, first)
        elif section == "trends":
            data = {"weeks": insights.trends(scope, first)}
        else:
            data = {"patterns": insights.tuning(scope, first)}
    if section == "trends":
        weeks = data.get("weeks", [])
        data["max"] = max([w["alerts"] for w in weeks] or [1])
    siem_name = next((s["name"] for s in visible if s["id"] == requested), None)
    return render_template("insights.html", section=section, locked=False, data=data, period=period,
                           siems=visible, siem=requested or "", siem_name=siem_name,
                           siem_names={s["id"]: s["name"] for s in visible},
                           generated=datetime.now(timezone.utc), empty_scope=scope == [],
                           can_csv=editions.has("csv_export"))


# --------------------------------------------------------------------------- CSV export
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(value) -> str:
    """Neutralise spreadsheet formulas: alert fields are attacker-influenced."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


@bp.get("/api/alerts.csv")
def alerts_csv():
    if not editions.has("csv_export"):
        abort(403)
    main = _main()
    filters = main.get_filters(request.args)
    alerts = main.apply_filters(main.visible_alerts(main.load_alerts()), filters)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time_utc", "siem", "rule", "host", "verdict", "severity", "confidence", "escalate",
                "occurrences", "summary", "alert_id"])
    for a in alerts[:50000]:
        w.writerow([_cell(x) for x in (a["timestamp_iso"], a["siem_name"], a["rule_name"], a["hostname"],
                                        a["verdict"], a["severity"], a["confidence_score"], a["should_escalate"],
                                        a["occurrences"], a["detail"]["summary"], a["alert_id"])])
    name = f"ardea-alerts-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# --------------------------------------------------------------------------- re-triage
@bp.post("/api/alerts/<alert_id>/retriage")
def retriage(alert_id):
    if not editions.has("retriage"):
        abort(403)
    if g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)
    main = _main()
    main.require_alert_access(alert_id)
    with get_connection() as conn:
        row = conn.execute("""UPDATE alerts SET status = 'retry', attempts = 0, next_attempt_at = NOW(),
                                     locked_by = NULL, last_error = %s
                              WHERE alert_id = %s AND status IN ('done', 'failed')
                              RETURNING alert_id""",
                           (f"re-triage requested by {g.user['username']}", alert_id)).fetchone()
    if not row:
        return jsonify(error="already_queued"), 409
    auth.audit(g.user["username"], "retriage", target=alert_id[:120], ip=request.remote_addr)
    return {"ok": True}


# --------------------------------------------------------------------------- MSP usage export
@bp.get("/admin/usage.csv")
def usage_csv():
    if g.user["role"] != "admin":
        abort(403)
    if not editions.has("usage_export"):
        abort(403)
    month = request.args.get("month") or datetime.now(timezone.utc).strftime("%Y-%m")
    try:
        start = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
    except ValueError:
        abort(400)
    rows = insights.usage(start)
    out = io.StringIO()
    w = csv.writer(out)
    cols = ["siem", "siem_name", "alerts_triaged", "raw_alerts", "true_positive", "needs_review",
            "benign_positive", "false_positive"]
    w.writerow(["month"] + cols)
    for r in rows:
        w.writerow([month] + [_cell(r[c]) for c in cols])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="ardea-usage-{month}.csv"'})


def exception_json(entries) -> str:
    return json.dumps({"entries": entries}, indent=2)


bp.add_app_template_filter(exception_json, "exception_json")
