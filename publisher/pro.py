"""Pro and MSP pages: Insights (report, trends, rule tuning), CSV export, re-triage, MSP usage export.

In the Community edition the Insights pages still open, but show what the feature does instead of data,
so people can see what an upgrade gives them. Nothing here changes how alerts are triaged.
"""
import csv
import io
import json
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, g, jsonify, redirect, render_template, request

import auth
import editions
import incidents
import insights
import nis2
import suppressions
import work
from db import get_connection

bp = Blueprint("pro", __name__)
SECTIONS = ("report", "trends", "tuning", "suppressions")


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
    feature = {"report": "reports", "trends": "reports", "tuning": "tuning", "suppressions": "suppressions"}[section]
    if section in ("tuning", "suppressions") and g.user["role"] not in auth.FEEDBACK_ROLES:
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
        elif section == "suppressions":
            data = {"suggestions": suppressions.suggestions(scope, first), "list": suppressions.listing(scope),
                    "days": suppressions.DEFAULT_DAYS, "max_days": suppressions.MAX_DAYS,
                    "error": request.args.get("error", "")[:200], "done": request.args.get("done", "")}
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


@bp.post("/suppressions")
def suppression_create():
    if not editions.has("suppressions") or g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)
    try:
        sid = suppressions.create(g.user["username"], request.form, lambda s: auth.can_see_siem(g.user, s))
    except suppressions.SuppressionError as exc:
        return redirect(f"/insights/suppressions?error={_q(str(exc))}", code=303)
    auth.audit(g.user["username"], "suppression_created", target=str(sid),
               detail=f"{request.form.get('rule_name', '')[:200]} / {request.form.get('process_executable', '')[:200]}")
    return redirect(f"/insights/suppressions?done=created#s{sid}", code=303)


@bp.post("/suppressions/<int:sid>/revoke")
def suppression_revoke(sid):
    if not editions.has("suppressions") or g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)
    if not suppressions.revoke(sid, g.user["username"], lambda s: auth.can_see_siem(g.user, s)):
        abort(404)
    auth.audit(g.user["username"], "suppression_revoked", target=str(sid))
    return redirect("/insights/suppressions?done=revoked", code=303)


# --------------------------------------------------------------------------- incidents
@bp.get("/incidents")
def incidents_page():
    if not editions.has("incidents"):
        return render_template("incidents.html", locked=True, needs=editions.FEATURES["incidents"],
                               edition=editions.edition())
    main = _main()
    everything, _ = main.load_incidents()
    mine = [i for i in everything if auth.can_see_siem(g.user, i["siem"])]
    range_key = request.args.get("range", "7d")
    range_key = range_key if range_key in incidents.RANGES else "7d"
    status = "all" if request.args.get("status") == "all" else "attention"
    siem = (request.args.get("siem") or "")[:32]
    shown = incidents.select(mine, range_key=range_key, status=status, siem=siem)
    visible = [s for s in main.load_siems() if auth.can_see_siem(g.user, s["id"])]
    return render_template("incidents.html", locked=False, incidents=shown, range_key=range_key,
                           status=status, siem=siem, siems=visible, inc_work=_incident_work(shown),
                           bulk=work.enabled() and g.user["role"] in auth.FEEDBACK_ROLES,
                           users=work.assignable_users() if work.enabled() else [],
                           error=request.args.get("error", "")[:200], done=request.args.get("done", ""),
                           open_count=sum(1 for i in incidents.select(mine, range_key=range_key, siem=siem)))


@bp.get("/incidents/<inc_id>")
def incident_page(inc_id):
    if not editions.has("incidents"):
        return render_template("incidents.html", locked=True, needs=editions.FEATURES["incidents"],
                               edition=editions.edition())
    everything, _ = _main().load_incidents()
    inc = incidents.find(everything, inc_id[:40])
    if inc is None or not auth.can_see_siem(g.user, inc["siem"]):
        abort(404)                                     # not 403: don't confirm it exists
    items = _incident_work([inc]).get(inc["id"], {}).get("items", [])
    return render_template("incident.html", inc=inc, multi_siem=len(_main().load_siems()) > 1,
                           work_on=work.enabled(), items=items,
                           can_work=g.user["role"] in auth.FEEDBACK_ROLES,
                           users=work.assignable_users(inc["siem"]) if work.enabled() else [],
                           log=work.history([i["alert"]["alert_id"] for i in items]) if items else [],
                           labels=work.STATUS_LABELS, due_text=work.due_text, nis2=editions.has("nis2"),
                           can_export=editions.has("incident_export"),
                           error=request.args.get("error", "")[:200], done=request.args.get("done", ""))


def _incident_or_404(inc_id):
    everything, _ = _main().load_incidents()
    inc = incidents.find(everything, inc_id[:40])
    if inc is None or not auth.can_see_siem(g.user, inc["siem"]):
        abort(404)
    return inc


@bp.get("/incidents/<inc_id>/nis2")
def incident_nis2(inc_id):
    if not editions.has("nis2"):
        return _locked_page("nis2")
    inc = _incident_or_404(inc_id)
    stage = request.args.get("stage", "early")
    stage = stage if stage in nis2.STAGES else "early"
    notes = []
    if work.enabled():
        rows, _ = work.load(a["alert_id"] for a in inc["alerts"])
        notes = [r["note"] for r in rows.values() if r.get("status") == "resolved" and r.get("note")]
    text_ = nis2.draft(inc, stage, notes)
    if request.args.get("download") == "1":
        name = f"nis2-{stage}-{inc['id']}.txt"
        return Response(text_ + "\n", mimetype="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})
    return render_template("nis2.html", inc=inc, stage=stage, stages=nis2.STAGES, draft=text_,
                           deadlines=nis2.deadlines(inc), todo_count=text_.count("[TO COMPLETE"))


@bp.get("/incidents/<inc_id>/export.zip")
def incident_export(inc_id):
    if not editions.has("incident_export"):
        return _locked_page("incident_export")
    import zipfile
    from db import get_feedback, get_trail
    inc = _incident_or_404(inc_id)
    alerts = inc["alerts"][:200]
    rows, _ = work.load(a["alert_id"] for a in alerts) if work.enabled() else ({}, set())
    t = lambda d: d.astimezone().strftime("%d/%m/%Y %H:%M:%S")          # noqa: E731
    md = [f"# Incident {inc['id']}: {inc['title']} on {inc['where']}", "",
          f"- SIEM: {inc['siem_name']}", f"- Status: {'needs a person' if inc['status'] == 'attention' else 'closed'}"
          f", highest severity {inc['severity']}", f"- Time: {t(inc['start'])} to {t(inc['end'])} ({inc['minutes']} min)",
          f"- Alerts: {inc['count']} ({inc['needs_person']} needed a person)",
          f"- Hosts: {', '.join(inc['hosts']) or '-'}", f"- Accounts: {', '.join(inc['users']) or '-'}",
          f"- Techniques: {', '.join((m['id'] + ' ' + m['name']).strip() for m in inc['techniques']) or '-'}",
          f"- Exported: {t(datetime.now(timezone.utc))} by {g.user['username']}", "", "## Timeline", ""]
    out_alerts = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        timeline = io.StringIO()
        w = csv.writer(timeline)
        w.writerow(["time", "alert_id", "verdict", "severity", "confidence", "rule", "host", "account", "assignee",
                    "status", "summary"])
        for a in alerts:
            d = a.get("detail") or {}
            wr = rows.get(a["alert_id"]) or {}
            w.writerow([_cell(x) for x in (a["timestamp_raw"].isoformat(), a["alert_id"], a["verdict"], a["severity"],
                                           a.get("confidence_score"), a["rule_name"], a["hostname"], a.get("user", ""),
                                           wr.get("assignee") or "", wr.get("status") or "", d.get("summary", ""))])
            md += [f"### {t(a['timestamp_raw'])} · {a['rule_name']} on {a['hostname']}", "",
                   f"**{a['verdict']}**, {a['severity']}, confidence {a.get('confidence_score')}. Alert `{a['alert_id']}`.",
                   "", d.get("summary", "") or "(no summary)", ""]
            md += [f"- [{f_['stance']}] {f_['claim']} ({', '.join(f_['evidence']) or 'no evidence id'})"
                   for f_ in d.get("findings", [])]
            md += [f"- Action ({act.get('priority') or '-'}): {act['action']}" for act in d.get("actions", [])]
            if wr.get("note"):
                md.append(f"- Resolution note: {wr['note']}")
            md.append("")
            trail = get_trail(a["alert_id"])
            z.writestr(f"trails/{_safe_name(a['alert_id'])}.json",
                       json.dumps({"alert_id": a["alert_id"], "steps": trail, "feedback": get_feedback(a["alert_id"])},
                                  default=str, indent=1, ensure_ascii=False))
            out_alerts.append({k: a.get(k) for k in ("alert_id", "rule_name", "hostname", "user", "siem", "verdict",
                                                      "severity", "confidence_score", "occurrences", "detail")}
                              | {"time": a["timestamp_raw"].isoformat(), "work": wr or None})
        z.writestr("report.md", "\n".join(md) + "\n")
        z.writestr("timeline.csv", timeline.getvalue())
        z.writestr("incident.json", json.dumps({k: inc[k] for k in ("id", "title", "where", "siem", "siem_name", "status",
                                                                    "severity", "count", "hosts", "users", "techniques",
                                                                    "verdicts")}
                                               | {"start": inc["start"].isoformat(), "end": inc["end"].isoformat(),
                                                  "rules": dict(inc["rules"]), "alerts": out_alerts},
                                               default=str, indent=1, ensure_ascii=False))
        z.writestr("README.txt", "Ardea incident export\n\nreport.md      readable report with every alert's verdict, "
                   "findings and actions\ntimeline.csv   one row per alert\nincident.json  everything above, "
                   "machine-readable\ntrails/        every investigation step per alert (queries, results, model "
                   "output, guardrails) and analyst feedback\n\nVerdicts are automated: verify before acting.\n")
    auth.audit(g.user["username"], "incident_export", inc["id"], _main()._client_ip(), f"{len(alerts)} alerts")
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="ardea-{inc["id"]}.zip"'})


def _safe_name(text_):
    import re
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text_)[:120]


def _incident_work(incs):
    """inc id -> {"items", "open", "overdue", "assignees"} for alerts that need a person (Pro: assignments)."""
    if not work.enabled():
        return {}
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    flagged = [a for inc in incs for a in inc["alerts"] if a["verdict"] in work.NEEDS_PERSON]
    rows, reviewed = work.load(a["alert_id"] for a in flagged)
    out = {}
    for inc in incs:
        items = [work.item(a, rows, reviewed, now) for a in inc["alerts"] if a["verdict"] in work.NEEDS_PERSON]
        out[inc["id"]] = {"items": items, "open": sum(1 for i in items if not i["handled"]),
                          "overdue": sum(1 for i in items if i["overdue"]),
                          "assignees": sorted({i["assignee"] for i in items if i["assignee"] and not i["handled"]})}
    return out


# --------------------------------------------------------------------------- ask about this alert
ASK_PER_10_MIN = 10


@bp.post("/api/alerts/<alert_id>/ask")
def ask_question(alert_id):
    if not editions.has("ask"):
        return jsonify(error="Asking about an alert needs Ardea Pro or MSP."), 403
    if g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)
    _main().require_alert_access(alert_id)
    body = request.get_json(silent=True) or {}
    question = " ".join(str(body.get("question") or request.form.get("question") or "").split())
    if len(question) < 5:
        return jsonify(error="Ask a question of at least a few words."), 400
    if len(question) > 500:
        return jsonify(error="Keep the question under 500 characters."), 400
    with get_connection() as conn:
        recent = conn.execute("SELECT count(*) AS n FROM alert_questions WHERE asked_by = %s "
                              "AND created_at > NOW() - interval '10 minutes'", (g.user["username"],)).fetchone()
        if recent["n"] >= ASK_PER_10_MIN:
            return jsonify(error="That is a lot of questions: wait a few minutes."), 429
        row = conn.execute("INSERT INTO alert_questions (alert_id, asked_by, question) VALUES (%s, %s, %s) "
                           "RETURNING id", (alert_id, g.user["username"], question)).fetchone()
        conn.commit()
    return jsonify(id=row["id"])


@bp.get("/api/alerts/<alert_id>/questions")
def alert_questions(alert_id):
    _main().require_alert_access(alert_id)
    if not editions.has("ask"):
        return jsonify(questions=[])
    with get_connection() as conn:
        rows = conn.execute("""SELECT id, asked_by, question, status, answer, cited, note, steps, created_at,
                                      finished_at FROM alert_questions WHERE alert_id = %s ORDER BY id DESC LIMIT 20""",
                            (alert_id,)).fetchall()
    out = []
    for r in rows:
        evidence = next((s["evidence"] for s in (r["steps"] or []) if isinstance(s, dict) and "evidence" in s), [])
        out.append({"id": r["id"], "asked_by": r["asked_by"], "question": r["question"], "status": r["status"],
                    "answer": r["answer"] or "", "cited": r["cited"] or [], "note": r["note"] or "",
                    "new_evidence": [{"id": e.get("id"), "tool": e.get("tool")} for e in evidence][:10],
                    "asked": r["created_at"].isoformat() if r["created_at"] else ""})
    return jsonify(questions=out)


# --------------------------------------------------------------------------- my queue and deadlines
def _locked_page(feature, template="incidents.html"):
    return render_template(template, locked=True, needs=editions.FEATURES[feature], edition=editions.edition(),
                           locked_feature=feature)


@bp.get("/queue")
def queue_page():
    if not editions.has("assignments"):
        return _locked_page("assignments", "queue.html")
    if not work.enabled():
        return render_template("queue.html", locked=False, disabled=True)
    main = _main()
    mine = main.visible_alerts(main.load_alerts())
    who = request.args.get("who", "all")
    who = who if who in ("all", "mine", "unassigned") else "all"
    range_key = request.args.get("range", "30d")
    range_key = range_key if range_key in work.RANGES else "30d"
    show_handled = request.args.get("handled") == "1"
    items = work.queue(mine, who=who, me=g.user["username"], range_key=range_key, show_handled=show_handled)
    _, inc_of = main.load_incidents() if editions.has("incidents") else ({}, {})
    counts = {k: len(work.queue(mine, who=k, me=g.user["username"], range_key=range_key)) for k in ("mine", "unassigned", "all")}
    return render_template("queue.html", locked=False, items=items, who=who, range_key=range_key,
                           show_handled=show_handled, counts=counts, inc_of=inc_of,
                           can_work=g.user["role"] in auth.FEEDBACK_ROLES, users=work.assignable_users(),
                           labels=work.STATUS_LABELS, due_text=work.due_text,
                           error=request.args.get("error", "")[:200], done=request.args.get("done", ""))


@bp.post("/queue/work")
def queue_work():
    if not work.enabled():
        abort(403)
    if g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)
    main = _main()
    visible = {a["alert_id"]: a for a in main.visible_alerts(main.load_alerts())}
    one = request.form.get("one")
    ids = [one] if one in visible else [a for a in request.form.getlist("alert_id") if a in visible][:work.MAX_BULK]
    action = request.form.get("one_action", "take") if one else request.form.get("action", "")
    back = request.form.get("back", "/queue")
    back = back if back.startswith(("/queue", "/incidents/")) and "//" not in back else "/queue"
    if not ids:
        return redirect(back, code=303)
    try:
        n = work.update(ids, g.user["username"], action, request.form.get("assignee") or None,
                        request.form.get("note", ""), siem_of=lambda aid: visible[aid]["siem"])
    except work.WorkError as exc:
        return redirect(f"{back}{'&' if '?' in back else '?'}error={_q(str(exc))}", code=303)
    return redirect(f"{back}{'&' if '?' in back else '?'}done={n}", code=303)


@bp.post("/incidents/work")
def incidents_work():
    """Bulk actions on the Incidents page: apply to every alert that needs a person in the ticked incidents."""
    if not work.enabled() or g.user["role"] not in auth.FEEDBACK_ROLES:
        abort(403)
    everything, _ = _main().load_incidents()
    by_id = {i["id"]: i for i in everything if auth.can_see_siem(g.user, i["siem"])}
    chosen = [by_id[i] for i in request.form.getlist("inc_id")[:200] if i in by_id]
    back = request.form.get("back", "/incidents")
    back = back if back.startswith("/incidents") and "//" not in back else "/incidents"
    ids = [a["alert_id"] for inc in chosen for a in inc["alerts"] if a["verdict"] in work.NEEDS_PERSON]
    sep = "&" if "?" in back else "?"
    if not ids:
        return redirect(f"{back}{sep}error={_q('Tick at least one incident that has alerts needing a person.')}",
                        code=303)
    siem_of = {a["alert_id"]: inc["siem"] for inc in chosen for a in inc["alerts"]}
    try:
        n = work.update(ids, g.user["username"], request.form.get("action", ""), request.form.get("assignee") or None,
                        request.form.get("note", ""), siem_of=siem_of.get)
    except work.WorkError as exc:
        return redirect(f"{back}{sep}error={_q(str(exc))}", code=303)
    return redirect(f"{back}{sep}done={n}", code=303)


def _q(text_):
    from urllib.parse import quote
    return quote(text_[:200])


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
