"""Export analyst-labelled alerts as replayable eval cases (eval/run_eval.py format).

Every case = the raw alert (re-read from Elastic) + the SIEM/web results the worker actually got
(from investigation_steps, replayed as fixtures, so the eval never touches the SIEM) + the analyst's
verdict as the expected answer. Disagreements are the most valuable cases: export them first.

Run inside the worker container (it has the DB + Elastic credentials):
    docker compose exec worker python export_eval_cases.py --out /tmp/cases --limit 200
    docker cp Ardea_worker:/tmp/cases/. eval/cases/
Cases contain REAL alert data: eval/cases/ is git-ignored, keep it that way.
"""
import argparse
import json
import pathlib
import re

import db
import elastic
import licensing

SQL = """
WITH latest AS (
    SELECT DISTINCT ON (alert_id) alert_id, agrees, correct_verdict, comment, analyst, created_at
    FROM feedback ORDER BY alert_id, created_at DESC)
SELECT l.alert_id, l.agrees, l.comment, l.analyst, t.verdict AS model_verdict, a.count, a.rule_name,
       a.siem, a.elastic_id,
       CASE WHEN l.agrees THEN t.verdict ELSE l.correct_verdict END AS label
FROM latest l JOIN triage_results t USING (alert_id) JOIN alerts a USING (alert_id)
WHERE (CASE WHEN l.agrees THEN t.verdict ELSE l.correct_verdict END) IS NOT NULL
ORDER BY l.agrees ASC, l.created_at DESC          -- disagreements first
LIMIT %s"""

STEPS_SQL = """
SELECT tool_name, arguments, result FROM investigation_steps
WHERE alert_id = %s AND kind IN ('enrichment', 'tool') AND status IN ('ok', 'cached')
  AND tool_name IS NOT NULL AND tool_name <> 'finish_investigation' AND result IS NOT NULL
  AND run_id = (SELECT run_id FROM investigation_steps WHERE alert_id = %s ORDER BY created_at DESC LIMIT 1)
ORDER BY step"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/cases")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()
    conn = db.get_connection()
    licensing.sync(conn, max_age=0)
    if not licensing.has("eval_export"):
        raise SystemExit(f"exporting eval cases needs Ardea Pro or MSP (this installation runs {licensing.tier()})")
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    n = skipped = 0
    for row in conn.execute(SQL, (args.limit,)).fetchall():
        siem_id = row["siem"] or elastic.default_id()
        if siem_id not in elastic.configured():
            skipped += 1                       # its SIEM was removed from siems.json
            continue
        with elastic.use(siem_id):
            raw = elastic.fetch_alert(row["elastic_id"] or row["alert_id"])
        if raw is None:
            skipped += 1                       # rolled out of the alerts index
            continue
        fixtures = {}
        for s in conn.execute(STEPS_SQL, (row["alert_id"], row["alert_id"])).fetchall():
            fixtures.setdefault(s["tool_name"], []).append({"match": s["arguments"] or {}, "result": s["result"]})
        label = row["label"]
        case = {
            "name": re.sub(r"[^\w-]+", "_", f"{row['rule_name'] or 'rule'}_{row['alert_id']}")[:120],
            "tags": ["exported", "agreed" if row["agrees"] else "corrected", f"siem:{siem_id}"],
            "alert": raw,
            "occurrences": row["count"] or 1,
            "fixtures": fixtures,
            "expected": {
                "verdict": label,
                # a confirmed TP must at least reach a human; Review is an acceptable answer for anything
                "acceptable": ["Needs Human Review"] if label != "Needs Human Review" else [],
                "must_escalate": label == "True Positive",
                "injection": False,
            },
            "notes": {"model_verdict_at_export": row["model_verdict"], "analyst": row["analyst"],
                      "comment": row["comment"]},
        }
        (out / f"{case['name']}.json").write_text(json.dumps(case, indent=1, default=str))
        n += 1
    print(f"exported {n} cases to {out} ({skipped} skipped: alert no longer in Elastic or SIEM removed)")


if __name__ == "__main__":
    main()
