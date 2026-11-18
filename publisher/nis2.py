"""NIS2 report drafts (Pro) from an incident's facts.

NIS2 (Directive (EU) 2022/2555, Article 23) asks for an early warning within 24 hours of becoming aware
of a significant incident, an incident notification within 72 hours, and a final report within one month of
the notification.
Ardea fills in what it knows from the incident (times, systems, accounts, techniques, indicators, verdicts,
actions recommended) and marks everything only a person can know with [TO COMPLETE: …]. No language
model is involved: the draft repeats the investigation's own findings, so nothing is invented.
A draft, not legal advice: the national authority's form and rules decide what is sent.
"""
import re
from datetime import timedelta

import settings_admin

STAGES = {
    "early": ("Early warning", timedelta(hours=24)),
    "notification": ("Incident notification", timedelta(hours=72)),
    "final": ("Final report", timedelta(hours=72) + timedelta(days=30)),   # one month after the notification
}
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b")
_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|cc|co|eu)\b")
_FILE = re.compile(r"\b[\w.-]{1,60}\.(?:exe|dll|ps1|bat|vbs|js|hta|scr|zip|iso|lnk)\b", re.I)
NEEDS_PERSON = ("True Positive", "Needs Human Review")


def todo(what: str) -> str:
    return f"[TO COMPLETE: {what}]"


def _setting(name: str, what: str) -> str:
    return settings_admin.publisher_value(name, "").strip() or todo(what)


def indicators(alerts: list[dict]) -> dict:
    """IPs, domains, hashes and file names quoted in the verdicts' summaries and findings."""
    text = " ".join([(a.get("detail") or {}).get("summary", "") for a in alerts] +
                    [f.get("claim", "") for a in alerts for f in (a.get("detail") or {}).get("findings", [])])
    found = {"IP addresses": sorted(set(_IP.findall(text))), "Domains": sorted(set(_DOMAIN.findall(text)) - {"e.g"}),
             "File hashes": sorted(set(_HASH.findall(text))), "Files": sorted({f for f in _FILE.findall(text)})}
    return {k: v[:20] for k, v in found.items() if v}


def facts(inc: dict) -> dict:
    flagged = [a for a in inc["alerts"] if a["verdict"] in NEEDS_PERSON] or inc["alerts"]
    actions, seen = [], set()
    for a in flagged:
        for act in (a.get("detail") or {}).get("actions", []):
            key = act.get("action", "").lower()
            if key and key not in seen:
                seen.add(key)
                actions.append(act)
    return {"aware": inc["start"], "last": inc["end"], "flagged": flagged, "actions": actions[:12],
            "malicious": any(a["verdict"] == "True Positive" for a in inc["alerts"]),
            "iocs": indicators(flagged)}


def deadlines(inc: dict) -> list[tuple[str, str, object]]:
    return [(key, label, inc["start"] + delta) for key, (label, delta) in STAGES.items()]


def draft(inc: dict, stage: str, resolved_notes: list[str] | None = None) -> str:
    """The report text for one stage. Plain text, ready to paste into the authority's form."""
    label, delta = STAGES[stage]
    f = facts(inc)
    t = lambda d: d.astimezone().strftime("%d/%m/%Y %H:%M %Z")          # noqa: E731
    lines = [f"NIS2 {label.upper()} (DRAFT)",
             f"Reference: {inc['id']} · prepared with Ardea from the incident's evidence",
             f"Deadline: {t(inc['start'] + delta)} ({label.lower()} is due "
             f"{'within 24 hours of becoming aware' if stage == 'early' else 'within 72 hours of becoming aware' if stage == 'notification' else 'within one month of the incident notification, counted here from its latest possible date'}"
             "; check the time you actually became aware)", "",
             "1. REPORTING ENTITY",
             f"   Name: {_setting('NIS2_ENTITY', 'legal name of the entity')}",
             f"   Sector / type: {_setting('NIS2_SECTOR', 'sector and whether essential or important entity')}",
             f"   Contact for this incident: {_setting('NIS2_CONTACT', 'name, phone and e-mail')}",
             f"   Sent to: {_setting('NIS2_AUTHORITY', 'national CSIRT or competent authority')}", "",
             "2. WHEN",
             f"   First suspicious activity detected: {t(inc['start'])}",
             f"   Became aware of the incident: {t(f['aware'])} {todo('confirm, if a person confirmed it later')}",
             f"   Latest related activity seen: {t(f['last'])}", "",
             "3. WHAT HAPPENED",
             f"   Suspected unlawful or malicious act: "
             f"{'Yes, suspected: at least one alert was confirmed as a true positive.' if f['malicious'] else todo('yes / no; the alerts still need a person to decide')}",
             f"   Detection: {inc['count']} related alert(s) in {inc['siem_name']}, {inc['minutes']} minutes "
             f"from first to last; {inc['needs_person']} needed a person."]
    for a in f["flagged"][:8]:
        summary = (a.get("detail") or {}).get("summary", "")
        lines.append(f"   - {a['timestamp_raw'].astimezone():%d/%m %H:%M} {a['rule_name']} on {a['hostname']}"
                     f"{' (' + a['user'] + ')' if a.get('user') else ''}: {a['verdict']}, {a['severity']}."
                     + (f" {summary}" if summary else ""))
    if inc["techniques"]:
        lines.append("   Techniques (MITRE ATT&CK): " + ", ".join(f"{m['id']} {m['name']}".strip()
                                                              for m in inc["techniques"]))
    lines += ["", "4. AFFECTED SYSTEMS AND ACCOUNTS",
              f"   Hosts: {', '.join(inc['hosts']) or todo('hosts')}",
              f"   Accounts: {', '.join(inc['users']) or 'none recorded'}",
              f"   Services affected and impact on their provision: {todo('which services, since when, how badly')}",
              f"   Number of users or customers affected: {todo('estimate')}",
              f"   Possible cross-border impact: {todo('yes / no, and which Member States')}"]
    if stage in ("notification", "final"):
        lines += ["", "5. INITIAL ASSESSMENT",
                  f"   Severity: {inc['severity']} (Ardea's highest verdict severity) {todo('your assessment of severity and impact')}"]
        if f["iocs"]:
            lines.append("   Indicators of compromise found in the evidence:")
            lines += [f"   - {kind}: {', '.join(values)}" for kind, values in f["iocs"].items()]
        else:
            lines.append(f"   Indicators of compromise: {todo('none were quoted in the evidence; add any you found')}")
    if f["actions"] or stage != "early":
        lines += ["", "6. MEASURES" if stage != "early" else "5. FIRST MEASURES"]
        lines += [f"   - Recommended by the investigation: {a['action']}" +
                  (f" ({a['priority']})" if a.get("priority") else "") for a in f["actions"]]
        lines += [f"   - Done: {n}" for n in (resolved_notes or [])]
        lines.append(f"   - {todo('measures taken and ongoing')}")
    if stage == "final":
        lines += ["", "7. ROOT CAUSE AND LESSONS",
                  f"   Type of threat or root cause: {todo('e.g. phishing e-mail, stolen credentials, unpatched service')}",
                  f"   Mitigation applied and ongoing: {todo('what was changed so it does not happen again')}",
                  f"   Cross-border impact (final): {todo('yes / no')}"]
    lines += ["", "Prepared from Ardea's automated investigation. Verify every statement and complete the marked "
                  "fields before sending. This is a draft, not legal advice; the national authority's form decides "
                  "what must be reported."]
    return "\n".join(lines)
